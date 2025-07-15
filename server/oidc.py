# https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
# https://openid.net/specs/openid-connect-core-1_0.html

import base64
import datetime
import hashlib

import jwt
from aiohttp import BasicAuth
from aiohttp import web

from . import backends
from .utils import decode_jwt
from .utils import encode_jwt
from .utils import update_url


def s256(s: str) -> str:
    h = hashlib.sha256(s.encode('ascii')).digest()
    return base64.urlsafe_b64encode(h).decode('ascii').rstrip('=')


def find_username(username_or_email: str, config: dict) -> str:
    if '@' in username_or_email:
        for username, user in config['users'].items():
            if user.get('email') == username_or_email:
                return username
    return username_or_email


def get_allowed_clients(user: dict, config: dict) -> list[str]:
    if 'clients' in user:
        return user['clients']
    elif 'default_clients' in config:
        return config['default_clients']
    else:
        return []


def get_claims(user: dict, client_id: str) -> dict:
    return {
        **user.get('client_claims', {}).get(client_id, {}),
        'name': user.get('full_name'),
        'email': user.get('email'),
        'groups': user.get('oidc_groups', []),
    }


def render_form(request, *, error: bool):
    with open(request.app['dir'] / 'form.html') as fh:
        template = fh.read()
    if error:
        template = template.replace('hidden', '')
    return web.Response(text=template, content_type='text/html', headers={
        'X-Frame-Options': 'DENY',
        'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    })


def render_error(request, status, msg):
    with open(request.app['dir'] / 'error.html') as fh:
        template = fh.read()
    html = template.replace('{msg}', msg)
    return web.Response(status=status, text=html, content_type='text/html')


def error_response(error: str, status: int = 400):
    return web.json_response({'error': error}, status=status, headers={
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
    })


async def config_handler(request):
    # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    config = request.app['config']
    return web.json_response({
        'issuer': config['issuer'],
        'authorization_endpoint': config['issuer'] + 'login/',
        'token_endpoint': config['issuer'] + 'token/',
        'userinfo_endpoint': config['issuer'] + 'userinfo/',
        'jwks_uri': config['issuer'] + '.well-known/jwks.json',
        'scopes_supported': ['openid', 'email'],
        'response_types_supported': ['code'],
        'grant_types_supported': ['authorization_code'],
        'subject_types_supported': ['public'],
        'id_token_signing_alg_values_supported': ['RS256'],
        'token_endpoint_auth_methods_supported': [
            'client_secret_post', 'client_secret_basic'
        ],
        'require_request_uri_registration': True,
        'code_challenge_methods_supported': ['S256'],
    })


async def jwks_handler(request):
    config = request.app['config']
    return web.json_response({
        'keys': [{
            'kid': '1',
            'kty': 'RSA',
            'alg': 'RS256',
            'use': 'sig',
            'e': 'AQAB',
            'n': config['public_key_n'],
        }]
    })


async def login_handler(request):
    config = request.app['config']

    try:
        client_id = request.query['client_id']
        client = config['clients'][client_id]
    except KeyError as e:
        raise web.HTTPBadRequest from e

    # inform users that bookmarking the login link does not work
    today = datetime.date.today().isoformat()
    if 'day' not in request.query:
        return web.Response(status=303, headers={'Location': update_url(
            f'?{request.url.query_string}',
            day=today,
        )})
    elif request.query['day'] != today:
        return render_error(request, 400, 'Dieser Link ist nicht mehr gültig.')

    if (
        request.query.get('response_type') != 'code'
        or 'openid' not in request.query.get('scope', '').split()
        or request.query.get('redirect_uri') != client['redirect_uri']
        or (
            client.get('code_challenge_required', True)
            and 'code_challenge' not in request.query
        )
        or (
            'code_challenge' in request.query
            and request.query.get('code_challenge_method') != 'S256'
        )
    ):
        raise web.HTTPBadRequest

    if request.method != 'POST':
        return render_form(request, error=False)

    try:
        post_data = await request.post()
        username_or_email = post_data['username']
        password = post_data['password']
    except KeyError:
        return render_form(request, error=True)

    username = find_username(username_or_email, config)
    user = await backends.auth(username, password, config)
    if not user:
        return render_form(request, error=True)
    elif client_id not in get_allowed_clients(user, config):
        return render_form(request, error=True)
    else:
        return web.Response(status=303, headers={'Location': update_url(
            client['redirect_uri'],
            state=request.query.get('state'),
            code=encode_jwt({
                'sub': username,
                'aud': client_id,
                'nonce': request.query.get('nonce'),
                'code_challenge': request.query.get('code_challenge'),
            }, 'auth_code', config),
        )})


async def token_handler(request):
    config = request.app['config']
    post_data = await request.post()

    try:
        if 'Authorization' in request.headers:
            h = request.headers['Authorization']
            auth = BasicAuth.decode(h)
            client_id = auth.login
            client_secret = auth.password
        else:
            client_id = post_data['client_id']
            client_secret = post_data['client_secret']
        client = config['clients'][client_id]
    except Exception:
        return error_response('invalid_client', 401)

    if not backends.check_internal_password(client['secret'], client_secret):
        return error_response('invalid_client', 401)

    if post_data.get('grant_type') != 'authorization_code':
        return error_response('unsupported_grant_type')

    try:
        code = decode_jwt(
            post_data['code'], 'auth_code', config, audience=client_id
        )
    except jwt.exceptions.InvalidTokenError:
        return error_response('invalid_grant')

    try:
        username = code['sub']
        user = config['users'][username]
    except KeyError:
        return error_response('invalid_grant')

    if client_id not in get_allowed_clients(user, config):
        return error_response('invalid_grant')

    if (
        code.get('code_challenge')
        or 'code_verifier' in post_data
        or client.get('code_challenge_required', True)
    ):
        if (
            'code_verifier' not in post_data
            or len(post_data['code_verifier']) < 43
            or len(post_data['code_verifier']) > 128
            or code.get('code_challenge') != s256(post_data['code_verifier'])
        ):
            return error_response('invalid_grant')

    return web.json_response({
        'access_token': encode_jwt({
            'sub': username,
            'client_id': client_id,
        }, 'access_token', config),
        'expires_in': 20,
        'token_type': 'Bearer',
        'id_token': encode_jwt({
            **get_claims(user, client_id),
            'aud': client_id,
            'sub': username,
            'nonce': code['nonce'],
        }, 'id_token', config),
    }, headers={
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
    })


async def userinfo_handler(request):
    config = request.app['config']

    try:
        h = request.headers['Authorization']
        if not h.startswith('Bearer'):
            raise ValueError
        token = decode_jwt(h.removeprefix('Bearer '), 'access_token', config)
        username = token['sub']
        client_id = token['client_id']
        user = config['users'][username]
    except Exception:
        return web.Response(status=401, headers={
            'WWW-Authenticate': 'Bearer error="invalid_token"',
        })

    if client_id not in get_allowed_clients(user, config):
        return error_response('invalid_grant')

    return web.json_response({
        **get_claims(user, client_id),
        'sub': username,
        'preferred_username': username,
    })
