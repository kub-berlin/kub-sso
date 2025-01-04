# https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
# https://openid.net/specs/openid-connect-core-1_0.html

import datetime
import urllib.parse

import jwt
from aiohttp import web

from . import backends


def utcnow():
    return datetime.datetime.now(tz=datetime.timezone.utc)


def update_url(url: str, **params) -> str:
    url_parts = list(urllib.parse.urlparse(url))
    query = urllib.parse.parse_qs(url_parts[4])
    for key, value in params.items():
        if value is not None:
            query[key] = value
    url_parts[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(url_parts)


def find_username(username_or_email: str, config: dict) -> str:
    if '@' not in username_or_email:
        return username_or_email
    for username, user in config['users'].items():
        if user.get('email') == username_or_email:
            return username
    raise KeyError(username_or_email)


def encode_jwt(data: dict, config: dict) -> str:
    return jwt.encode(
        {
            **data,
            'iss': config['server']['issuer'],
            'iat': utcnow(),
            'exp': utcnow() + datetime.timedelta(seconds=20),
        },
        config['server']['private_key_pem'],
        algorithm='RS256',
        headers={'kid': '1'},
    )


def decode_jwt(encoded: str, config: dict, **kwargs) -> dict:
    return jwt.decode(
        encoded,
        config['server']['public_key_pem'],
        algorithms=['RS256'],
        issuer=config['server']['issuer'],
        **kwargs,
    )


def render_form(request, *, error: bool):
    with open(request.app['dir'] / 'form.html') as fh:
        template = fh.read()
    if error:
        template = template.replace('hidden', '')
    return web.Response(text=template, content_type='text/html', headers={
        'X-Frame-Options': 'DENY',
        'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    })


async def config_handler(request):
    # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    config = request.app['config']
    return web.json_response({
        'issuer': config['server']['issuer'],
        'authorization_endpoint': config['server']['issuer'] + 'login/',
        'token_endpoint': config['server']['issuer'] + 'token/',
        'userinfo_endpoint': config['server']['issuer'] + 'userinfo/',
        'jwks_uri': config['server']['issuer'] + '.well-known/jwks.json',
        'grant_types_supported': ['authorization_code'],
        'scopes_supported': ['openid', 'profile', 'email'],
        'response_types_supported': ['id_token'],
        'id_token_signing_alg_values_supported': ['RS256'],
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
            'n': config['server']['public_key_n'],
        }]
    })


async def login_handler(request):
    config = request.app['config']

    try:
        if 'openid' not in request.query['scope'].split():
            raise ValueError('openid not in scope')
        if request.query['response_type'] != 'code':
            raise ValueError('response_type is not code')
        client_id = request.query['client_id']
        client = config['clients'][client_id]
        redirect_uri = request.query['redirect_uri']
        if redirect_uri != client['redirect_uri']:
            raise ValueError('redirect_uri does not match client configuration')
    except Exception as e:
        raise web.HTTPBadRequest from e

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
    elif client_id not in user.get('clients', []):
        return render_form(request, error=True)
    else:
        return web.Response(status=303, headers={'Location': update_url(
            redirect_uri,
            state=request.query.get('state'),
            code=encode_jwt({
                'sub': username,
                'aud': client_id,
                'nonce': request.query.get('nonce'),
            }, config),
        )})


async def token_handler(request):
    config = request.app['config']
    post_data = await request.post()

    try:
        client_id = post_data['client_id']
        client = config['clients'][client_id]
        if not backends.check_internal_password(
            client['secret'], post_data['client_secret']
        ):
            raise ValueError('invalid password')
    except Exception as e:
        raise web.HTTPForbidden from e

    if post_data.get('grant_type') != 'authorization_code':
        raise web.HTTPBadRequest

    try:
        code = decode_jwt(post_data['code'], config, audience=client_id)
        username = code['sub']
        user = config['users'][username]
    except (KeyError, jwt.exceptions.InvalidTokenError) as e:
        raise web.HTTPBadRequest from e

    if client_id not in user.get('clients', []):
        raise web.HTTPBadRequest

    return web.json_response({
        'access_token': encode_jwt({'sub': username}, config),
        'token_type': 'Bearer',
        'id_token': encode_jwt({
            'aud': client_id,
            'sub': username,
            'name': user.get('full_name'),
            'email': user.get('email'),
            'groups': user.get('oidc_groups', []),
            'nonce': code['nonce'],
        }, config),
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
        token = decode_jwt(h.removeprefix('Bearer '), config)
        username = token['sub']
        user = config['users'][username]
    except Exception as e:
        raise web.HTTPForbidden from e

    return web.json_response({
        'sub': username,
        'name': user.get('full_name'),
        'email': user.get('email'),
        'groups': user.get('oidc_groups', []),
        'preferred_username': username,
    })
