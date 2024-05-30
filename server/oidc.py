# https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
# https://openid.net/specs/openid-connect-core-1_0.html

import datetime
import urllib.parse

import jwt
from aiohttp import BasicAuth
from aiohttp import web

from . import backends

SESSION_COOKIE = 'kub_sso_session'
SESSION_MAX_AGE = datetime.timedelta(hours=1)


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


def generate_code(client_id: str, username: str, config: dict) -> str:
    return jwt.encode({
        'sub': username,
        'aud': client_id,
        'exp': utcnow() + datetime.timedelta(seconds=20),
    }, config['server']['secret'], algorithm='HS256')


def get_code(encoded: str, client_id: str, config: dict) -> dict:
    secret = config['server']['secret']
    return jwt.decode(encoded, secret, audience=client_id, algorithms=['HS256'])


def generate_id_token(client_id: str, username: str, config: dict) -> str:
    return jwt.encode({
        'iss': config['server']['issuer'],
        'sub': username,
        'aud': client_id,
        'exp': utcnow() + datetime.timedelta(seconds=20),
        'iat': utcnow(),
    }, config['server']['secret'], algorithm='HS256')


def render_form(request, *, error: bool):
    with open(request.app['dir'] / 'form.html') as fh:
        template = fh.read()
    if error:
        template = template.replace('hidden', '')
    return web.Response(text=template, content_type='text/html')


async def config_handler(request):
    # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    config = request.app['config']
    return web.json_response({
        'issuer': config['server']['issuer'],
        'authorization_endpoint': config['server']['issuer'] + '/login/',
        'token_endpoint': config['server']['issuer'] + '/token/',
        'jwks_uri': config['server']['issuer'] + '/.well-known/openid-jwks/',
        'grant_types_supported': ['authorization_code'],
        'scopes_supported': ['openid', 'profile', 'email'],
        'response_types_supported': ['id_token'],
        'subject_types_supported': ['pairwise'],
        'id_token_signing_alg_values_supported': ['RS256'],
    })


async def jwks_handler(request):
    return web.json_response({'keys': []})


async def login_handler(request):
    config = request.app['config']

    try:
        if 'openid' not in request.query['scope'].split():
            raise ValueError
        if request.query['response_type'] != 'code':
            raise ValueError
        client_id = request.query['client_id']
        client = config['clients'][client_id]
        redirect_uri = request.query['redirect_uri']
        if redirect_uri != client['redirect_uri']:
            raise ValueError
    except Exception as e:
        raise web.HTTPBadRequest from e

    if request.method != 'POST':
        return render_form(request, error=False)

    try:
        post_data = await request.post()
        username = post_data['username']
        password = post_data['password']
    except KeyError:
        return render_form(request, error=True)

    user = await backends.auth(username, password, config)
    if not user:
        return render_form(request, error=True)
    elif client_id not in user.get('clients', []):
        raise web.HTTPForbidden
    else:
        return web.Response(status=302, headers={'Location': update_url(
            redirect_uri,
            state=request.query.get('state'),
            code=generate_code(client_id, username, config),
        )})


async def token_handler(request):
    config = request.app['config']

    try:
        h = request.headers['Authorization']
        auth = BasicAuth.decode(h)
        client_id = auth.login
        client = config['clients'][client_id]
    except Exception as e:
        raise web.HTTPUnauthorized from e
    if not backends.check_internal_password(client['secret'], auth.password):
        raise web.HTTPUnauthorized

    post_data = await request.post()
    if post_data.get('grant_type') != 'authorization_code':
        raise web.HTTPBadRequest

    try:
        code = get_code(post_data['code'], client_id, config)
        username = code['sub']
        user = config['users'][username]
    except (KeyError, jwt.exceptions.InvalidTokenError) as e:
        raise web.HTTPBadRequest from e

    if client_id not in user.get('clients', []):
        raise web.HTTPBadRequest

    return web.json_response({
        'access_token': 'noop',
        'token_type': 'Bearer',
        'id_token': generate_id_token(client_id, username, config),
        'name': user.get('full_name'),
        'email': user.get('email'),
    }, headers={
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
    })
