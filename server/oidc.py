# https://www.rfc-editor.org/rfc/rfc6749
# https://openid.net/specs/openid-connect-core-1_0.html

import base64
import datetime
import urllib.parse

import jwt
from aiohttp import web

from . import backends

SESSION_COOKIE = 'kub_sso_session'
SESSION_MAX_AGE = datetime.timedelta(hours=1)


def utcnow():
    return datetime.datetime.now(tz=datetime.timezone.utc)


def update_url(url: str, **params) -> str:
    url_parts = list(urllib.parse.urlparse(url))
    query = urllib.parse.parse_qs(url_parts[4])
    query.update(params)
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


def generate_session(username: str, config: dict) -> str:
    return jwt.encode({
        'aud': 'kub-sso',
        'sub': username,
        'exp': utcnow() + SESSION_MAX_AGE,
    }, config['server']['secret'], algorithm='HS256')


def get_session(request, config: dict) -> dict:
    encoded = request.cookies[SESSION_COOKIE]
    secret = config['server']['secret']
    return jwt.decode(encoded, secret, audience='kub-sso', algorithms=['HS256'])


def login_validate(request, config: dict) -> bool:
    return (
        request.query.get('response_type') == 'code'
        and request.query.get('client_id') in config['clients']
    )


def login_response(request, username, config):
    client_id = request.query['client_id']
    client = config['clients'][client_id]
    return web.Response(status=302, headers={'Location': update_url(
        client['redirect_uri'],
        state=request.query.get('state', ''),
        code=generate_code(
            request.query['client_id'],
            username,
            config,
        ),
    )})


def render_form(request, *, error: bool):
    with open(request.app['dir'] / 'form.html') as fh:
        template = fh.read()
    if error:
        template = template.replace('hidden', '')
    return web.Response(text=template, content_type='text/html')


async def login_get(request):
    config = request.app['config']

    if not login_validate(request, config):
        raise web.HTTPBadRequest

    try:
        session = get_session(request, config)
        username = session['sub']
        user = config['users'][username]
    except (KeyError, jwt.exceptions.InvalidTokenError) as e:
        print(e)
        return render_form(request, error=False)

    if request.query['client_id'] not in user.get('clients', []):
        raise web.HTTPForbidden
    else:
        return login_response(request, username, config)


async def login_post(request):
    config = request.app['config']

    if not login_validate(request, config):
        raise web.HTTPBadRequest

    try:
        post_data = await request.post()
        username = post_data['username']
        password = post_data['password']
    except KeyError:
        return render_form(request, error=True)

    user = await backends.auth(username, password, config)
    if not user:
        return render_form(request, error=True)
    elif request.query['client_id'] not in user.get('clients', []):
        raise web.HTTPForbidden
    else:
        response = login_response(request, username, config)
        response.set_cookie(
            SESSION_COOKIE,
            generate_session(username, config),
            max_age=SESSION_MAX_AGE.total_seconds(),
            httponly=True,
        )
        return response


def basic_auth(request) -> tuple[str, str]:
    h = request.headers['Authorization']
    if not h.startswith('Basic '):
        raise ValueError
    s = base64.b64decode(h.removeprefix('Basic ')).decode('utf-8')
    return s.split(':', 1)


async def token_handler(request):
    config = request.app['config']

    try:
        client_id, client_secret = basic_auth(request)
        client = config['clients'][client_id]
    except Exception as e:
        raise web.HTTPUnauthorized from e
    if not backends.check_internal_password(client['secret'], client_secret):
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
        'name': user.get('full_name'),
        'email': user.get('email'),
    }, headers={
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
    })