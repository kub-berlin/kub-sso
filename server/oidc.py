# https://www.rfc-editor.org/rfc/rfc6749
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


def login_validate(request, config: dict) -> bool:
    return (
        request.query.get('response_type') == 'code'
        and request.query.get('client_id') in config['clients']
    )


def render_form(request, *, error: bool):
    with open(request.app['dir'] / 'form.html') as fh:
        template = fh.read()
    if error:
        template = template.replace('hidden', '')
    return web.Response(text=template, content_type='text/html')


async def login_handler(request):
    config = request.app['config']

    if not login_validate(request, config):
        raise web.HTTPBadRequest

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
    elif request.query['client_id'] not in user.get('clients', []):
        raise web.HTTPForbidden
    else:
        client_id = request.query['client_id']
        client = config['clients'][client_id]
        response = web.Response(status=302, headers={'Location': update_url(
            client['redirect_uri'],
            state=request.query.get('state', ''),
            code=generate_code(
                request.query['client_id'],
                username,
                config,
            ),
        )})
        return response


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
        'name': user.get('full_name'),
        'email': user.get('email'),
    }, headers={
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
    })
