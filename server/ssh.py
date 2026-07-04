import asyncio
import datetime

import jwt
from aiohttp import web
from cryptography.hazmat.primitives.serialization import SSHCertificateBuilder
from cryptography.hazmat.primitives.serialization import SSHCertificateType
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from . import backends
from .oidc import render_form
from .utils import decode_jwt
from .utils import encode_jwt
from .utils import render_message

AUTH_FUTURES = {}


def get_ssh_principals(user: dict, config: dict) -> list[str]:
    if 'ssh_principals' in user:
        return user['ssh_principals']
    elif 'default_ssh_principals' in config:
        return config['default_ssh_principals']
    else:
        return []


def create_cert(key: bytes, username: str, principal: str, config: dict) -> bytes:
    now = datetime.datetime.now(tz=datetime.UTC)
    return (
        SSHCertificateBuilder()
        .public_key(load_ssh_public_key(key))
        .type(SSHCertificateType.USER)
        .key_id(f'sso:{username}'.encode())
        .valid_after(now.timestamp())
        .valid_before((now + datetime.timedelta(hours=8)).timestamp())
        .valid_principals([principal.encode()])
        .sign(config['ssh_ca_key'])
        .public_bytes()
    )


def cleanup_futures(config: dict):
    tokens = list(AUTH_FUTURES.keys())
    for token in tokens:
        try:
            decode_jwt(token, 'ssh-session', config)
        except jwt.exceptions.InvalidTokenError:
            AUTH_FUTURES.pop(token, None)


async def start_handler(request):
    config = request.app['config']
    principal = request.match_info['principal']

    if len(principal) > 32:
        raise web.HTTPBadRequest

    cleanup_futures(config)
    if len(AUTH_FUTURES) > 64:
        raise web.HTTPServiceUnavailable

    token = encode_jwt({
        'sub': principal,
    }, 'ssh-session', config, ttl=60 * 10)

    AUTH_FUTURES[token] = asyncio.Future()

    return web.Response(body=token, content_type='application/jwt')


async def finish_handler(request):
    config = request.app['config']
    token = request.match_info['token']

    try:
        auth_future = AUTH_FUTURES[token]
    except KeyError as e:
        raise web.HTTPNotFound from e

    try:
        session = decode_jwt(token, 'ssh-session', config)
        principal = session['sub']
    except jwt.exceptions.InvalidTokenError as e:
        raise web.HTTPBadRequest from e

    try:
        username = await auth_future
    except Exception as e:
        raise web.HTTPUnauthorized from e
    finally:
        AUTH_FUTURES.pop(token, None)

    client_pubkey = await request.read()
    cert = create_cert(client_pubkey, username, principal, config)

    return web.Response(body=cert, content_type='text/x-ssh-public-key')


async def login_handler(request):
    config = request.app['config']
    token = request.match_info['token']

    try:
        auth_future = AUTH_FUTURES[token]
    except KeyError as e:
        raise web.HTTPNotFound from e

    try:
        session = decode_jwt(token, 'ssh-session', config)
        principal = session['sub']
    except jwt.exceptions.InvalidTokenError as e:
        raise web.HTTPBadRequest from e

    if request.method != 'POST':
        return render_form(request)

    try:
        post_data = await request.post()
        username_or_email = post_data['username']
        password = post_data['password']
    except KeyError:
        return render_form(request, error='Das Passwort war nicht korrekt')

    username = backends.find_username(username_or_email, config)
    user = await backends.auth(username, password, config)
    if not user:
        return render_form(request, error='Das Passwort war nicht korrekt')
    elif principal not in get_ssh_principals(user, config):
        return render_form(request, error='Zugriff verweigert')
    else:
        auth_future.set_result(username)
        return render_message(request, 'Authentifizierung erfolgreich')
