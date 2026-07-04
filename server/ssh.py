import asyncio
import datetime
import secrets
import time

import jwt
from aiohttp import web
from cryptography.hazmat.primitives.serialization import SSHCertificateBuilder
from cryptography.hazmat.primitives.serialization import SSHCertificateType
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from .oidc import s256
from .utils import decode_jwt
from .utils import render_message
from .utils import update_url

CLIENT_ID = 'ssh'
SESSION_TTL = 60 * 5
SESSIONS = {}


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


def cleanup_sessions():
    now = time.monotonic()
    for key, session in list(SESSIONS.items()):
        if now - session['created_at'] > SESSION_TTL:
            SESSIONS.pop(key)
            if not session['future'].done():
                session['future'].set_exception(TimeoutError())


def get_session(key):
    # A session can be used exactly twice:
    # Once by confirm_handler and once by sign_handler (in arbitrary order).
    cleanup_sessions()
    session = SESSIONS[key]
    if session['used']:
        SESSIONS.pop(key)
    session['used'] = True
    return session


async def start_handler(request):
    config = request.app['config']
    principal = request.match_info['principal']

    if len(principal) > 32:
        raise web.HTTPBadRequest

    cleanup_sessions()
    if len(SESSIONS) > 64:
        raise web.HTTPServiceUnavailable

    session_id = secrets.token_urlsafe(48)
    code_verifier = secrets.token_urlsafe(48)

    SESSIONS[session_id] = {
        'created_at': time.monotonic(),
        'future': asyncio.Future(),
        'code_verifier': code_verifier,
        'principal': principal,
        'used': False,
    }

    return web.Response(status=303, headers={'Location': update_url(
        config['issuer'] + 'login/',
        day=datetime.date.today().isoformat(),
        client_id=CLIENT_ID,
        redirect_uri=config['issuer'] + 'ssh-confirm/',
        response_type='code',
        scope='openid',
        state=session_id,
        code_challenge=s256(code_verifier),
        code_challenge_method='S256',
    )})


async def confirm_handler(request):
    config = request.app['config']

    try:
        code = decode_jwt(
            request.query['code'], 'auth_code', config, audience=CLIENT_ID
        )
    except jwt.exceptions.InvalidTokenError:
        return render_message(request, 'Ungültiger Code', 400)

    try:
        username = code['sub']
        user = config['users'][username]
        session = get_session(request.query['state'])
    except KeyError:
        return render_message(request, 'Ungültiger Code', 400)

    if code.get('code_challenge') != s256(session['code_verifier']):
        return render_message(request, 'Ungültiger Code', 400)

    if session['principal'] not in get_ssh_principals(user, config):
        return render_message(request, 'Zugriff verweigert', 403)

    session['future'].set_result(username)
    return render_message(request, 'Authentifizierung erfolgreich')


async def sign_handler(request):
    # SECURITY: a confirmed session ID is sufficient to sign a key

    config = request.app['config']
    session_id = request.match_info['session']

    try:
        session = get_session(session_id)
    except KeyError as e:
        raise web.HTTPNotFound from e

    try:
        username = await session['future']
    except Exception as e:
        raise web.HTTPUnauthorized from e

    client_pubkey = await request.read()
    cert = create_cert(client_pubkey, username, session['principal'], config)

    return web.Response(body=cert, content_type='text/x-ssh-public-key')
