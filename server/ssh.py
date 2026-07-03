import datetime

from aiohttp import BasicAuth
from aiohttp import web
from cryptography.hazmat.primitives.serialization import SSHCertificateBuilder
from cryptography.hazmat.primitives.serialization import SSHCertificateType
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from . import backends


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


async def ssh_handler(request):
    config = request.app['config']

    try:
        h = request.headers['Authorization']
    except KeyError as e:
        raise web.HTTPUnauthorized from e
    auth = BasicAuth.decode(h)
    username = backends.find_username(auth.login, config)
    user = await backends.auth(username, auth.password, config)
    if not user:
        raise web.HTTPUnauthorized

    try:
        principal = request.query['principal']
    except KeyError as e:
        raise web.HTTPBadRequest from e
    if principal not in get_ssh_principals(user, config):
        raise web.HTTPForbidden

    client_pubkey = await request.read()
    cert = create_cert(client_pubkey, username, principal, config)

    return web.Response(body=cert, content_type='text/x-ssh-public-key')
