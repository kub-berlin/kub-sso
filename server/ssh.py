import asyncio
import os
import tempfile
from pathlib import Path
from subprocess import CalledProcessError

from aiohttp import BasicAuth
from aiohttp import web

from . import backends


def get_ssh_principals(user: dict, config: dict) -> list[str]:
    if 'ssh_principals' in user:
        return user['ssh_principals']
    elif 'default_ssh_principals' in config:
        return config['default_ssh_principals']
    else:
        return []


async def create_cert(
    client_key: bytes, username: str, principal: str, config: dict
) -> bytes:
    old_mask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            dirpath = Path(tmp)

            ca_path = dirpath / 'ca'
            ca_path.write_text(config['ssh_ca_key'])

            key_path = dirpath / 'client.pub'
            key_path.write_bytes(client_key)

            cmd = [
                'ssh-keygen',
                '-I', f'sso:{username}',
                '-s', str(ca_path),
                '-n', principal,
                '-V', '-0:+8h',
                '-q',
                str(key_path),
            ]
            proc = await asyncio.create_subprocess_exec(*cmd)
            await proc.wait()
            if proc.returncode != 0:
                raise CalledProcessError(proc.returncode, cmd)

            cert_path = dirpath / 'client-cert.pub'
            return cert_path.read_bytes()
    finally:
        os.umask(old_mask)


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
    cert = await create_cert(client_pubkey, username, principal, config)

    return web.Response(body=cert, content_type='text/x-ssh-public-key')
