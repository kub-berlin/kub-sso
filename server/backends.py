import asyncio
import logging
import sys
from getpass import getpass

import aiosmtplib
import argon2

logger = logging.getLogger(__name__)
hasher = argon2.PasswordHasher()


def check_internal_password(encoded, password):
    if encoded.startswith('$argon2id$'):
        return hasher.verify(encoded, password)
    else:
        return False


def make_internal_password_interactive():
    password = getpass('Password: ')
    password_repeat = getpass('Password (again): ')
    if password != password_repeat:
        print('The two passwords did not match')
        sys.exit(1)
    print(hasher.hash(password))
    sys.exit(0)


async def check_unix_password(username, password):
    proc = await asyncio.create_subprocess_exec(
        'su', '-c', 'true', username,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={'LC_ALL': 'C'},
    )
    stdout, stderr = await proc.communicate(password.encode())
    if proc.returncode == 0:
        if stdout != b'':
            raise ValueError(stdout)
        if stderr != b'Password: ':
            raise ValueError(stderr)
        return True
    return False


async def check_smtp_password(email, password, config):
    domain = email.split('@', 1)[1]
    hostname = config['smtp'][domain]
    try:
        async with aiosmtplib.SMTP(
            hostname=hostname, username=email, password=password, use_tls=True
        ):
            return True
    except aiosmtplib.errors.SMTPAuthenticationError:
        return False


async def _auth(username, password, config):
    user_config = config['users'][username]
    auth_type = user_config.get('auth', 'internal')

    if auth_type == 'internal':
        if check_internal_password(user_config['auth_password'], password):
            return user_config
    elif auth_type == 'unix':
        if await check_unix_password(username, password):
            return user_config
    elif auth_type == 'smtp':
        if await check_smtp_password(user_config['email'], password, config):
            return user_config

    return None


async def auth(username, password, config):
    try:
        return await _auth(username, password, config)
    except Exception:
        logger.exception('Authentication failed')
        return None
