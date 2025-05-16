import asyncio
import logging
import sys
from getpass import getpass

import aiosmtplib
import argon2

from .last_login import check_expired
from .last_login import check_last_login

logger = logging.getLogger(__name__)
hasher = argon2.PasswordHasher()


def _check_internal_password(encoded, password):
    if encoded.startswith('$argon2id$'):
        try:
            return hasher.verify(encoded, password)
        except argon2.exceptions.VerificationError:
            return False
    else:
        return False


def check_internal_password(encoded, password):
    if isinstance(encoded, list):
        return any(_check_internal_password(e, password) for e in encoded)
    else:
        return _check_internal_password(encoded, password)


def make_internal_password_cmd():
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
    if username not in config['users']:
        return None

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
        user = await _auth(username, password, config)
        if user:
            check_expired(user)
            check_last_login(username, user, config)
        return user
    except Exception:
        logger.exception('Authentication failed')
        return None
    return user
