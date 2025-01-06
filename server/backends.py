import asyncio
import base64
import logging
import os
import sys
from getpass import getpass
from hashlib import pbkdf2_hmac

import aiosmtplib

logger = logging.getLogger(__name__)


def pbkdf2_sha256(password, salt, iterations):
    hash = pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return base64.b64encode(hash).decode('ascii')


def make_internal_password(password, iterations=500_000):
    salt = os.urandom(16)
    return '{}${}${}${}'.format(
        'pbkdf2_sha256',
        iterations,
        base64.b64encode(salt).decode('ascii'),
        pbkdf2_sha256(password, salt, iterations),
    )


def check_internal_password(encoded, password):
    algo, _iterations, _salt, old_hash = encoded.split('$')
    iterations = int(_iterations, 10)
    salt = base64.b64decode(_salt)

    if algo == 'pbkdf2_sha256':
        return pbkdf2_sha256(password, salt, iterations) == old_hash
    else:
        return False


def make_internal_password_interactive():
    password = getpass('Password: ')
    password_repeat = getpass('Password (again): ')
    if password != password_repeat:
        print('The two passwords did not match')
        sys.exit(1)
    print(make_internal_password(password))
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
