import datetime
from email.message import EmailMessage

import aiosmtplib
import jwt
from aiohttp import web

from .backends import hasher
from .oidc import decode_jwt
from .oidc import encode_jwt


async def send_message(to, subject, body, config, reply_to=None):
    message = EmailMessage()
    message['From'] = config['email']['username'],
    message['To'] = to
    message['Subject'] = subject
    if reply_to:
        message['Reply-To'] = reply_to
    message.set_content(body)

    return await aiosmtplib.send(
        message,
        hostname=config['email']['host'],
        username=config['email']['username'],
        password=config['email']['password'],
        use_tls=True,
    )


def render_form(request, *, error: bool):
    config = request.app['config']

    with open(request.app['dir'] / 'signup.html') as fh:
        template = fh.read()
    spam_token = encode_jwt({}, 'spam', config, ttl=3600)
    template = template.replace('{token}', spam_token)
    if error:
        template = template.replace('hidden', '', 1)
    return web.Response(text=template, content_type='text/html')


def render_success(request):
    with open(request.app['dir'] / 'signup_success.html') as fh:
        template = fh.read()
    return web.Response(text=template, content_type='text/html')


async def signup_handler(request):
    config = request.app['config']

    if request.method != 'POST':
        return render_form(request, error=False)

    post_data = await request.post()

    try:
        decode_jwt(post_data['token'], 'spam', config)
    except jwt.exceptions.InvalidTokenError as e:
        return render_form(request, error=True)

    if len(post_data.get('password', '')) < 8:
        return render_form(request, error=True)

    if post_data['password'] != post_data.get('password_confirm'):
        return render_form(request, error=True)

    msg = '\n'.join(f'{k} = "{v}"' for k, v in [
        ('full_name', post_data['full_name']),
        ('email', post_data['email']),
        ('created_at', datetime.date.today().isoformat()),
        ('auth_password', hasher.hash(post_data['password'])),
    ])

    await send_message(
        config['signup_email'],
        '[kub-sso] New signup request',
        msg,
        config,
        reply_to=post_data['email'],
    )

    return render_success(request)
