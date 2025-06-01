import datetime

import jwt
from aiohttp import web

from .backends import hasher
from .utils import decode_jwt
from .utils import encode_jwt
from .utils import send_message


def render_form(request, *, error: bool):
    config = request.app['config']

    with open(request.app['dir'] / 'signup.html') as fh:
        template = fh.read()
    spam_token = encode_jwt({}, 'spam', config, ttl=3600)
    template = template.replace('{token}', spam_token)
    if error:
        template = template.replace('hidden', '', 1)
    return web.Response(text=template, content_type='text/html')


def render_message(request, msg: str, *, status: int = 200):
    with open(request.app['dir'] / 'message.html') as fh:
        template = fh.read()
    text = template.format(msg=msg)
    return web.Response(text=text, content_type='text/html', status=status)


async def signup_handler(request):
    config = request.app['config']

    if request.method != 'POST':
        return render_form(request, error=False)

    post_data = await request.post()

    try:
        decode_jwt(post_data['token'], 'spam', config)
    except jwt.exceptions.InvalidTokenError:
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
        config['signup_msg_subject'],
        msg,
        config,
        reply_to=post_data['email'],
    )

    return render_message(request, (
        'Wir haben die Anfrage bekommen und kümmern uns so schnell '
        'wie möglich darum!'
    ))
