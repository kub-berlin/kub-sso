import datetime

import jwt
from aiohttp import web

from .backends import hasher
from .utils import decode_jwt
from .utils import encode_jwt
from .utils import send_message
from .utils import update_url


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

    activation_link = update_url(
        config['issuer'] + 'verify/',
        token=encode_jwt({
            'full_name': post_data['full_name'].strip(),
            'email': post_data['email'],
            'fg': post_data.get('fg', '').strip(),
            'password': hasher.hash(post_data['password']),
        }, 'signup', config, ttl=60 * 60 * 24 * 7)
    )

    await send_message(
        post_data['email'],
        config['signup_msg_subject'],
        config['signup_msg_body'].format(
            full_name=post_data['full_name'].strip(),
            link=activation_link,
        ),
        config,
        reply_to=config['signup_email'],
    )

    return render_message(request, (
        'Bitte klicke auf den Bestätigungslink, den wir dir in '
        'einer E-Mail zugeschickt haben.'
    ))


async def verify_handler(request):
    config = request.app['config']

    try:
        data = decode_jwt(request.query['token'], 'signup', config)
    except Exception:
        return render_message(
            request, 'Der Bestätigungslink ist ungültig.', status=400
        )

    msg = '\n'.join(f'{k} = "{v}"' for k, v in [
        ('full_name', data['full_name']),
        ('email', data['email']),
        ('created_at', datetime.date.today().isoformat()),
        ('auth_password', data['password']),
    ])

    if data.get('fg'):
        msg += f'\n\nFachgruppe: {data["fg"]}'

    await send_message(
        config['signup_email'],
        config['signup_msg_subject'],
        msg,
        config,
        reply_to=data['email'],
    )

    return render_message(request, (
        'Wir haben die Anfrage bekommen und kümmern uns so schnell '
        'wie möglich darum!'
    ))
