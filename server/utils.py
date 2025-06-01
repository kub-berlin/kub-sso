import datetime
import urllib.parse
from email.message import EmailMessage

import aiosmtplib
import jwt


def update_url(url: str, **params) -> str:
    url_parts = list(urllib.parse.urlparse(url))
    query = urllib.parse.parse_qs(url_parts[4])
    for key, value in params.items():
        if value is not None:
            query[key] = value
    url_parts[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(url_parts)


def encode_jwt(data: dict, use: str, config: dict, *, ttl=20) -> str:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    return jwt.encode(
        {
            **data,
            'iss': config['issuer'],
            'iat': now,
            'exp': now + datetime.timedelta(seconds=ttl),
            'x-use': use,
        },
        config['private_key_pem'],
        algorithm='RS256',
        headers={'kid': '1'},
    )


def decode_jwt(encoded: str, use: str, config: dict, **kwargs) -> dict:
    data = jwt.decode(
        encoded,
        config['public_key_pem'],
        algorithms=['RS256'],
        issuer=config['issuer'],
        **kwargs,
    )
    if data.get('x-use') != use:
        raise ValueError(use)
    return data


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
