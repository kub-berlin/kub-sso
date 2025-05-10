import argparse
from pathlib import Path

import tomllib
from aiohttp import web

from . import backends
from . import last_login
from . import oidc
from . import signup


async def pam_handler(request):
    config = request.app['config']
    post_data = await request.post()

    try:
        username = post_data['username']
        password = post_data['password']
    except KeyError as e:
        raise web.HTTPBadRequest from e

    user_config = await backends.auth(username, password, config)

    if not user_config:
        raise web.HTTPForbidden

    return web.json_response({
        'username': username,
        'uid': user_config['unix_id'],
        'full_name': user_config.get('full_name', ''),
        'groups': user_config.get('unix_groups', []),
        'ecryptfs_passphrase': user_config['ecryptfs_passphrase'],
    })


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--config', default='/etc/kub-sso/server.toml')
    parser.add_argument('--password', action='store_true', help='generate password hash and exit')  # noqa
    parser.add_argument('--locked', action='store_true', help='list locked users and exit')  # noqa
    args = parser.parse_args()

    if args.password:
        backends.make_internal_password_cmd()
    elif args.locked:
        with open(args.config, 'rb') as fh:
            config = tomllib.load(fh)
        last_login.list_locked_users_cmd(config)

    app = web.Application(middlewares=[
        web.normalize_path_middleware(),
    ])
    app['dir'] = Path(__file__).parent
    with open(args.config, 'rb') as fh:
        app['config'] = tomllib.load(fh)

    app.router.add_post('/pam/', pam_handler)

    app.router.add_get('/signup/', signup.signup_handler)
    app.router.add_post('/signup/', signup.signup_handler)

    app.router.add_get('/.well-known/openid-configuration/', oidc.config_handler)
    app.router.add_get('/.well-known/jwks.json', oidc.jwks_handler)
    app.router.add_get('/login/', oidc.login_handler)
    app.router.add_post('/login/', oidc.login_handler)
    app.router.add_post('/token/', oidc.token_handler)
    app.router.add_get('/userinfo/', oidc.userinfo_handler)
    app.router.add_post('/userinfo/', oidc.userinfo_handler)

    app.router.add_static('/static/', app['dir'] / 'static')

    web.run_app(app, host='localhost', port=args.port)
