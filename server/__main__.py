import argparse
from pathlib import Path

import toml
from aiohttp import web

from . import backends
from . import oidc


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
    })


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--config', default='/etc/kub-sso/server.toml')
    parser.add_argument('--password', action='store_true')
    args = parser.parse_args()

    if args.password:
        backends.make_internal_password_interactive()

    app = web.Application()
    app['dir'] = Path(__file__).parent
    with open(args.config) as fh:
        app['config'] = toml.load(fh)
    app.router.add_post('/pam/', pam_handler)
    app.router.add_get('/discovery/', oidc.discovery_handler)
    app.router.add_get('/login/', oidc.login_handler)
    app.router.add_post('/login/', oidc.login_handler)
    app.router.add_post('/token/', oidc.token_handler)
    app.router.add_static('/static/', app['dir'] / 'static')
    web.run_app(app, host='localhost', port=args.port)
