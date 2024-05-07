import argparse

import toml
from aiohttp import web

from . import backends


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
    with open(args.config) as fh:
        app['config'] = toml.load(fh)
    app.router.add_post('/pam/', pam_handler)
    web.run_app(app, host='localhost', port=args.port)
