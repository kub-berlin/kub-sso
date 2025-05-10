import datetime
import json
import sys
from pathlib import Path

LAST_LOGIN_PATH = Path('/var/lib/kub-sso/last_login.json')


def _get_last_logins():
    if LAST_LOGIN_PATH.exists():
        with LAST_LOGIN_PATH.open() as fh:
            return json.load(fh)
    return {}


def _check_last_login(username, user, last_logins, config):
    days = config.get('max_days_since_last_login', 30)
    if days is None:
        return True
    s = last_logins.get(username, user.get('created_at', '1970-01-01'))
    last_login = datetime.date.fromisoformat(s)
    return last_login + datetime.timedelta(days=days) >= datetime.date.today()


def check_last_login(username, user, config):
    last_logins = _get_last_logins()
    if not _check_last_login(username, user, last_logins, config):
        raise ValueError('last_login')

    last_logins[username] = datetime.date.today().isoformat()
    with LAST_LOGIN_PATH.open('w') as fh:
        json.dump(last_logins, fh, indent=2, sort_keys=True)


def list_locked_users_cmd(config):
    last_logins = _get_last_logins()
    for username, user in config['users'].items():
        if not _check_last_login(username, user, last_logins, config):
            print(username)
    sys.exit(0)
