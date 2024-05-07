#!/bin/env python3

import os
import subprocess
import sys

import requests

SERVER = 'https://example.com/sso/pam/'

try:
    username = os.environ['PAM_USER']
    password = os.environ['PAM_AUTHTOK']
except KeyError:
    sys.exit(0)

try:
    r = requests.post(SERVER, data={
        'username': username,
        'password': password,
    })

    r.raise_for_status()
    data = r.json()

    # pass parameters in env because /proc/*/environ is only readable by
    # owner, while /proc/*/cmdline is world-readable
    subprocess.run(['kub-update-user'], env={
        'USER': username,
        'PASSWORD': password,
        'UID': str(data['uid']),
        'FULLNAME': data['full_name'],
        'GROUPS': ','.join(data['groups']),
    })
except Exception as e:
    print(f'SSO failed: {e}')
    sys.exit(1)
