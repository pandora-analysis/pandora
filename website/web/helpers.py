#!/usr/bin/env python3

import hashlib
import json
import os

from functools import lru_cache, wraps
from pathlib import Path
from typing import Dict, Union, List, Optional

from flask import abort
import flask_login  # type: ignore
from werkzeug.security import generate_password_hash

from pandora.default import get_homedir, get_config
from pandora.pandora import Pandora
from pandora.role import RoleName
from pandora.task import Task


# Method to make sizes in bytes human readable
# Source: https://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return ("{:.1f}{}{}".format(num, 'Yi', suffix)).strip()


def src_request_ip(request) -> str:
    # NOTE: X-Real-IP is the IP passed by the reverse proxy in the headers.
    real_ip = request.headers.get('X-Real-IP')
    if not real_ip:
        real_ip = request.remote_addr
    return real_ip


@lru_cache(64)
def get_secret_key() -> bytes:
    secret_file_path: Path = get_homedir() / 'secret_key'
    if not secret_file_path.exists() or secret_file_path.stat().st_size < 64:
        if not secret_file_path.exists() or secret_file_path.stat().st_size < 64:
            with secret_file_path.open('wb') as f:
                f.write(os.urandom(64))
    with secret_file_path.open('rb') as f:
        return f.read()


def update_user_role(pandora: Pandora, task: Task, seed: Optional[str]=None):
    if flask_login.current_user.is_admin:
        flask_login.current_user.role = pandora.get_role(role_name=RoleName.admin)
    elif task.user and task.user.get_id() == flask_login.current_user.get_id():
        flask_login.current_user.role = pandora.get_role(role_name=RoleName.owner)
    elif seed is not None and pandora.is_seed_valid(task, seed):
        flask_login.current_user.role = pandora.get_role(role_name=RoleName.reader)
    else:
        flask_login.current_user.role = pandora.get_role(role_name=RoleName.other)


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not flask_login.current_user.is_admin:
            return abort(403)
        return func(*args, **kwargs)

    return wrapper


@lru_cache(64)
def get_users() -> Dict[str, Union[str, List[str]]]:
    return get_config('generic', 'users')


@lru_cache(64)
def build_users_table() -> Dict[str, Dict[str, str]]:
    users_table: Dict[str, Dict[str, str]] = {}
    for username, authstuff in get_users().items():
        if isinstance(authstuff, str):
            # just a password, make a key
            if not authstuff:
                raise Exception(f'Password for {username} is empty, not allowed.')
            users_table[username] = {}
            users_table[username]['password'] = generate_password_hash(authstuff)
            users_table[username]['authkey'] = hashlib.pbkdf2_hmac('sha256', get_secret_key(),
                                                                   authstuff.encode(),
                                                                   100000).hex()

        elif isinstance(authstuff, list) and len(authstuff) == 2:
            if not authstuff[0]:
                raise Exception(f'Password for {username} is empty, not allowed.')
            if isinstance(authstuff[0], str) and isinstance(authstuff[1], str) and len(authstuff[1]) == 64:
                users_table[username] = {}
                users_table[username]['password'] = generate_password_hash(authstuff[0])
                users_table[username]['authkey'] = authstuff[1]
        else:
            raise Exception('User setup invalid. Must be "username": "password" or "username": ["password", "token 64 chars (sha256)"]')
    return users_table


@lru_cache(64)
def build_keys_table() -> Dict[str, str]:
    keys_table = {}
    for username, authstuff in build_users_table().items():
        if 'authkey' in authstuff:
            keys_table[authstuff['authkey']] = username
    return keys_table


def load_user_from_request(request) -> Optional[str]:
    '''Returns the username if the auth key matches'''
    api_key = request.headers.get('Authorization')
    if not api_key:
        return None
    api_key = api_key.strip()
    keys_table = build_keys_table()
    if api_key in keys_table:
        return keys_table[api_key]
    return None


@lru_cache(64)
def sri_load() -> Dict[str, Dict[str, str]]:
    with (get_homedir() / 'website' / 'web' / 'sri.txt').open() as f:
        return json.load(f)
