#!/usr/bin/env python3

# NOTE: This is a copy of flask session (https://github.com/fengsp/flask-session),
#       which doesn't seem to be maintained anymore. Redis sessions only because
#       the rest isn't used anyway.

# Original Licence:
#
# Copyright (c) 2014 by Shipeng Feng.
#
# Some rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the following
#   disclaimer in the documentation and/or other materials provided
#   with the distribution.
#
# * The names of the contributors may not be used to endorse or
#   promote products derived from this software without specific
#   prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import pickle

from typing import Optional, Dict
from uuid import uuid4

from flask.sessions import SessionMixin
from flask.sessions import SessionInterface
from redis import Redis
from itsdangerous import BadSignature
from itsdangerous.url_safe import URLSafeSerializer
from werkzeug.datastructures import CallbackDict

from flask import Flask, Request, Response


class RedisSession(CallbackDict, SessionMixin):
    """Baseclass for server-side based sessions."""

    sid: str
    modified: bool
    permanent: bool

    def __init__(self, redis: Redis, key_prefix: str, sid: Optional[str]=None,
                 initial: Optional[Dict]=None):
        def on_update(self):
            self.modified = True
        CallbackDict.__init__(self, initial, on_update)
        self.redis: Redis = redis
        self.key_prefix: str = key_prefix
        if sid is None:
            self.sid = str(uuid4())
        else:
            self.sid = sid
        self.permanent = True
        self.modified = False
        print('session', self.sid)

    def clear(self):
        self.redis.delete(f'{self.key_prefix}{self.sid}')
        self.sid = str(uuid4())


class RedisSessionInterface(SessionInterface):
    """Uses the Redis key-value store as a session backend.

    :param redis: A ``redis.Redis`` instance.
    :param key_prefix: A prefix that is added to all Redis store keys.
    :param secret_key: Used to sign the sid.
    """

    def __init__(self, redis: Redis, key_prefix: str, secret_key: str):
        self.redis: Redis = redis
        self.key_prefix: str = key_prefix
        self.safe_serializer = URLSafeSerializer(secret_key)

    def open_session(self, app: Flask, request: Request) -> RedisSession:
        sid = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
        if not sid:
            print('sid not in cookie')
            return RedisSession(redis=self.redis, key_prefix=self.key_prefix)
        try:
            # We have a sid from the cookie
            sid = self.safe_serializer.loads(sid)
        except BadSignature:
            print('Bad signature in cookie.')
            return RedisSession(redis=self.redis, key_prefix=self.key_prefix)

        if val := self.redis.get(f'{self.key_prefix}{sid}'):
            try:
                return RedisSession(sid=sid, initial=pickle.loads(val), redis=self.redis, key_prefix=self.key_prefix)
            except Exception:
                print('Unable to load session fron redis.')
                return RedisSession(redis=self.redis, key_prefix=self.key_prefix)
        print('missing key in redis')
        return RedisSession(redis=self.redis, key_prefix=self.key_prefix)

    def save_session(self, app: Flask, session: RedisSession, response: Response):  # type: ignore[override]
        # if not self.should_set_cookie(app, session):
        #    return

        # The session was modified.
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        response.delete_cookie(app.config['SESSION_COOKIE_NAME'],
                               domain=domain, path=path)

        self.redis.setex(name=f'{self.key_prefix}{session.sid}',
                         value=pickle.dumps(dict(session)),
                         time=app.permanent_session_lifetime)

        safe_value = self.safe_serializer.dumps(session.sid)
        if isinstance(safe_value, bytes):
            # Should not be bytes.
            safe_value = safe_value.decode()
        response.set_cookie(app.config['SESSION_COOKIE_NAME'],
                            value=safe_value,
                            max_age=None,
                            expires=self.get_expiration_time(app, session),
                            path=path,
                            domain=domain,
                            secure=self.get_cookie_secure(app),
                            httponly=self.get_cookie_httponly(app),
                            samesite=self.get_cookie_samesite(app))


class Session():

    def __init__(self, app: Optional[Flask]=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        """This is used to set up session for your app object.

        :param app: the Flask app object with proper configuration.
        """
        app.session_interface = self._get_interface(app)

    def _get_interface(self, app: Flask) -> SessionInterface:
        config = app.config.copy()
        config.setdefault('SESSION_KEY_PREFIX', 'session:')

        return RedisSessionInterface(redis=config['SESSION_REDIS'],
                                     key_prefix=config['SESSION_KEY_PREFIX'],
                                     secret_key=app.secret_key)
