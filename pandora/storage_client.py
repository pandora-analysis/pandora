#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import operator

from typing import Optional, Dict, List, Union

from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .default import get_socket_path


class Storage():

    def __init__(self) -> None:
        # NOTE: this will be a connector to kvrocks
        self._redis_pool_storage: ConnectionPool = ConnectionPool(
            connection_class=UnixDomainSocketConnection,
            path=get_socket_path('cache'), decode_responses=True)

    @property
    def storage(self):
        return Redis(connection_pool=self._redis_pool_storage)

    # #### User ####

    def get_user(self, user_id: str) -> Optional[Dict[str, str]]:
        return self.storage.hgetall(f'users:{user_id}')

    def set_user(self, user: Dict[str, str]) -> None:
        self.storage.hmset(f'users:{user["session_id"]}', user)
        # NOTE: do we want to expire all of them?
        self.storage.expire(f'users:{user["session_id"]}', 36000)
        self.storage.sadd('users', user["session_id"])

    def get_users(self):
        users = []
        to_pop = []
        for session_id in self.storage.smembers('users'):
            user = self.storage.hgetall(f'users:{session_id}')
            if user:
                users.append(user)
            else:
                # Session expired
                to_pop.append(session_id)
        if to_pop:
            self.storage.srem('users', *to_pop)
        users.sort(key=operator.itemgetter('last_seen'), reverse=True)
        return users

    # ##############

    # #### Role ####

    def get_role(self, role_name: str) -> Dict[str, str]:
        return self.storage.hgetall(f'roles:{role_name}')

    def get_roles(self) -> List[Dict[str, str]]:
        roles = []
        for role_name in sorted(list(self.storage.smembers('roles'))):
            roles.append(self.get_role(role_name))
        return roles

    def set_role(self, role: Dict[str, str]) -> None:
        self.storage.hmset(f'roles:{role["name"]}', role)
        self.storage.sadd('roles', role["name"])

    def has_roles(self):
        return self.storage.exists('roles')

    # ##############

    # #### Observable ####

    def set_observable(self, observable: Dict[str, str]):
        # TODO: need UUID for each observable.
        if 'allowlist' in observable and observable['allowlist']:
            self.storage.hmset(f'observables:allowlist:{observable["address"]}', observable)
            self.storage.sadd('observables:allowlist', observable["address"])
        else:
            raise Exception('not implemented')

    def get_observables(self) -> List[Dict[str, str]]:
        observables = []
        for address in self.storage.smembers('observables:allowlist'):
            observables.append(self.storage.hgetall(f'observables:allowlist:{address}'))
        return observables

    # ##############

    # #### File ####

    def get_file(self, file_id: str) -> Dict[str, str]:
        return self.storage.hgetall(f'files:{file_id}')

    def set_file(self, file_details: Dict[str, Union[str, int]]):
        self.storage.hmset(f'files:{file_details["uuid"]}', file_details)
        self.storage.sadd('files', file_details["uuid"])

    def get_files(self) -> List[Dict[str, str]]:
        files = []
        for uuid in self.storage.smembers('files'):
            files.append(self.storage.hgetall(f'files:{uuid}'))
        return files

    # ##############

    # #### Task ####

    def get_task(self, task_id: str) -> Dict[str, str]:
        return self.storage.hgetall(f'tasks:{task_id}')

    def set_task(self, task: Dict[str, str]):
        self.storage.hmset(f'tasks:{task["rid"]}', task)
        self.storage.sadd('tasks', task["rid"])

    def get_tasks(self) -> List[Dict[str, str]]:
        tasks = []
        for rid in self.storage.smembers('tasks'):
            tasks.append(self.storage.hgetall(f'tasks:{rid}'))
        tasks.sort(key=operator.itemgetter('save_date'), reverse=True)
        return tasks
