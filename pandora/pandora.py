#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import secrets

from typing import Optional, Union, Tuple, List

from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .default import get_config, get_socket_path
from .helpers import roles_from_config, allowlist_default, expire_in_sec
# from .file import File
from .observable import TaskObservable, Observable
# from .report import Report
from .role import Role, RoleName
from .task import Task
from .user import User
from .storage_client import Storage


class Pandora():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))

        self.redis_pool_cache: ConnectionPool = ConnectionPool(
            connection_class=UnixDomainSocketConnection,
            path=get_socket_path('cache'), decode_responses=True)

        self.redis_pool_cache_bytes: ConnectionPool = ConnectionPool(
            connection_class=UnixDomainSocketConnection,
            path=get_socket_path('cache'))

        self.storage: Storage = Storage()

        # probably move that somewhere else
        if not self.storage.has_roles():
            for role in roles_from_config().values():
                role.store

        # Load user-defined allowlist
        for observable in TaskObservable.get_observables(links=allowlist_default(), allowlist=True):
            observable.store

    @property
    def redis_bytes(self):
        return Redis(connection_pool=self.redis_pool_cache_bytes)

    @property
    def redis(self):
        return Redis(connection_pool=self.redis_pool_cache)

    def check_redis_up(self):
        return self.redis.ping()

    # #### User ####

    def get_user(self, user_id: str) -> Optional[User]:
        u = self.storage.get_user(user_id)
        if u:
            return User(**u)
        return None

    def get_users(self):
        users = []
        for user in self.storage.get_users():
            users.append(User(**user))
        return users

    # ##############

    # #### Role ####

    def get_role(self, role_name: Union[str, RoleName]) -> Role:
        if isinstance(role_name, RoleName):
            role_name = role_name.name
        r = self.storage.storage.hgetall(f'roles:{role_name}')
        if not r:
            raise Exception(f'Unknown role: "{role_name}"')
        return Role(**r)

    def get_roles(self) -> List[Role]:
        roles = []
        for role in self.storage.get_roles():
            roles.append(Role(**role))
        return roles

    # ##############

    # #### Task ####
    def get_task(self, task_id: str) -> Task:
        t = self.storage.get_task(task_id)
        if not t:
            raise Exception(f'Unknown task ID: "{task_id}"')
        return Task(**t)

    """
    def get_task_reports(self, task_id: str) -> List[Report]:
        # get all the reports from workers associated to the task
        pass

    def get_related_tasks(self, linked_with: Task, extracted_from: Task, user: User):
        # get the linked and extracted tasks from the current task.
        pass

    def new_task(self, task_file, user: User, disabled_workers: List[str]) -> str:"""
    """
        Add new task in queue.
        :param (Stream) task_file: stream from flask
        :param (User) user: User triggering the task
        :param disabled_workers: List of disabled workers for this task
        :returns: The task ID.
        """
    """
        _file = File(stream=task_file, client_name=task_file.filename)
        _file.save()
        return self.enqueue_task(_file, user, disabled_workers)
    """
    def enqueue_task(self, task: Task):
        """
        Enqueue a task for processing.
        """
        fields = {
            'fid': task.file.uuid,
            'uid': task.user.get_id(),
            'pid': task.parent.rid if task.parent is not None else 0,
            'oid': task.origin.rid if task.origin is not None else 0,
            'disabled_workers': json.dumps(task.disabled_workers),
            'filename': task.file.original_filename
        }
        task.rid = self.redis.xadd(name='tasks_queue', fields=fields, id='*', maxlen=get_config('generic', 'tasks_max_len'))
        seed, expire = self.add_seed(task)
        return task.rid, seed

    def get_tasks(self, user: User):
        tasks = []
        for task in self.storage.get_tasks():
            _task = Task(**task)
            if not hasattr(_task, 'user'):
                continue
            if user.get_id() == _task.user.get_id() or user.is_admin:
                tasks.append(_task)
        return tasks

    # ##############

    # #### Observable ####

    def get_observables(self) -> List[Observable]:
        observables = []
        for observable in self.storage.get_observables():
            observables.append(Observable(**observable))
        return observables

    # ##############

    # #### Seed ####
    def check_seed(self, seed: str):
        rid = self.redis.get(f'seed:{seed}')
        return rid if rid is not None else None

    def add_seed(self, task: Task, time: Optional[str]=None) -> Tuple[str, Optional[int]]:
        seed = secrets.token_urlsafe()
        expire = expire_in_sec(time)
        if expire:
            self.redis.setex(name=f'seed:{seed}', time=expire, value=task.rid)
        else:
            self.redis.set(name=f'seed:{seed}', value=task.rid)
        return seed, expire
    # ##############
