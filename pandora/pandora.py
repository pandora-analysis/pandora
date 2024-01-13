#!/usr/bin/env python3

from __future__ import annotations

import json
import logging

from datetime import datetime
from typing import Optional, Union, List, Set

from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .default import get_config, get_socket_path, PandoraException
from .exceptions import InvalidPandoraObject
from .helpers import roles_from_config, Seed
from .report import Report
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

        self.seed = Seed()

        # probably move that somewhere else
        if not self.storage.has_roles():
            for role in roles_from_config().values():
                role.store()

    @property
    def redis_bytes(self) -> Redis:  # type: ignore[type-arg]
        return Redis(connection_pool=self.redis_pool_cache_bytes)

    @property
    def redis(self) -> Redis:  # type: ignore[type-arg]
        return Redis(connection_pool=self.redis_pool_cache)

    def check_redis_up(self) -> bool:
        return self.redis.ping()

    # #### User ####

    def get_user(self, user_id: str) -> User | None:
        u = self.storage.get_user(user_id)
        if u:
            return User(**u)
        return None

    def get_users(self) -> list[User]:
        users = []
        for user in self.storage.get_users():
            users.append(User(**user))
        return users

    # ##############

    # #### Role ####

    def get_role(self, role_name: str | RoleName) -> Role:
        if isinstance(role_name, RoleName):
            role_name = role_name.name
        r = self.storage.storage.hgetall(f'roles:{role_name}')
        if not r:
            raise InvalidPandoraObject(f'Unknown role: "{role_name}"')
        return Role(**r)

    def get_roles(self) -> list[Role]:
        roles = []
        for role in self.storage.get_roles():
            roles.append(Role(**role))
        return roles

    # ##############

    # #### Task ####
    def get_task(self, task_id: str) -> Task:
        t = self.storage.get_task(task_id)
        if not t:
            raise InvalidPandoraObject(f'Unknown task ID: "{task_id}"')
        # FIXME: get rid of that typing ignore
        return Task(**t)  # type: ignore

    def enqueue_task(self, task: Task) -> str:
        """
        Enqueue a task for processing.
        """
        fields = {
            'task_uuid': task.uuid,
            'disabled_workers': json.dumps(task.disabled_workers)
        }
        self.redis.xadd(name='tasks_queue', fields=fields, id='*',  # type: ignore[arg-type]
                        maxlen=get_config('generic', 'tasks_max_len'))
        return task.uuid

    def trigger_manual_worker(self, task: Task, worker: str) -> None:
        fields = {
            'task_uuid': task.uuid,
            'manual_worker': worker
        }
        self.redis.xadd(name='tasks_queue', fields=fields, id='*',  # type: ignore[arg-type]
                        maxlen=get_config('generic', 'tasks_max_len'))

    def add_extracted_reference(self, task: Task, extracted_task: Task) -> None:
        self.storage.add_extracted_reference(task.uuid, extracted_task.uuid)

    def get_tasks(self, user: User, *, first_date: datetime | int | float | str=0, last_date: datetime | int | float | str='+Inf') -> list[Task]:
        if isinstance(first_date, datetime):
            first_date = first_date.timestamp()
        if isinstance(last_date, datetime):
            last_date = last_date.timestamp()
        tasks = []
        for task in self.storage.get_tasks(first_date=first_date, last_date=last_date):
            # FIXME: get rid of that typing ignore
            try:
                _task = Task(**task)  # type: ignore
            except PandoraException as e:
                self.logger.warning(f'Unable to load task {task}: {e}')
                continue
            if user.is_admin or (_task.user and user.get_id() == _task.user.get_id()):
                tasks.append(_task)
        return tasks

    # ##############

    # #### Observable ####

    # def get_observables(self) -> List[Observable]:
        # TODO: get most recent observables, optionally filter
    #    pass

    # #### Observables Lists ####

    def get_suspicious_observables(self) -> dict[str, str] | None:
        return self.storage.get_suspicious_observables()

    def add_suspicious_observable(self, observable: str, observable_type: str) -> None:
        return self.storage.add_suspicious_observable(observable, observable_type)

    def delete_suspicious_observable(self, observable: str) -> None:
        return self.storage.delete_suspicious_observable(observable)

    def get_legitimate_observables(self) -> dict[str, str] | None:
        return self.storage.get_legitimate_observables()

    def add_legitimate_observable(self, observable: str, observable_type: str) -> None:
        return self.storage.add_legitimate_observable(observable, observable_type)

    def delete_legitimate_observable(self, observable: str) -> None:
        return self.storage.delete_legitimate_observable(observable)

    # ##############

    # #### Seed ####

    def is_seed_valid(self, task: Task, seed: str) -> bool:
        if task.uuid == self.seed.get_task_uuid(seed):
            return True
        if hasattr(task, 'parent') and task.parent:
            return self.is_seed_valid(task.parent, seed)
        return False

    # ##############

    # #### Report ####

    def get_report(self, task_id: str, worker_name: str) -> Report:
        r = self.storage.get_report(task_id, worker_name)
        if not r:
            raise InvalidPandoraObject(f'Unknown Report ID: "{task_id}-{worker_name}"')
        # FIXME: get rid of that typing ignore
        return Report(**r)

    # #### Other ####

    def get_enabled_workers(self) -> set[str]:
        return self.redis.smembers('enabled_workers')

    # #### pubsub ####

    def publish_on_channel(self, channel_name: str, data: str) -> None:
        self.redis.publish(channel_name, data)
