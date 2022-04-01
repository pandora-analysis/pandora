#!/usr/bin/env python3

import json
import logging
import secrets

from datetime import datetime
from typing import Optional, Union, Tuple, List, Set

from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .default import get_config, get_socket_path
from .helpers import roles_from_config, expire_in_sec
from .observable import Observable
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

        # probably move that somewhere else
        if not self.storage.has_roles():
            for role in roles_from_config().values():
                role.store()

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
        # FIXME: get rid of that typing ignore
        return Task(**t)  # type: ignore

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
    def enqueue_task(self, task: Task) -> str:
        """
        Enqueue a task for processing.
        """
        fields = {
            'task_uuid': task.uuid,
            'disabled_workers': json.dumps(task.disabled_workers)
        }
        self.redis.xadd(name='tasks_queue', fields=fields, id='*',
                        maxlen=get_config('generic', 'tasks_max_len'))
        return task.uuid

    def add_extracted_reference(self, task: Task, extracted_task: Task):
        self.storage.add_extracted_reference(task.uuid, extracted_task.uuid)

    def get_tasks(self, user: User, *, first_date: Union[datetime, int, float, str]=0, last_date: Union[datetime, int, float, str]='+Inf'):
        if isinstance(first_date, datetime):
            first_date = first_date.timestamp()
        if isinstance(last_date, datetime):
            last_date = last_date.timestamp()
        tasks = []
        for task in self.storage.get_tasks(first_date=first_date, last_date=last_date):
            # FIXME: get rid of that typing ignore
            _task = Task(**task)  # type: ignore
            if user.is_admin or (hasattr(_task, 'user') and user.get_id() == _task.user.get_id()):
                tasks.append(_task)
        return tasks

    # ##############

    # #### Observable ####

    def get_observables(self) -> List[Observable]:
        # TODO: get most recent observables, optionnally filter
        pass

    # ##############

    # #### Seed ####

    def get_seed_uuid(self, seed: str) -> Optional[str]:
        return self.redis.get(f'seed:{seed}')

    def add_seed(self, task: Task, time: str, seed: Optional[str]=None) -> Tuple[str, int]:
        expire = expire_in_sec(time)
        if not seed:
            seed = secrets.token_urlsafe()
        if expire:
            self.redis.setex(name=f'seed:{seed}', time=expire, value=task.uuid)
        else:
            self.redis.set(name=f'seed:{seed}', value=task.uuid)
        return seed, expire

    def is_seed_valid(self, task: Task, seed: str) -> bool:
        if task.uuid == self.get_seed_uuid(seed):
            return True
        elif hasattr(task, 'parent') and task.parent:
            return self.is_seed_valid(task.parent, seed)
        return False

    # ##############

    # #### Report ####

    def get_report(self, task_id: str, worker_name: str) -> Report:
        r = self.storage.get_report(task_id, worker_name)
        if not r:
            raise Exception(f'Unknown Report ID: "{task_id}-{worker_name}"')
        # FIXME: get rid of that typing ignore
        return Report(**r)

    # #### Other ####

    def get_enabled_workers(self) -> Set[str]:
        return self.redis.smembers('enabled_workers')
