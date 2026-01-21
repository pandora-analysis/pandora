#!/usr/bin/env python3

from __future__ import annotations

import logging

from collections.abc import Iterator
from datetime import datetime, timedelta

from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .default import get_config, get_socket_path
from .storage_client import Storage
from .task import Task


class Indexing():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))

        self.storage: Storage = Storage()

        self.__redis_pool_bytes = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                                 path=get_socket_path('indexing'))
        self.__redis_pool = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                           path=get_socket_path('indexing'), decode_responses=True)

        self.time_delta_on_index = timedelta(days=get_config('generic', 'max_days_index'))

    @property
    def redis_bytes(self) -> Redis[bytes]:
        return Redis(connection_pool=self.__redis_pool_bytes)

    @property
    def redis(self) -> Redis[str]:
        return Redis(connection_pool=self.__redis_pool)  # type: ignore[return-value]

    def __limit_failsafe(self, oldest_task: datetime | None=None, limit: int | None=None) -> float | str:
        if limit and not oldest_task:
            return '-Inf'
        # We have no limit set, we *must* set an oldest task
        return oldest_task.timestamp() if oldest_task else (datetime.now() - self.time_delta_on_index).timestamp()

    def can_index(self, task_uuid: str | None=None) -> bool:
        if task_uuid:
            return bool(self.redis.set(f'ongoing_indexing|{task_uuid}', 1, ex=360, nx=True))

        return bool(self.redis.set('ongoing_indexing', 1, ex=3600, nx=True))

    def indexing_done(self, task_uuid: str | None=None) -> None:
        if task_uuid:
            self.redis.delete(f'ongoing_indexing|{task_uuid}')
        else:
            self.redis.delete('ongoing_indexing')

    def force_reindex(self, task_uuid: str) -> None:
        p = self.redis.pipeline()
        p.srem('indexed_sha256', task_uuid)
        p.srem('indexed_filename', task_uuid)
        p.execute()

    def task_indexed(self, task_uuid: str) -> tuple[bool, bool]:
        p = self.redis.pipeline()
        p.sismember('indexed_sha256', task_uuid)
        p.sismember('indexed_filename', task_uuid)
        to_return: list[bool] = p.execute()
        return tuple(to_return)  # type: ignore[return-value]

    def index_task(self, uuid_to_index: str) -> bool:
        if not self.can_index(uuid_to_index):
            self.logger.info(f'Indexing on {uuid_to_index} ongoing, skipping. ')
            return False

        try:
            indexed = self.task_indexed(uuid_to_index)
            if all(indexed):
                return False

            # run index
            t = self.storage.get_task(uuid_to_index)
            task = Task(**t)  # type: ignore[call-overload]
            if not indexed[0]:
                self.logger.info(f'Indexing sha256 for {uuid_to_index}')
                self.index_sha256_task(task)
            if not indexed[1]:
                self.logger.info(f'Indexing filename for {uuid_to_index}')
                self.index_filename_task(task)
        except Exception as e:
            self.logger.error(f'Error during indexing for {uuid_to_index}: {e}')
        finally:
            self.indexing_done(uuid_to_index)
            return True

    # ============= sha256 =============

    @property
    def sha256(self) -> set[str]:
        return self.redis.smembers('sha256')

    def index_sha256_task(self, task: Task) -> None:
        if self.redis.sismember('indexed_sha256', task.uuid):
            # do not reindex
            return

        self.redis.sadd('indexed_sha256', task.uuid)
        self.logger.debug(f'Indexing sha256 for {task.uuid} ... ')
        pipeline = self.redis.pipeline()
        internal_index = f'task_indexes|{task.uuid}'
        pipeline.sadd(internal_index, 'sha256')

        pipeline.sadd(f'{internal_index}|sha256', task.file.sha256)
        pipeline.sadd('sha256', task.file.sha256)
        pipeline.zadd(f'sha256|{task.file.sha256}|tasks',
                      mapping={task.uuid: task.save_date.timestamp()})
        pipeline.sadd(f'{internal_index}|sha256|{task.file.sha256}', task.uuid)
        pipeline.execute()
        self.logger.debug(f'done with sha256 for {task.uuid}.')

    def get_tasks_sha256(self, sha256: str, most_recent_task: datetime | None = None,
                         oldest_task: datetime | None = None,
                         offset: int | None = None, limit: int | None = None) -> list[str]:

        max_score: str | float = most_recent_task.timestamp() if most_recent_task else '+Inf'
        min_score: str | float = self.__limit_failsafe(oldest_task, limit)
        return self.redis.zrevrangebyscore(f'sha256|{sha256}|tasks', max_score, min_score, start=offset, num=limit)

    def scan_tasks_sha256(self, sha256: str) -> Iterator[tuple[str, float]]:
        yield from self.redis.zscan_iter(f'sha256|{sha256}|tasks')

    def get_tasks_sha256_count(self, sha256: str) -> int:
        return self.redis.zcard(f'sha256|{sha256}|tasks')

    # ============= filename =============

    @property
    def filename(self) -> set[str]:
        return self.redis.smembers('filename')

    def index_filename_task(self, task: Task) -> None:
        if self.redis.sismember('indexed_filename', task.uuid):
            # do not reindex
            return

        self.redis.sadd('indexed_filename', task.uuid)
        self.logger.debug(f'Indexing filename for {task.uuid} ... ')
        pipeline = self.redis.pipeline()
        internal_index = f'task_indexes|{task.uuid}'
        pipeline.sadd(internal_index, 'filename')

        pipeline.sadd(f'{internal_index}|filename', task.file.original_filename)
        pipeline.sadd('filename', task.file.original_filename)
        pipeline.zadd(f'filename|{task.file.original_filename}|tasks',
                      mapping={task.uuid: task.save_date.timestamp()})
        pipeline.sadd(f'{internal_index}|filename|{task.file.original_filename}', task.uuid)
        pipeline.execute()
        self.logger.debug(f'done with filename for {task.uuid}.')

    def get_tasks_filename(self, filename: str, most_recent_task: datetime | None = None,
                           oldest_task: datetime | None = None,
                           offset: int | None = None, limit: int | None = None) -> list[str]:

        max_score: str | float = most_recent_task.timestamp() if most_recent_task else '+Inf'
        min_score: str | float = self.__limit_failsafe(oldest_task, limit)
        return self.redis.zrevrangebyscore(f'filename|{filename}|tasks', max_score, min_score, start=offset, num=limit)

    def scan_tasks_filename(self, filename: str) -> Iterator[tuple[str, float]]:
        yield from self.redis.zscan_iter(f'filename|{filename}|tasks')

    def get_tasks_filename_count(self, filename: str) -> int:
        return self.redis.zcard(f'filename|{filename}|tasks')
