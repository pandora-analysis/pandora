#!/usr/bin/env python3

from __future__ import annotations

import importlib
import inspect
import logging
import logging.config
from typing import Mapping

from redis import Redis

from pandora.default import AbstractManager, get_socket_path, get_config
from pandora.exceptions import MissingWorker, ConfigError
from pandora.helpers import workers
from pandora.workers.base import BaseWorker

logging.config.dictConfig(get_config('logging'))


class WorkersManager(AbstractManager):

    def __init__(self, loglevel: int | None=None) -> None:
        super().__init__(loglevel)
        self.script_name = 'workers_manager'
        self._workers: list[BaseWorker] = []

        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

        self.redis.delete('enabled_workers')

        for module_name, w_config in workers().items():
            self._workers += self._init_worker(module_name, w_config)

        for worker in self._workers:
            self.logger.info(f'starting worker {worker.name}...')
            worker.start()

    def _get_worker_class(self, module) -> type[BaseWorker]:  # type: ignore[no-untyped-def]
        for class_name, worker in inspect.getmembers(module, inspect.isclass):
            if class_name == 'BaseWorker':
                continue
            if issubclass(worker, BaseWorker):
                return worker
        raise MissingWorker(f'The worker class is missing in {module}')

    def _init_worker(self, module_name: str, worker_conf: dict[str, dict[str, str | int | bool]], restart: bool=False) -> list[BaseWorker]:
        """
        Create a new worker with given conf.
        :param worker_conf: dict extracted from yaml
        :param replicas: number of workers to create (by default replicas is taken from worker_conf)
        :param start_index: starting index for worker names
        :return: list of BaseWorker objects
        """
        # Check replicas value
        replicas = int(worker_conf['meta']['replicas'])
        if replicas < 1:
            return []

        # Import module
        module = importlib.import_module(f'pandora.workers.{module_name}')
        options: Mapping[str, str | int | bool] = {
            key: value for key, value in worker_conf['settings'].items()
            if key not in ('cache', 'timeout')
        }
        status_in_report = {}
        if 'status_in_report' in worker_conf:
            status_in_report = worker_conf['status_in_report']

        # [re]Create workers
        if restart:
            replicas = 1
        workers_list = []
        for i in range(1, replicas + 1):
            try:
                worker = self._get_worker_class(module)(
                    module=module_name, worker_id=i,
                    cache=worker_conf['settings']['cache'],  # type: ignore[arg-type]
                    timeout=worker_conf['settings']['timeout'],  # type: ignore[arg-type]
                    loglevel=self.loglevel,
                    status_in_report=status_in_report,  # type: ignore[arg-type]
                    **options
                )
                if i == 1 and not worker.disabled:
                    self.redis.sadd('enabled_workers', worker.module)

            except TypeError as e:
                key = str(e).rsplit(': ', maxsplit=1)[-1]
                raise ConfigError(f"missing mandatory key {key} for worker in config") from e
            workers_list.append(worker)
        return workers_list

    def _manager(self) -> None:
        """
        Restart eventual dead workers.
        """
        for worker in self._workers:
            if worker.is_alive():
                continue
            self.logger.info(f'restart dead worker {worker.module}')
            self._workers.remove(worker)
            # Restart module worker
            module_name, _ = worker.module.split('-')
            new_worker = self._init_worker(module_name, worker_conf=workers()[module_name], restart=True)[0]
            self._workers.append(new_worker)
            new_worker.start()

    def _to_run_forever(self) -> None:
        self._manager()

    def _wait_to_finish(self) -> None:
        self.redis.delete('enabled_workers')


def main() -> None:
    wm = WorkersManager()
    wm.run(sleep_in_sec=60)


if __name__ == '__main__':
    main()
