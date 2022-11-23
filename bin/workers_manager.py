#!/usr/bin/env python3

import importlib
import inspect
import logging
import logging.config

from typing import List, Dict, Type

from redis import Redis

from pandora.default import AbstractManager, get_socket_path, get_config
from pandora.exceptions import MissingWorker, ConfigError
from pandora.helpers import workers
from pandora.workers.base import BaseWorker

logging.config.dictConfig(get_config('logging'))


class WorkersManager(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'workers_manager'
        self._workers: List[BaseWorker] = []

        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

        self.redis.delete('enabled_workers')

        for module_name, w_config in workers().items():
            self._workers += self._init_worker(module_name, w_config)

        for worker in self._workers:
            self.logger.info(f'starting worker {worker.name}...')
            worker.start()

    def _get_worker_class(self, module) -> Type[BaseWorker]:
        for class_name, worker in inspect.getmembers(module, inspect.isclass):
            if class_name == 'BaseWorker':
                continue
            if issubclass(worker, BaseWorker):
                return worker
        raise MissingWorker(f'The worker class is missing in {module}')

    def _init_worker(self, module_name: str, worker_conf: Dict[str, Dict[str, str]], restart: bool=False) -> List[BaseWorker]:
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
        options = {
            key: value for key, value in worker_conf['settings'].items()
            if key not in ('cache', 'timeout')
        }

        # [re]Create workers
        if restart:
            replicas = 1
        workers_list = []
        for i in range(1, replicas + 1):
            try:
                worker = self._get_worker_class(module)(
                    module=module_name, worker_id=i,
                    cache=worker_conf['settings']['cache'],
                    timeout=worker_conf['settings']['timeout'],
                    loglevel=self.loglevel,
                    **options
                )
                if i == 1 and not worker.disabled:
                    self.redis.sadd('enabled_workers', worker.module)

            except TypeError as e:
                key = str(e).rsplit(': ', maxsplit=1)[-1]
                raise ConfigError(f"missing mandatory key {key} for worker in config") from e
            else:
                workers_list.append(worker)
        return workers_list

    def _manager(self):
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

    def _to_run_forever(self):
        self._manager()


def main():
    wm = WorkersManager()
    wm.run(sleep_in_sec=60)


if __name__ == '__main__':
    main()
