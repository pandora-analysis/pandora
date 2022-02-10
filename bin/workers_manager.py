#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import importlib
import logging

from typing import List, Dict, Union

from pandora.default import AbstractManager
from pandora.helpers import workers
from pandora.workers.base import BaseWorker

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO)


class WorkersManager(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'workers_manager'
        self._workers: List[BaseWorker] = []
        self._check_config()

        for w_config in workers().values():
            self._workers += self._init_worker(w_config)

        for worker in self._workers:
            self.logger.info(f'starting worker {worker.name}...')
            worker.start()

    def _check_config(self):
        """
        Read and check config.yml file.
        """
        for worker in workers().values():
            assert worker.get('module'), 'expected key worker.module not found or empty in config.yml'
            assert worker.get('class'), 'expected key worker.class not found or empty in config.yml'
            assert 'cache' in worker, 'expected key worker.cache not found in config.yml'
            assert 'timeout' in worker, 'expected key worker.timeout not found in config.yml'
            assert isinstance(worker['replicas'], int), 'key worker.replicas has to be an integer in config.yml'

    def _init_worker(self, worker_conf: Dict[str, Union[str, int]], restart: bool=False) -> List[BaseWorker]:
        """
        Create a new worker with given conf.
        :param worker_conf: dict extracted from yaml
        :param replicas: number of workers to create (by default replicas is taken from worker_conf)
        :param start_index: starting index for worker names
        :return: list of BaseWorker objects
        """
        # Check replicas value
        replicas = int(worker_conf['replicas'])
        if replicas < 1:
            return []

        # Import module
        module = importlib.import_module(f'pandora.workers.{worker_conf["module"]}')
        options = {
            key: value for key, value in worker_conf.items()
            if key not in ('module', 'class', 'cache', 'timeout', 'replicas', 'web_name')
        }

        # [re]Create workers
        if restart:
            replicas = 1
        workers = []
        for i in range(1, replicas + 1):
            worker_name = f'{worker_conf["module"]}-{i}'
            try:
                worker = getattr(module, str(worker_conf['class']))(
                    module=worker_conf['module'], name=worker_name,
                    cache=worker_conf['cache'],
                    timeout=worker_conf['timeout'], **options
                )
            except TypeError as e:
                key = str(e).split(': ')[-1]
                raise AssertionError(f"missing mandatory key {key} for worker in config")
            else:
                workers.append(worker)
        return workers

    def _manager(self):
        """
        Restart eventual dead workers.
        """
        for worker in self._workers:
            if worker.is_alive():
                continue
            self.logger.info(f'restart dead worker {worker.name}')
            self._workers.remove(worker)
            # Restart module worker
            module_name, index = worker.name.split('-')
            new_worker = self._init_worker(worker_conf=workers()[module_name], restart=True)[0]
            self._workers.append(new_worker)
            new_worker.start()

    def _to_run_forever(self):
        self._manager()


def main():
    wm = WorkersManager()
    wm.run(sleep_in_sec=60)


if __name__ == '__main__':
    main()
