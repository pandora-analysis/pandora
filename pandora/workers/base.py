from __future__ import annotations

import contextlib
import json
import logging
import multiprocessing
import signal
import time
import traceback

from logging import LoggerAdapter
from typing import MutableMapping, Any, Iterator

from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection
from redis.exceptions import ResponseError, ConnectionError as RedisConnectionError

from ..default import get_socket_path, get_config, PandoraException
from ..helpers import expire_in_sec, Status
from ..report import Report
from ..storage_client import Storage
from ..task import Task


class WorkerLogAdapter(LoggerAdapter):  # type: ignore[type-arg]
    """
    Prepend log entry with the UUID of the task
    """
    def process(self, msg: str, kwargs: MutableMapping[str, Any]) -> tuple[str, MutableMapping[str, Any]]:
        if self.extra:
            return '[{}] {}'.format(self.extra['uuid'], msg), kwargs
        return msg, kwargs


class BaseWorker(multiprocessing.Process):

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int | None=None,
                 status_in_report: dict[str, str] | None=None,
                 **options: Any) -> None:
        """
        Create a worker.
        :param module: module of the worker
        :param worker_id: The ID of the worker (for replicats)
        :param cache: cache time for module
        :param timeout: timeout for module
        """
        super().__init__(name=f'{module}-{worker_id}', daemon=True)
        self.loglevel: int = loglevel if loglevel is not None else get_config('generic', 'loglevel') or logging.INFO
        self.logger = logging.getLogger(module)
        self.logger.setLevel(self.loglevel)
        self.logger.info(f'Initializing {self.name}')

        self.redis_pool_cache: ConnectionPool = ConnectionPool(
            connection_class=UnixDomainSocketConnection,
            path=get_socket_path('cache'), decode_responses=True)

        self.module = module
        self.logger.debug('Create redis stream group...')
        self.disabled = options.pop('disabled', False)
        if self.disabled:
            self.logger.info(f'{module} is disabled in the config file.')
        else:
            try:
                self.redis.xgroup_create(name='tasks_queue', groupname=self.module, mkstream=True)
                self.logger.debug('Redis stream group created.')
            except ResponseError:
                self.logger.debug('Redis stream group already exists.')
            except RedisConnectionError:
                self.logger.critical('Redis not started, shutting down.')
                self.disabled = True
            except Exception as e:
                self.logger.critical(f'Unexpected error, shutting down: {e}.')
                self.disabled = True
            finally:
                if self.disabled:
                    self.logger.critical(f'General error, unable to initialize the workers for {module}.')
                    raise PandoraException(f'General error, unable to initialize the workers for {module}.')

        self.storage = Storage()

        self.cache = expire_in_sec(cache)
        self.timeout = expire_in_sec(timeout)

        self.status_in_report = status_in_report if status_in_report else {}

        self.required = options.pop('required', False)
        self.run_by_default = options.pop('run_by_default', True)

        for key, value in options.items():
            setattr(self, key, value)

    @property
    def redis(self) -> Redis:  # type: ignore[type-arg]
        return Redis(connection_pool=self.redis_pool_cache)

    @staticmethod
    def _raise_timeout(_, __) -> None:  # type: ignore[no-untyped-def]
        raise TimeoutError

    @contextlib.contextmanager
    def _timeout_context(self, logger: WorkerLogAdapter) -> Iterator[None]:
        start = time.time()
        if self.timeout != 0:
            # Register a function to raise a TimeoutError on the signal.
            signal.signal(signal.SIGALRM, self._raise_timeout)
            signal.alarm(self.timeout)
            try:
                yield
            except TimeoutError as e:
                raise e
            finally:
                signal.signal(signal.SIGALRM, signal.SIG_IGN)
        else:
            yield
        end = time.time()
        logger.info(f'Runtime: {end - start:.2f}s')

    def set_report_status(self, report: Report, detection_id: str, status: Status) -> None:
        """
        Set the status of the report.
        :param report: The report object to update
        :param detection_id: The detection ID that can be overwritten in the workers config
        :param status: The default status level from the worker
        """
        report = Report(detection_id, self.module)
        report.status = status
        self.storage.set_report(report.to_dict)

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        """
        Analyse task and save results in task object.
        This method has to be overwritten in a subclass.
        :param task: Task being provcessed
        :param report: Report for the current module.
        """
        # TODO:
        # 1. (optional, if relevant in context) check if we already have a relevant result (ex.: the query to the 3rd party service was already done recently)
        #   => if found, return Result
        # 2. Process the task on the module
        # 3. Store result (good or bad), update task object in redis with results
        #    update cache if relevant. Do not store cache on error
        raise NotImplementedError('Stuff this module is doing with this task')

    def _read_stream(self) -> tuple[str, list[str], str | None]:
        while True:
            new_stream = self.redis.xreadgroup(
                groupname=self.module, consumername=self.name, streams={'tasks_queue': '>'},
                count=1, block=2000
            )
            if new_stream:
                break
            time.sleep(1)
        _, entries = new_stream[0]
        _, values = entries[0]
        return (values['task_uuid'],
                json.loads(values['disabled_workers']) if values.get('disabled_workers') else [],
                values.get('manual_worker'))

    def run(self) -> None:
        """
        Run current worker and execute tasks from queue.
        """
        if self.disabled:
            self.logger.info(f'{self.module} is disabled')
            return

        self.logger.info('Worker is running...')

        while True:
            try:
                self.logger.debug('Waiting for new task...')
                task_uuid, disabled_workers, manual_worker = self._read_stream()
                logger = WorkerLogAdapter(self.logger, {'uuid': task_uuid})
                logger.debug('Got new task')

                if self.module in disabled_workers:
                    logger.debug('Disabled for this task.')
                    continue

                task_data = self.storage.get_task(task_uuid)
                # FIXME: remove that type ignore.
                task = Task(**task_data)  # type: ignore

                # From this point, the worker is generating the report
                report = Report(task.uuid, self.module)
                report.status_indicators = self.status_in_report

                try:
                    if self.disabled:
                        report.status = Status.DISABLED
                        # NOTE: continue still runs the finally block
                        continue

                    report.status = Status.RUNNING
                    # Store report to make status available to UI
                    self.storage.set_report(report.to_dict)

                    with self._timeout_context(logger):
                        self.analyse(task, report, self.module == manual_worker)
                except TimeoutError:
                    e = f'timeout on analyse call after {self.timeout}s'
                    logger.warning(e)
                    report.status = Status.ERROR
                except Exception as e:
                    # TODO: bubble up the error to the user (if safe, may want to do that on a module by module basis)
                    err = f'{repr(e)}\n{traceback.format_exc()}'
                    logger.error(f'unknown error during analysis : {err}')
                    report.status = Status.ERROR
                else:
                    if report.status == Status.RUNNING:
                        # Only change to success if the analysis didn't change it.
                        report.status = Status.CLEAN
                finally:
                    self.storage.set_report(report.to_dict)
                    logger.debug('Done with task.')

            except PandoraException as e:
                self.logger.critical(f'Error with current task : {e}')
            except ConnectionError:
                self.logger.critical('Redis is gone, shutting down.')
            except FileNotFoundError as e:
                self.logger.critical(f'unable to reach redis socket, shutting down : {e}')
            except Exception as e:
                self.logger.critical(f'unknown error with current task : {repr(e)}\n{traceback.format_exc()}')
