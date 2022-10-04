import contextlib
import json
import logging
import multiprocessing
import signal
import traceback

from typing import Tuple, List, Optional

from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection
from redis.exceptions import ResponseError, ConnectionError

from ..default import get_socket_path
from ..exceptions import PandoraException
from ..helpers import expire_in_sec, Status
from ..report import Report
from ..storage_client import Storage
from ..task import Task


class BaseWorker(multiprocessing.Process):

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int=logging.INFO, **options):
        """
        Create a worker.
        :param module: module of the worker
        :param worker_id: The ID of the worker (for replicats)
        :param cache: cache time for module
        :param timeout: timeout for module
        """
        super().__init__(name=f'{module}-{worker_id}', daemon=True)
        self.loglevel = loglevel
        self.logger = logging.getLogger(module)
        self.logger.setLevel(loglevel)
        self.logger.info(f'Initializing {self.name}')

        self.redis_pool_cache: ConnectionPool = ConnectionPool(
            connection_class=UnixDomainSocketConnection,
            path=get_socket_path('cache'), decode_responses=True)

        self.module = module
        self.logger.debug('Create redis stream group...')
        self.disabled = False
        try:
            self.redis.xgroup_create(name='tasks_queue', groupname=self.module, mkstream=True)
            self.logger.debug('Redis stream group created.')
        except ResponseError:
            self.logger.debug('Redis stream group already exists.')
        except ConnectionError:
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

        for key, value in options.items():
            setattr(self, key, value)

    @property
    def redis(self):
        return Redis(connection_pool=self.redis_pool_cache)

    @staticmethod
    def _raise_timeout(_, __):
        raise TimeoutError

    @contextlib.contextmanager
    def _timeout_context(self):
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

    def _read_stream(self) -> Tuple[str, List[str], Optional[str]]:
        _, entries = self.redis.xreadgroup(
            groupname=self.module, consumername=self.name, streams={'tasks_queue': '>'},
            block=0, count=1
        )[0]
        _, values = entries[0]
        return (values['task_uuid'],
                json.loads(values['disabled_workers']) if values.get('disabled_workers') else [],
                values.get('manual_worker'))

    def run(self):
        """
        Run current worker and execute tasks from queue.
        """
        self.logger.info('Worker is running...')

        while True:
            try:
                self.logger.debug('Waiting for new task...')
                task_uuid, disabled_workers, manual_worker = self._read_stream()
                self.logger.debug(f'Got new task {task_uuid}')

                if self.module in disabled_workers:
                    self.logger.debug(f'Disabled for this task ({task_uuid})')
                    continue

                task_data = self.storage.get_task(task_uuid)
                # FIXME: remove that type ignore.
                task = Task(**task_data)  # type: ignore

                # From this point, the worker is generating the report
                report = Report(task.uuid, self.module)

                try:
                    if self.disabled:
                        report.status = Status.DISABLED
                    else:
                        report.status = Status.RUNNING

                    if not self.disabled:
                        # Store report to make status available to UI
                        self.storage.set_report(report.to_dict)
                        with self._timeout_context():
                            self.analyse(task, report, self.module == manual_worker)
                except TimeoutError:
                    e = f'timeout on analyse call after {self.timeout}s'
                    self.logger.error(e)
                    report.status = Status.ERROR
                except Exception as e:
                    # TODO: bubble up the error to the user (if safe, may want to do that on a module by module basis)
                    err = f'{repr(e)}\n{traceback.format_exc()}'
                    self.logger.error(f'unknown error during analysis : {err}')
                    report.status = Status.ERROR
                else:
                    if report.status == Status.RUNNING:
                        # Only change to success if the analysis didn't change it.
                        report.status = Status.CLEAN
                finally:
                    self.storage.set_report(report.to_dict)
                    self.logger.debug(f'Done with task {task_uuid}.')

            except AssertionError as e:
                self.logger.critical(f'assertion error with current task : {e}')
            except ConnectionError:
                self.logger.critical('Redis is gone, shutting down.')
            except FileNotFoundError as e:
                self.logger.critical(f'unable to reach redis socket, shutting down : {e}')
            except BaseException as e:
                self.logger.critical(f'unknown error with current task : {repr(e)}\n{traceback.format_exc()}')
