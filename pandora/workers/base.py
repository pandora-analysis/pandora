import contextlib
import json
import logging
import multiprocessing
import signal
import traceback

from typing import Tuple, List

from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection
from redis.exceptions import ResponseError

from ..default import get_socket_path
from ..helpers import expire_in_sec, Status
from ..report import Report
from ..storage_client import Storage
from ..task import Task


class BaseWorker(multiprocessing.Process):

    def __init__(self, module: str, name: str, cache: str, timeout: str,
                 loglevel: int=logging.DEBUG, **options):
        """
        Create a worker.
        :param module: module of the worker
        :param name: name of the worker
        :param cache: cache time for module
        :param timeout: timeout for module
        """
        super().__init__(name=name, daemon=True)
        self.loglevel = loglevel
        self.logger = logging.getLogger(f'{name}')
        self.logger.setLevel(loglevel)
        self.logger.info(f'Initializing {name}')

        self.redis_pool_cache: ConnectionPool = ConnectionPool(
            connection_class=UnixDomainSocketConnection,
            path=get_socket_path('cache'), decode_responses=True)

        self.module = module
        self.logger.debug('Create redis stream group...')
        try:
            self.redis.xgroup_create(name='tasks_queue', groupname=self.module, mkstream=True)
            self.logger.debug('Redis stream group created.')
        except ResponseError:
            self.logger.debug('Redis stream group already exists.')

        self.storage = Storage()

        self.cache = expire_in_sec(cache)
        self.timeout = expire_in_sec(timeout)

    @property
    def redis(self):
        return Redis(connection_pool=self.redis_pool_cache)

    @staticmethod
    def _raise_timeout(_, __):
        raise TimeoutError

    @contextlib.contextmanager
    def _timeout_context(self):
        if self.timeout is not None:
            # Register a function to raise a TimeoutError on the signal.
            signal.signal(signal.SIGALRM, self._raise_timeout)
            signal.alarm(self.timeout)
            try:
                yield
            except TimeoutError:
                raise
            finally:
                signal.signal(signal.SIGALRM, signal.SIG_IGN)
        else:
            yield

    def analyse(self, task: Task, report: Report) -> None:
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

    def _read_stream(self) -> Tuple[str, List[str]]:
        _, entries = self.redis.xreadgroup(
            groupname=self.module, consumername=self.name, streams={'tasks_queue': '>'},
            block=0, count=1
        )[0]
        rid, values = entries[0]
        return values['task_uuid'], json.loads(values['disabled_workers'])

    def run(self):
        """
        Run current worker and execute tasks from queue.
        """
        self.logger.info('Worker is running...')

        while True:
            try:
                self.logger.debug('Waiting for new task...')
                task_uuid, disabled_workers = self._read_stream()
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
                    report.status = Status.RUNNING
                    self.storage.set_report(report.to_dict)
                    with self._timeout_context():
                        self.analyse(task, report)
                except TimeoutError:
                    e = f'timeout on analyse call after {self.timeout}s'
                    self.logger.error(e)
                    report.status = Status.ERROR
                except Exception as e:
                    err = f'{repr(e)}\n{traceback.format_exc()}'
                    self.logger.error(f'unknown error during analysis : {err}')
                    report.status = Status.ERROR
                else:
                    # NOTE: we probably need to enter that bloc even if there is an exception
                    #       otherwise the app will never know the worker failed and keep retrying
                    if report.status == Status.RUNNING:
                        # Only change to success if the analyis didn't change it.
                        report.status = Status.OKAY
                    self.storage.set_report(report.to_dict)
                    self.logger.debug(f'Done with task {task_uuid}.')

            except AssertionError as e:
                self.logger.critical(f'assertion error with current task : {e}')
            except BaseException as e:
                self.logger.critical(f'unknown error with current task : {repr(e)}\n{traceback.format_exc()}')
