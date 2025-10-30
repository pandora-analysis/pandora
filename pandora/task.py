from __future__ import annotations

import json
import logging

from collections.abc import MutableMapping
from datetime import datetime, timedelta, timezone
from io import BytesIO
from logging import LoggerAdapter
from typing import overload, Any, Literal
from uuid import uuid4

from pymisp import MISPEvent, MISPAttribute
from redis import Redis
from werkzeug.utils import secure_filename

from .default import get_homedir, safe_create_dir, PandoraException, get_config, get_socket_path
from .exceptions import TooManyObservables, Unsupported
from .file import File
from .helpers import Status, workers, Seed
from .observable import Observable
from .report import Report
from .storage_client import Storage
from .user import User


class PandoraTaskLogAdapter(LoggerAdapter):  # type: ignore[type-arg]
    """
    Prepend log entry with the UUID
    """
    def process(self, msg: str, kwargs: MutableMapping[str, Any]) -> tuple[str, MutableMapping[str, Any]]:
        if self.extra:
            return '[{}] {}'.format(self.extra['uuid'], msg), kwargs
        return msg, kwargs


class Task:

    _file: File
    _user: User
    _parent: Task | None

    @classmethod
    def new_task(cls, user: User, sample: BytesIO, filename: str, disabled_workers: list[str],
                 parent: Task | None=None, password: str | None=None) -> Task:
        task_uuid = str(uuid4())
        today = datetime.now(timezone.utc)
        directory = get_homedir() / 'tasks' / str(today.year) / f'{today.month:02}' / task_uuid
        safe_create_dir(directory)
        filepath = directory / secure_filename(filename)
        with filepath.open('wb') as _f:
            _f.write(sample.getvalue())
        file = File.new_file(filepath, filename=filename)

        task = cls(uuid=task_uuid, submitted_file=file, disabled_workers=disabled_workers,
                   user=user, parent=parent, password=password)
        task.store(force=True)
        return task

    @overload
    def __init__(self, *, uuid: str, submitted_file: File,
                 user: User,
                 parent: Task | None=None,
                 status: Status | None=None,
                 done: bool=False,
                 disabled_workers: list[str] | None=None,
                 password: str | None=None) -> None:
        '''With python classes'''
        ...

    @overload
    def __init__(self, *, uuid: str, file_id: str, user_id: str, save_date: str,
                 parent_id: str | None=None,
                 status: str | None=None,
                 done: bool=False,
                 disabled_workers: str | None=None,
                 password: str | None=None) -> None:
        '''From redis'''
        ...

    def __init__(self, *, uuid: str,
                 submitted_file: File | None=None, file_id: str | None=None,
                 user: User | None=None, user_id: str | None=None, save_date: str | None=None,
                 parent: Task | None=None, parent_id: str | None=None,
                 status: Status | str | None=None, done: bool=False,
                 disabled_workers: list[str] | str | None=None,
                 password: str | None=None) -> None:
        """
        Generate a Task object.
        :param uuid: Unique identifier of the task.
        :param file: File object
        :param user: User object
        :param save_date: task save date
        :param parent: parent task if file has been extracted
        """
        logger = logging.getLogger(f'{self.__class__.__name__}')
        logger.setLevel(get_config('generic', 'loglevel'))
        self.storage = Storage()
        # This redis is there just to make sure we only wait for workers that are currently enabled
        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

        if uuid:
            # Loading existing task
            self.uuid = uuid
        else:
            # New task
            self.uuid = str(uuid4())
            logger.info(f'[{self.uuid}] New task')
        self.logger = PandoraTaskLogAdapter(logger, {'uuid': self.uuid})

        if submitted_file is None and file_id is None:
            raise Unsupported('submitted_file or file_id is required')

        if submitted_file:
            self.file = submitted_file
            self.save_date = self.file.save_date
        elif file_id:
            self._file_id = file_id
            self.save_date = self.file.save_date
        elif save_date:
            self.save_date = datetime.fromisoformat(save_date)

        if user:
            self.user = user
        elif user_id:
            self._user_id = user_id

        if parent:
            self.parent = parent
        elif parent_id:
            self._parent_id = parent_id

        if isinstance(status, Status):
            self._status = status
        elif isinstance(status, str):
            self._status = Status[status]
        else:
            self._status = Status.WAITING
        self.done = done
        self.linked_tasks = None
        if disabled_workers:
            if isinstance(disabled_workers, str):
                self.disabled_workers = json.loads(disabled_workers)
            else:
                self.disabled_workers = disabled_workers
        else:
            self.disabled_workers = []
        if password:
            self.password = password
        else:
            self.password = ''  # nosec B105
        self.store()
        self.seed_manager = Seed()

    @property
    def user(self) -> User | None:
        if hasattr(self, '_user'):
            return self._user
        if hasattr(self, '_user_id'):
            if (u := self.storage.get_user(self._user_id)):
                self._user = User(**u)
                return self._user
        return None

    @user.setter
    def user(self, u: User) -> None:
        self._user = u

    @property
    def file(self) -> File:
        if hasattr(self, '_file'):
            return self._file
        if hasattr(self, '_file_id'):
            if (f := self.storage.get_file(self._file_id)):
                self._file = File(**f)
                return self._file
        raise PandoraException('missing file')

    @file.setter
    def file(self, f: File) -> None:
        self._file = f

    @property
    def parent(self) -> Task | None:
        if hasattr(self, '_parent'):
            return self._parent
        if hasattr(self, '_parent_id'):
            if (parent_task := self.storage.get_task(self._parent_id)):
                self._parent = Task(**parent_task)  # type: ignore
                return self._parent
        return None

    @parent.setter
    def parent(self, parent: Task) -> None:
        self._parent = parent

    @property
    def extracted(self) -> list[Task]:
        to_return = []
        for t_uuid in self.storage.get_extracted_references(self.uuid):
            extract = self.storage.get_task(t_uuid)
            if not extract:
                continue
            to_return.append(Task(**extract))  # type: ignore
        return to_return

    @property
    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in {
            'uuid': self.uuid,
            'parent_id': self.parent.uuid if self.parent else None,
            'file_id': self.file.uuid,
            'user_id': self.user.get_id() if self.user else None,
            'disabled_workers': json.dumps(self.disabled_workers) if hasattr(self, 'disabled_workers') else None,
            'password': self.password if self.password else None,
            'status': self.status.name,
            'save_date': self.save_date.isoformat()
        }.items() if v is not None}

    def store(self, force: bool=False) -> None:
        if force or (self.workers_done and self.status not in [Status.WAITING, Status.RUNNING]):
            self.storage.set_task(self.to_dict)

    @property
    def reports(self) -> dict[str, Report]:
        to_return: dict[str, Report] = {}
        enabled_workers = self.redis.smembers('enabled_workers')
        for worker_name in workers():
            if worker_name in self.disabled_workers or worker_name not in enabled_workers:
                continue
            stored_report = self.storage.get_report(task_uuid=self.uuid, worker_name=worker_name)
            if stored_report:
                report = Report(**stored_report)
            else:
                report = Report(self.uuid, worker_name)
            to_return[worker_name] = report
        return to_return

    @property
    def workers_done(self) -> bool:
        if self.save_date <= datetime.now(timezone.utc) - timedelta(hours=1):
            # NOTE Failsafe. If the task was started more than 1h ago, it is
            # either done, or it failed.
            return True
        for _, report in self.reports.items():
            if not report.is_done:
                return False
        return True

    @property
    def workers_status(self) -> dict[str, tuple[bool, str]]:
        to_return: dict[str, tuple[bool, str]] = {}
        for report_name, report in self.reports.items():
            to_return[report_name] = (report.is_done, report.status.name)
        return to_return

    @property
    def status(self) -> Status:
        if self.file.deleted:
            self._status = Status.DELETED

        if self._status in [Status.DELETED, Status.ERROR, Status.ALERT, Status.WARN, Status.CLEAN]:
            # If the status was set to any of these values, the reports finished
            return self._status

        if self.workers_done:
            self._status = max(self._status, Status.CLEAN)
            # All the workers are done, return success/error
            for _, report in self.reports.items():
                # Status code order: ALERT - WARN - CLEAN - ERROR
                # NOTE: when a report is Status.DISABLED or Status.NOTAPPLICABLE,
                #       it has no impact on the general status of the task
                if report.status in [Status.DISABLED, Status.NOTAPPLICABLE]:
                    continue
                self._status = max(self._status, report.status)
        else:
            # At least one worker isn't done yet
            self._status = Status.WAITING

        if self._status in [Status.WAITING, Status.RUNNING] and self.save_date <= datetime.now(timezone.utc) - timedelta(hours=1):
            # NOTE Failsafe. If the task was started more than 1h ago, it is
            # either done, or it failed.
            self._status = Status.ERROR

        return self._status

    @status.setter
    def status(self, _status: Status) -> None:
        self._status = _status

    def add_observable(self, value: str, observable_type: str, seen: datetime | None=None) -> None:
        if not seen:
            seen = datetime.now(timezone.utc)
        observable = Observable.new_observable(value, observable_type, seen)
        self.storage.add_task_observable(self.uuid, observable.sha256, observable.observable_type)

    def init_observables_from_file(self) -> None:
        nb_observables = 0
        for observable_type, values in self.file.observables.items():
            for value in values:
                self.add_observable(value, observable_type, self.file.save_date)
                nb_observables += 1
                if nb_observables > 1000:
                    raise TooManyObservables('This file has more than 1000 observables.')

    @property
    def observables(self) -> list[Observable]:
        observables = [Observable(**observable) for observable in self.storage.get_task_observables(self.uuid)]
        observables.sort()
        return observables

    def __str__(self) -> str:
        return f'<uuid: {self.uuid} - file: {self.file}>'

    @overload
    def misp_export(self, with_extracted_tasks: Literal[True]) -> list[MISPEvent]:
        ...

    @overload
    def misp_export(self, with_extracted_tasks: Literal[False]) -> MISPEvent:
        ...

    @overload
    def misp_export(self, with_extracted_tasks: bool) -> MISPEvent | list[MISPEvent]:
        ...

    def misp_export(self, with_extracted_tasks: bool) -> MISPEvent | list[MISPEvent]:
        public_url = get_config('generic', 'public_url')
        event = MISPEvent()
        event.info = f'Pandora analysis ({self.file.original_filename})'
        seed, _ = self.seed_manager.add(self.uuid, None)
        pandora_link: MISPAttribute = event.add_attribute('link', f'{public_url}/analysis/{self.uuid}/seed-{seed}')  # type: ignore
        pandora_link.distribution = 0
        internal_ref: MISPAttribute = event.add_attribute('comment', self.uuid, category="Internal reference")  # type: ignore
        internal_ref.distribution = 0
        # Delegate population to file class as the objects will depend on the filetype.
        self.file.populate_misp_event(event)
        for observable in self.observables:
            event.add_attribute(observable.observable_type, observable.value, to_ids=False)
        if not with_extracted_tasks:
            return event
        to_return = [event]
        for extracted in self.extracted:
            e_events = extracted.misp_export(with_extracted_tasks)
            for e_event in e_events:
                e_event.extends_uuid = event.uuid
                to_return.append(e_event)
        return to_return
