import json

from datetime import datetime
from io import BytesIO
from typing import Dict, Any, Optional, List, overload, Tuple
from uuid import uuid4

from werkzeug.utils import secure_filename

from .default import get_homedir, safe_create_dir
from .file import File
from .helpers import Status, workers
from .observable import Observable
from .report import Report
from .storage_client import Storage
from .user import User


class Task:

    @classmethod
    def new_task(cls, user: User, sample: BytesIO, filename: str, disabled_workers: List[str],
                 parent: Optional['Task']=None) -> 'Task':
        task_uuid = str(uuid4())
        directory = get_homedir() / 'tasks' / task_uuid
        safe_create_dir(directory)
        filepath = directory / secure_filename(filename)
        with filepath.open('wb') as _f:
            _f.write(sample.getvalue())

        file = File.new_file(filepath, filename=filename)

        task = cls(uuid=task_uuid, submitted_file=file, disabled_workers=disabled_workers,
                   user=user, parent=parent)
        task.store()
        return task

    @overload
    def __init__(self, uuid: str, submitted_file: File,
                 user: User,
                 parent: Optional['Task']=None,
                 status: Optional[Status]=None,
                 done: bool=False,
                 disabled_workers: List[str]=[]):
        '''With python classes'''
        ...

    @overload
    def __init__(self, uuid: str, file_id: str, user_id: str, save_date: str,
                 parent_id: Optional[str]=None,
                 status: Optional[str]=None,
                 done: bool=False,
                 disabled_workers: Optional[str]=None):
        '''From redis'''
        ...

    def __init__(self, uuid,
                 submitted_file=None, file_id=None,
                 user=None, user_id=None, save_date=None,
                 parent=None, parent_id=None,
                 status=None, done=False,
                 disabled_workers=[]):
        """
        Generate a Task object.
        :param uuid: Unique identifier of the task.
        :param file: File object
        :param user: User object
        :param save_date: task save date
        :param parent: parent task if file has been extracted
        """
        self.storage = Storage()

        if uuid:
            # Loading existing task
            self.uuid = uuid
        else:
            # New task
            self.uuid = str(uuid4())

        assert submitted_file is not None or file_id is not None, 'submitted_file or file_id is required'

        if submitted_file:
            self.file = submitted_file
            self.save_date = self.file.save_date
        elif file_id:
            self.file = File(**self.storage.get_file(file_id))
            self.save_date = self.file.save_date
        else:
            self.save_date = save_date

        if user:
            self.user = user
        elif user_id:
            user = self.storage.get_user(user_id)
            if user:
                self.user = User(**user)

        if parent:
            self.parent = parent
        elif parent_id:
            parent_task = self.storage.get_task(parent_id)
            if parent_task:
                self.parent = Task(**parent_task)  # type: ignore

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

    @property
    def extracted(self) -> List['Task']:
        to_return = []
        for t_uuid in self.storage.get_extracted_references(self.uuid):
            extract = self.storage.get_task(t_uuid)
            if not extract:
                continue
            to_return.append(Task(**extract))  # type: ignore
        return to_return

    @property
    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in {
            'uuid': self.uuid,
            'parent_id': self.parent.uuid if hasattr(self, 'parent') else None,
            'file_id': self.file.uuid if hasattr(self, 'file') else None,
            'user_id': self.user.get_id() if hasattr(self, 'user') else None,
            'disabled_workers': json.dumps(self.disabled_workers) if hasattr(self, 'disabled_workers') else None,
            'status': self.status.name,
            'save_date': self.save_date.isoformat()
        }.items() if v is not None}

    def store(self):
        self.storage.set_task(self.to_dict)

    @property
    def reports(self) -> Dict[str, Report]:
        to_return: Dict[str, Report] = {}
        for worker_name in workers():
            if worker_name in self.disabled_workers:
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
        for report_name, report in self.reports.items():
            if not report.is_done:
                return False
        return True

    @property
    def workers_status(self) -> Dict[str, Tuple[bool, str]]:
        to_return: Dict[str, Tuple[bool, str]] = {}
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
            self._status = Status.CLEAN
            # All the workers are done, return success/error
            for report_name, report in self.reports.items():
                # Status code order: ALERT - WARN - CLEAN - ERROR
                # NOTE: when a report is Status.DISABLED or Status.NOTAPPLICABLE,
                #       it has no impact on the general status of the task
                if report.status in [Status.DISABLED, Status.NOTAPPLICABLE]:
                    continue
                if report.status > self._status:
                    self._status = report.status
            return self._status
        else:
            # At least one worker isn't done yet
            self._status = Status.WAITING
            return self._status

    @status.setter
    def status(self, _status: Status):
        self._status = _status

    def add_observable(self, value: str, observable_type: str, seen: Optional[datetime]=None):
        if not seen:
            seen = datetime.now()
        observable = Observable.new_observable(value, observable_type, seen)
        self.storage.add_task_observable(self.uuid, observable.sha256, observable.observable_type)

    def __init_observables_from_file(self):
        for observable_type, values in self.file.observables.items():
            for value in values:
                self.add_observable(value, observable_type, self.file.save_date)

    @property
    def observables(self) -> List[Observable]:
        # FIXME: this method is called multiple times on the analysis result, we should not add the same observables multiple times in redis
        self.__init_observables_from_file()
        observables = []
        for observable in self.storage.get_task_observables(self.uuid):
            observables.append(Observable(**observable))
        return observables

    def __str__(self):
        return f'<uuid: {self.uuid} - file: {self.file}>'
