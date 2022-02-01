from typing import Dict, Any, Optional, Union, List, overload

from .file import File
from .user import User
from .helpers import Status
from .observable import TaskObservable, Observable
from .report import Report
from .storage_client import Storage

# TODO: replace rid (redis stream ID) by a UUID.


class Task:

    @overload
    def __init__(self, rid: Optional[str]=None, submitted_file: Optional[File]=None,
                 user=None, user_id=None, save_date=None, reports=None,
                 parent=None, origin=None, status: Optional[Union[str, Status]]=None,
                 done=False, seed=None,
                 disabled_workers=[]):
        ...

    @overload
    def __init__(self, rid: Optional[str]=None, file_id: Optional[str]=None,
                 user=None, user_id=None, save_date=None, reports=None,
                 parent=None, origin=None, status: Optional[Union[str, Status]]=None,
                 done=False, seed=None,
                 disabled_workers=[]):
        ...

    def __init__(self, rid=None, submitted_file=None, file_id=None,
                 user=None, user_id=None, save_date=None, reports=None,
                 parent=None, origin=None, status=None,
                 done=False, seed=None,
                 disabled_workers=[]):
        """
        Generate a Task object.
        :param rid: redis id - returned by xadd, this is the stream ID
        :param file: File object
        :param user: User object
        :param save_date: task save date
        :param reports: dict in this way {module name => report object}
        :param parent: parent task if file has been extracted
        :param origin: origin task if file has been extracted (can be parent or grand-parent, ...)
        :param seed: random string to share analysis page
        """
        self.storage = Storage()

        self.rid = rid

        assert submitted_file is not None or file_id is not None, 'submitted_file or file_id is required'

        if submitted_file:
            self.file = submitted_file
            self.file_id = self.file.uuid
            self.save_date = self.file.save_date
        elif file_id:
            self.file_id = file_id
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
        self.observables: List[Observable] = []
        self.reports = reports or dict()
        self.parent = parent
        self.origin = origin
        if isinstance(status, Status):
            self.status = status
        elif isinstance(status, str):
            self.status = Status[status]
        else:
            self.status = Status.WAITING
        self.done = done
        self.seed = seed
        self.linked_tasks = None
        self.extracted_tasks = None
        self.disabled_workers = disabled_workers

        # NOTE: this may need to be moved somewhere else
        if self.file.deleted:
            self.status = Status.DELETED

    @property
    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in {
            'rid': self.rid,
            'seed': self.seed,
            'parent_id': self.parent.rid if self.parent else None,
            'origin_id': self.origin.rid if self.origin else None,
            'file_id': self.file.uuid if self.file else None,
            'user_id': self.user.get_id(),
            'status': self.status.name,
            'save_date': self.save_date.isoformat()
        }.items() if v is not None}

    @property
    def store(self):
        self.storage.set_task(self.to_dict)

    def get_report(self, worker):
        """
        Get report for given module.
        :param (BaseWorker) worker: object inherited from BaseWorker class
        :return (Report): report corresponding
        """
        return self.reports.get(worker.module)

    def set_report(self, worker, status, **kwargs):
        """
        Set report for given module and status.
        :param (BaseWorker) worker: object inherited from BaseWorker class
        :param (str) status: status
        :param (mapping) kwargs: arguments to set in report
        :return (Report): corresponding Report object
        """
        report = Report(self, worker=worker, status=status, **kwargs)
        self.reports[worker.module] = report
        return report

    def set_report_disable(self, worker, **kwargs):
        """
        Set report with status DEACTIVATE.
        :param (BaseWorker) worker: object inherited from BaseWorker class
        :param kwargs: arguments to set in report
        """
        return self.set_report(worker=worker, status=Status.DEACTIVATE, **kwargs)

    def set_report_running(self, worker, **kwargs):
        """
        Set report with status RUNNING.
        :param (BaseWorker) worker: object inherited from BaseWorker class
        :param kwargs: arguments to set in report
        """
        return self.set_report(worker=worker, status=Status.RUNNING, **kwargs)

    def set_report_okay(self, worker, **kwargs):
        """
        Set report with status OKAY.
        :param (BaseWorker) worker: object inherited from BaseWorker class
        :param kwargs: arguments to set in report
        """
        return self.set_report(worker=worker, status=Status.OKAY, **kwargs)

    def set_report_warn(self, worker, **kwargs):
        """
        Set report with status WARN.
        :param (BaseWorker) worker: object inherited from BaseWorker class
        :param kwargs: arguments to set in report
        """
        self.set_report(worker=worker, status=Status.WARN, **kwargs)

    def set_report_alert(self, worker, **kwargs):
        """
        Set report with status WARN.
        :param (BaseWorker) worker: object inherited from BaseWorker class
        :param kwargs: arguments to set in report
        """
        return self.set_report(worker=worker, status=Status.ALERT, **kwargs)

    def set_report_error(self, worker, **kwargs):
        """
        Set report with status ERROR.
        :param (BaseWorker) worker: object inherited from BaseWorker class
        :param kwargs: arguments to set in report
        """
        return self.set_report(worker=worker, status=Status.ERROR, **kwargs)

    def set_observables(self, links):
        """
        Add observables to current task.
        :param (list) links: list of strings
        """
        self.observables = TaskObservable.get_observables(links)

    def __str__(self):
        return f'<rid: {self.rid} - file: {self.file}>'
