import json

from typing import Optional, Dict, Union, List, Set, Any, overload

from .helpers import Status


class Report:
    def __init__(self, task_uuid: str, worker_name: str, status: Optional[str]= None,
                 details: Optional[str]=None):
        """
        Generate module report.
        :param kwargs: arguments to set in this report
        """
        self.task_uuid = task_uuid
        self.worker_name = worker_name
        if status:
            self._status = Status[status]
        else:
            self._status = Status.WAITING
        self._details: Dict[str, Union[Dict[str, Any], Set[str], str]] = {}
        if details:
            for k, v in json.loads(details).items():
                self._details[k] = json.loads(v)
                if isinstance(self._details[k], list):
                    self._details[k] = set(self._details[k])

    @property
    def to_dict(self):
        return {k: v for k, v in {
            'task_uuid': self.task_uuid,
            'worker_name': self.worker_name,
            'status': self.status.name,
            'duration': self.duration,
            'cache': getattr(self, 'cache', None),
            'start_date': getattr(self, 'start_date', None),
            'end_date': getattr(self, 'end_date', None),
            'error': getattr(self, 'error', None),
            'error_trace': getattr(self, 'error_trace', None),
            'details': json.dumps({key: json.dumps(value) for key, value in self.details.items()}) if self.details else None,
        }.items() if v is not None}

    @property
    def status(self) -> Status:
        return self._status

    @status.setter
    def status(self, status: Status):
        if self._status < status:
            self._status = status

    @property
    def is_done(self):
        return self._status not in (Status.WAITING, Status.RUNNING)

    @property
    def duration(self):
        """
        Return duration of analysis if start_date and end_date are known.
        :return (int|None): Total duration in seconds or None
        """

    @property
    def details(self) -> Dict[str, Union[Dict[str, Any], List[str], str]]:
        to_return: Dict[str, Union[Dict[str, Any], List[str], str]] = {}
        for k, v in self._details.items():
            if isinstance(v, set):
                to_return[k] = list(v)
            else:
                to_return[k] = v
        return to_return

    @overload
    def add_details(self, details_name: str, details: str):
        ...

    @overload
    def add_details(self, details_name: str, details: Union[List[str], Set[str]]):
        ...

    @overload
    def add_details(self, details_name: str, details: Dict[str, Any]):
        ...

    def add_details(self, details_name, details):
        if isinstance(details, list):
            details = set(details)

        if details_name not in self._details:
            # just add the details, call it a day
            self._details[details_name] = details
        else:
            if isinstance(self._details[details_name], str):
                if isinstance(details, dict):
                    raise Exception('Unable to concatenate a str with a dict')
                self._details[details_name] = {self._details[details_name], }
            if isinstance(details, str):
                details = {details, }
            self._details[details_name] |= details
