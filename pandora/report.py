import json

from typing import Optional, Dict, Any

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
            self.status = Status[status]
        else:
            self.status = Status.WAITING
        if details:
            for k, v in json.loads(details).items():
                setattr(self, k, json.loads(v))

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
    def is_done(self):
        return self.status not in (Status.WAITING, Status.RUNNING)

    def display_attr(self, attr):
        """
        Used to display report attr in html.
        :param (str) attr: attr to display
        :return: value to display
        """
        value = getattr(self, attr, None)
        if value is None:
            return None
        if isinstance(value, bytes):
            value = json.loads(value.decode())
            if isinstance(value, (list, set)):
                return '\n'.join(value)
            elif isinstance(value, dict):
                return '\n'.join([f'{k}: {v}' for k, v in value.items()])
            else:
                return value
        return value

    @property
    def duration(self):
        """
        Return duration of analysis if start_date and end_date are known.
        :return (int|None): Total duration in seconds or None
        """

    @property
    def details(self) -> Dict[str, str]:
        excluded_keys = (
            'worker_name', 'task_uuid', 'cache', 'status', 'start_date', 'end_date', 'error', 'error_trace', 'web_name'
        )
        return {key: value for key, value in self.__dict__.items() if not key.startswith('_') and key not in excluded_keys}

    def add_details(self, details_name: str, details: Any):
        if isinstance(details, set):
            details = list(details)
        setattr(self, details_name, details)

    def __str__(self):
        return ', '.join([
            f'{key}={value}'
            for key, value in self.__dict__.items()
            if not key.startswith('_') and key not in ('worker_name', 'task_uuid')
        ])
