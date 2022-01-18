import json

from .helpers import Status


class Report:
    def __init__(self, task, worker, **kwargs):
        """
        Generate module report.
        :param (Task) task: object Task
        :param (BaseWorker) worker: object inherited from BaseWorker class
        :param kwargs: arguments to set in this report
        """
        self.task = task
        self.worker = worker
        self.status = Status.WAITING
        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def to_dict(self):
        return {
            'status': self.status,
            'duration': self.duration,
            'is_done': self.is_done,
            'cache': getattr(self, 'cache', None),
            'start_date': getattr(self, 'start_date', None),
            'end_date': getattr(self, 'end_date', None),
            'error': getattr(self, 'error', None),
            'error_trace': getattr(self, 'error_trace', None),
            'details': {key: self.display_attr(key) for key in self.details},
        }

    @property
    def is_done(self):
        return self.status not in (Status.WAITING, Status.RUNNING)

    @staticmethod
    def get_model(models, name):
        """
        Find model in list with given name.
        :param (list) models: list of Model objects
        :param (str) name: name of Model to search
        :return (Model): Model object
        """
        for model in models:
            if model.name == name:
                return model

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
            if isinstance(value, list):
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
        start = getattr(self, 'start_date', None)
        end = getattr(self, 'end_date', None)
        if start and end:
            return 1 + int((end - start).total_seconds())

    @property
    def db_keys(self):
        excluded_keys = ('worker', 'task', 'web_name')
        return [key for key in self.__dict__ if not key.startswith('_') and key not in excluded_keys]

    @property
    def details(self):
        excluded_keys = (
            'worker', 'task', 'cache', 'status', 'start_date', 'end_date', 'error', 'error_trace', 'web_name'
        )
        return [key for key in self.__dict__ if not key.startswith('_') and key not in excluded_keys]

    def __str__(self):
        return ', '.join([
            f'{key}={value}'
            for key, value in self.__dict__.items()
            if not key.startswith('_') and key not in ('worker', 'task')
        ])
