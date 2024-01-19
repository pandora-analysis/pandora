from __future__ import annotations

import json

from typing import Any, overload

from .default import PandoraException
from .helpers import Status


def default_json(obj: Any) -> Any:
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, bytes):
        return str(obj)
    raise TypeError(f'Object of type {obj.__class__.__name__} is not JSON serializable')


class Report:
    def __init__(self, task_uuid: str, worker_name: str, status: str | None= None,
                 details: str | None=None, extras: str | None=None,):
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
        self._details: dict[str, dict[str, Any] | set[str] | str] = {}
        if details:
            for k, v in json.loads(details).items():
                self._details[k] = json.loads(v)
                if isinstance(self._details[k], list):
                    self._details[k] = set(self._details[k])
        self._extras: dict[str, Any] = {}
        if extras:
            self._extras = json.loads(extras)

    @property
    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in {
            'task_uuid': self.task_uuid,
            'worker_name': self.worker_name,
            'status': self.status.name,
            'cache': getattr(self, 'cache', None),
            'start_date': getattr(self, 'start_date', None),
            'end_date': getattr(self, 'end_date', None),
            'error': getattr(self, 'error', None),
            'error_trace': getattr(self, 'error_trace', None),
            'details': json.dumps({key: json.dumps(value, default=default_json) for key, value in self.details.items()}) if self.details else None,
            'extras': json.dumps(self.extras) if self.extras else None,
        }.items() if v is not None}

    @property
    def status(self) -> Status:
        return self._status

    @status.setter
    def status(self, status: Status) -> None:
        self._status = max(self._status, status)

    @property
    def is_done(self) -> bool:
        return self._status not in (Status.WAITING, Status.RUNNING)

    @property
    def details(self) -> dict[str, dict[str, Any] | list[str] | str]:
        to_return: dict[str, dict[str, Any] | list[str] | str] = {}
        for k, v in self._details.items():
            if isinstance(v, set):
                to_return[k] = list(v)
            else:
                to_return[k] = v
        return to_return

    @property
    def extras(self) -> dict[str, Any]:
        return self._extras

    def add_extra(self, key: str, value: Any) -> None:
        self._extras[key] = value

    @overload
    def add_details(self, details_name: str, details: str) -> None:
        ...

    @overload
    def add_details(self, details_name: str, details: list[str] | set[str]) -> None:
        ...

    @overload
    def add_details(self, details_name: str, details: dict[str, Any]) -> None:
        ...

    def add_details(self, details_name: str, details: str | list[str] | set[str] | dict[str, Any]) -> None:
        if isinstance(details, list):
            details = set(details)

        if details_name not in self._details:
            # just add the details, call it a day
            self._details[details_name] = details
        else:
            # can only add dict to dict. If the current details are a str, we can make it a set
            if isinstance(self._details[details_name], dict):
                if isinstance(details, dict):
                    self._details[details_name].update(details)  # type: ignore[union-attr]
                else:
                    raise PandoraException('The details exist and are a dict, impossible to add anything else than another dict')
            elif isinstance(self._details[details_name], set):
                if isinstance(details, dict):
                    raise PandoraException('The details exist and are a set, impossible to add dict.')
                if isinstance(details, str):
                    details = {details, }
                self._details[details_name] |= details  # type: ignore[operator]
            elif isinstance(self._details[details_name], str) and isinstance(details, (set, str)):
                self._details[details_name] = {self._details[details_name], }  # type: ignore[arg-type]
                if isinstance(details, str):
                    self._details[details_name].add(details)  # type: ignore[union-attr]
                else:
                    self._details[details_name] |= details  # type: ignore[operator]
            else:
                raise PandoraException('Invalid type.')

    def clear_details(self) -> None:
        self._details = {}

    def clear_extras(self) -> None:
        self._extras = {}

    def reset_status(self) -> None:
        self._status = Status.WAITING
