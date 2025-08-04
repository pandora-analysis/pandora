from __future__ import annotations

import hashlib
import json
import logging
import re

from datetime import datetime, timezone
from functools import cached_property
from typing import overload, Any

# NOTE: remove .api on next package release.
from pymispwarninglists.api import WarningList

from .default import get_config
from .helpers import get_warninglists, Status
from .storage_client import Storage

always_suspicious_observables: dict[str, list[str]] = {
    'url': ['^file://']
}


class Observable:

    all_warninglists = get_warninglists()

    @classmethod
    def new_observable(cls, value: str, observable_type: str, seen: datetime | None=None) -> Observable:
        if not seen:
            seen = datetime.now(timezone.utc)
        # NOTE: observable_type must be a valid MISP Type, we need to check that.
        sha256 = hashlib.sha256(value.encode()).hexdigest()
        # Check if it already exists, update if needed
        stored_observable = Storage().get_observable(sha256, observable_type)
        if stored_observable:
            if (wl := stored_observable.pop('warninglist', None)):
                if not stored_observable.get('warninglists'):
                    # Old format, was ignored.
                    stored_observable['warninglists'] = json.dumps([wl])  # pylint: disable=E1137
            observable = cls(**stored_observable)
            changed = False
            if seen < observable.first_seen:
                observable.first_seen = seen
                changed = True
            elif seen > observable.last_seen:
                observable.last_seen = seen
                changed = True
            if changed:
                observable.check_warninglists()
                observable.store()
        else:
            first_seen = seen
            last_seen = seen
            observable = cls(sha256, value, observable_type, first_seen, last_seen)
            observable.check_warninglists()
            observable.store()
        return observable

    @overload
    def __init__(self, sha256: str, value: str, observable_type: str,
                 first_seen: str, last_seen: str, warninglists: str | None=None):
        '''From redis'''
        ...

    @overload
    def __init__(self, sha256: str, value: str, observable_type: str,
                 first_seen: datetime, last_seen: datetime, warninglists: list[WarningList] | None=None):
        '''From python'''
        ...

    def __init__(self, sha256: str, value: str, observable_type: str,
                 first_seen: str | datetime, last_seen: str | datetime,
                 warninglists: str | list[WarningList] | None=None,
                 warninglist: str | None=None):
        self.storage = Storage()
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))

        self.sha256 = sha256
        self.value = value
        self.observable_type = observable_type

        if isinstance(first_seen, str):
            self.first_seen = datetime.fromisoformat(first_seen)
            self.first_seen = self.first_seen.astimezone(timezone.utc)
        else:
            self.first_seen = first_seen

        if isinstance(last_seen, str):
            self.last_seen = datetime.fromisoformat(last_seen)
            self.last_seen = self.first_seen.astimezone(timezone.utc)
        else:
            self.last_seen = last_seen

        if warninglist and not warninglists:
            # cleaning up old data
            warninglists = json.dumps([warninglist])

        self.warninglists: list[WarningList] = []
        if warninglists:
            if isinstance(warninglists, str):
                for wl in json.loads(warninglists):
                    if wl := self.all_warninglists.get(wl):
                        self.warninglists.append(wl)
                    else:
                        self.logger.warning(f'Unable to find warning list {wl}')
            elif isinstance(warninglists, list):
                self.warninglists = warninglists

    def __lt__(self, obj: Observable) -> bool:
        if self.observable_type < obj.observable_type:
            return True
        if self.observable_type == obj.observable_type:
            return self.value < obj.value
        return False

    def check_warninglists(self) -> None:
        self.warninglists = self.all_warninglists.search(self.value)

    @cached_property
    def status(self) -> Status:
        if suspicious := always_suspicious_observables.get(self.observable_type):
            if re.match('|'.join(suspicious), self.value.strip()):
                return Status.WARN
        if suspicious_observables := self.storage.get_suspicious_observables():
            if self.value.strip() in suspicious_observables:
                return Status.ALERT
        if legitimate_observbles := self.storage.get_legitimate_observables():
            if self.value.strip() in legitimate_observbles:
                return Status.CLEAN
        return Status.NOTAPPLICABLE

    @property
    def to_dict(self) -> dict[str, Any]:
        return {
            'sha256': self.sha256,
            'value': self.value,
            'observable_type': self.observable_type,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'warninglists': json.dumps([wl.name for wl in self.warninglists])
        }

    def store(self) -> None:
        self.storage.set_observable(self.to_dict)
