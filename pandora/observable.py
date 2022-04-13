import hashlib
import logging

from datetime import datetime
import json
from typing import Optional, overload, List

# NOTE: remove .api on next package release.
from pymispwarninglists.api import WarningList

from .helpers import get_warninglists
from .storage_client import Storage


class Observable:

    @classmethod
    def new_observable(cls, value: str, observable_type: str, seen: Optional[datetime]=None):
        if not seen:
            seen = datetime.now()
        # NOTE: observable_type must be a valid MISP Type, we need to check that.
        sha256 = hashlib.sha256(value.encode()).hexdigest()
        # Check if it already exists, update if needed
        stored_observable = Storage().get_observable(sha256, observable_type)
        if stored_observable:
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
                 first_seen: str, last_seen: str, warninglists: Optional[str]=None):
        '''From redis'''
        ...

    @overload
    def __init__(self, sha256: str, value: str, observable_type: str,
                 first_seen: datetime, last_seen: datetime, warninglists: Optional[List[WarningList]]=None):
        '''From python'''
        ...

    def __init__(self, sha256, value, observable_type, first_seen, last_seen, warninglists=None, warninglist=None):
        self.storage = Storage()
        self.logger = logging.getLogger(f'{self.__class__.__name__}')

        self.sha256 = sha256
        self.value = value
        self.observable_type = observable_type

        if isinstance(first_seen, str):
            self.first_seen = datetime.fromisoformat(first_seen)
        else:
            self.first_seen = first_seen

        if isinstance(last_seen, str):
            self.last_seen = datetime.fromisoformat(last_seen)
        else:
            self.last_seen = last_seen

        self.warninglists: List[WarningList] = []
        if warninglists:
            if isinstance(warninglists, str):
                for wl in json.loads(warninglists):
                    if get_warninglists().get(wl):
                        self.warninglists.append(get_warninglists()[wl])
                    else:
                        self.logger.warning(f'Unable to find warning list {wl}')
            else:
                self.warninglists = warninglists

    def __lt__(self, obj):
        if self.observable_type < obj.observable_type:
            return True
        elif self.observable_type == obj.observable_type:
            return self.value < obj.value

    def check_warninglists(self):
        self.warninglists = get_warninglists().search(self.value)

    @property
    def to_dict(self):
        return {
            'sha256': self.sha256,
            'value': self.value,
            'observable_type': self.observable_type,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'warninglists': json.dumps([wl.name for wl in self.warninglists])
        }

    def store(self):
        self.storage.set_observable(self.to_dict)
