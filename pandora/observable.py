import hashlib

from datetime import datetime
from typing import Optional, overload

from .storage_client import Storage


class Observable:

    @classmethod
    def new_observable(cls, value: str, observable_type: str, seen: Optional[datetime]=None):
        if not seen:
            seen = datetime.now()
        # NOTE: observable_type must be a valid MISP Type, we need to check that.
        sha256 = hashlib.sha256(value.encode()).hexdigest()
        first_seen = seen
        last_seen = seen
        observable = cls(sha256, value, observable_type, first_seen, last_seen)
        observable.store()
        return observable

    @overload
    def __init__(self, sha256: str, value: str, observable_type: str,
                 first_seen: str, last_seen: str, warninglist: Optional[str]=None):
        '''From redis'''
        ...

    @overload
    def __init__(self, sha256: str, value: str, observable_type: str,
                 first_seen: datetime, last_seen: datetime, warninglist: Optional[str]=None):
        '''From python'''
        ...

    def __init__(self, sha256, value, observable_type, first_seen, last_seen, warninglist=None):
        self.storage = Storage()

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

        if warninglist:
            self.warninglist = warninglist
        else:
            # in case warninglist == ''
            self.warninglist = None

    @property
    def to_dict(self):
        return {
            'sha256': self.sha256,
            'value': self.value,
            'observable_type': self.observable_type,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'warninglist': self.warninglist if self.warninglist else ''
        }

    def store(self):
        self.storage.set_observable(self.to_dict)
