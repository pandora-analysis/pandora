from datetime import datetime
from typing import Dict, Optional, Union

from .role import RoleName, Role
from .storage_client import Storage


class User:

    def __init__(self, session_id: str, *, last_ip: str, name: Optional[str]=None,
                 first_seen: Optional[Union[str, datetime]]=None,
                 last_seen: Optional[Union[str, datetime]]=None,
                 role: Union[str, RoleName, Role]=RoleName.other):
        """
        Generate User object for flask_login.
        :param session_id: session uid
        :param name: user name
        :param first_login: date of first login
        :param last_login: date of last login
        :param last_ip: user current ip
        :param role: Role object
        """
        self.storage = Storage()

        self.session_id = session_id
        self.name = name
        self.last_ip = last_ip
        if not first_seen:
            self.first_seen: datetime = datetime.now()
            self.last_seen: datetime = datetime.now()
        else:
            if isinstance(first_seen, str):
                self.first_seen = datetime.fromisoformat(first_seen)
            else:
                self.first_seen = first_seen

            if not last_seen:
                self.last_seen = datetime.now()
            elif isinstance(last_seen, str):
                self.last_seen = datetime.fromisoformat(last_seen)
            else:
                self.last_seen = last_seen

        if isinstance(role, Role):
            self.role = role
        else:
            if isinstance(role, RoleName):
                stored_role = self.storage.get_role(role.name)
            else:
                stored_role = self.storage.get_role(role)
            self.role = Role(**stored_role)

    def get_id(self) -> str:
        return self.session_id

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_active(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    @property
    def is_admin(self) -> bool:
        return self.role.name == RoleName.admin

    @property
    def to_dict(self) -> Dict[str, str]:
        return {k: v for k, v in {'session_id': self.session_id, 'name': self.name,
                                  'first_seen': self.first_seen.isoformat(),
                                  'last_seen': self.last_seen.isoformat(),
                                  'role': self.role.name.name if self.role else RoleName.other.name,
                                  'last_ip': self.last_ip}.items()
                if v
                }

    @property
    def store(self):
        self.storage.set_user(self.to_dict)

    def __repr__(self):
        return f'User(name={self.name}, session_id={self.session_id}, role={self.role.name})'
