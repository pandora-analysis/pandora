from __future__ import annotations

from datetime import datetime, timezone

from .role import RoleName, Role
from .storage_client import Storage


class User:

    def __init__(self, session_id: str, *, last_ip: str, name: str | None=None,
                 detailed_view: bool | int | str=False,
                 first_seen: str | datetime | None=None,
                 last_seen: str | datetime | None=None,
                 role: str | RoleName | Role=RoleName.other):
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
        if isinstance(detailed_view, str):
            detailed_view = int(detailed_view)
        self._detailed_view: bool = bool(detailed_view)
        self.last_ip = last_ip
        if not first_seen:
            self.first_seen: datetime = datetime.now(timezone.utc)
            self.last_seen: datetime = datetime.now(timezone.utc)
        else:
            if isinstance(first_seen, str):
                self.first_seen = datetime.fromisoformat(first_seen)
            else:
                self.first_seen = first_seen

            if not last_seen:
                self.last_seen = datetime.now(timezone.utc)
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

    def toggle_detailed_view(self) -> None:
        self._detailed_view = not self._detailed_view

    @property
    def detailed_view(self) -> bool:
        return self._detailed_view

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
    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in {'session_id': self.session_id, 'name': self.name,
                                  'first_seen': self.first_seen.isoformat(),
                                  'last_seen': self.last_seen.isoformat(),
                                  'detailed_view': str(int(self.detailed_view)),
                                  'role': self.role.name.name if self.role else RoleName.other.name,
                                  'last_ip': self.last_ip}.items()
                if v is not None
                }

    def store(self) -> None:
        self.storage.set_user(self.to_dict)

    def __repr__(self) -> str:
        return f'User(name={self.name}, session_id={self.session_id}, role={self.role.name})'
