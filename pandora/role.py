import json

from enum import Enum, unique, auto
from typing import Union, List, Dict, cast

from .storage_client import Storage


@unique
class RoleName(Enum):
    admin = auto()
    owner = auto()
    reader = auto()
    other = auto()


@unique
class Action(Enum):
    submit_file = auto()
    read_analysis = auto()
    download_images = auto()
    download_pdf = auto()
    download_text = auto()
    see_text_preview = auto()
    download_zip = auto()
    refresh_analysis = auto()
    rescan_file = auto()
    notify_cert = auto()
    share_analysis = auto()
    delete_file = auto()
    list_own_tasks = auto()
    list_all_tasks = auto()
    search_file_name = auto()
    search_file_hash = auto()
    list_observables = auto()
    update_observable = auto()
    insert_observable = auto()
    list_users = auto()
    list_roles = auto()
    update_role = auto()
    list_stats = auto()


class Role:

    def __init__(self, name: str, description: str, actions: Union[Dict[str, bool], str]):
        assert name in RoleName.__members__.keys(), f"unexpected role name '{name}'"
        self.storage = Storage()
        self.name = RoleName[name]
        self.description = description
        if isinstance(actions, str):
            actions = cast(Dict[str, bool], json.loads(actions))
        self.actions: Dict[Action, bool] = {}
        for action_name, perm in actions.items():
            assert action_name in Action.__members__.keys(), f"unexpected action name '{action_name}'"
            self.actions[Action[action_name]] = perm

    @property
    def to_dict(self) -> Dict[str, str]:
        to_return = {'name': str(self.name.name), 'description': self.description}
        to_return['actions'] = json.dumps({action.name: perm for action, perm in self.actions.items()})
        return to_return

    @property
    def store(self) -> None:
        self.storage.set_role(self.to_dict)

    def set_action(self, action: Union[str, Action], value: bool):
        """
        Add boolean action for role.
        :param (str) action: model name
        :param (bool) value: model value
        """
        if isinstance(action, str):
            assert action in Action.__members__.keys(), f"unexpected action name '{action}'"
            action = Action[action]
        self.actions[action] = value

    def can(self, actions: Union[str, List[str], Action, List[Action]], operator: str='and') -> bool:
        """
        Property that returns True if role can do an action
        :param actions: action or list of actions
        :param operator: and/or operator
        :return: whether if the role is allowed to do the action
        """
        assert operator in ('and', 'or'), f"unexpected operator '{operator}'"
        if isinstance(actions, str):
            actions = Action[actions]
        if isinstance(actions, list):
            if operator == 'and':
                return all([self.can(action) for action in actions])
            else:
                return any([self.can(action) for action in actions])
        if actions in self.actions:
            return self.actions[actions]
        else:
            return False

    @property
    def is_admin(self) -> bool:
        """
        Property to know if if is admin role
        :return (bool):
        """
        return self.name == RoleName.admin

    def __repr__(self):
        return str(self.to_dict)
