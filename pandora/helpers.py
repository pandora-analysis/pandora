#!/usr/bin/env python3

from __future__ import annotations

import logging
import re
import secrets

from datetime import timedelta
from enum import IntEnum, Enum, unique, auto
from functools import lru_cache
from importlib.metadata import version
from typing import Any

from publicsuffix2 import PublicSuffixList, fetch  # type: ignore[import-untyped]
from pymispwarninglists import WarningLists  # type: ignore[attr-defined]
from redis import Redis
import yaml

from .default import get_homedir, get_socket_path
from .exceptions import Unsupported, ConfigError
from .role import Role

logger = logging.getLogger('Helpers')


# NOTE: Status code order for the UI: ALERT -> WARN -> CLEAN
#       the keys in the enum must stay in this order
@unique
class Status(IntEnum):
    WAITING = auto()  # Worker not started yet
    RUNNING = auto()  # Worker started
    DELETED = auto()  # Sample deleted
    NOTAPPLICABLE = auto()  # Worker not applicable for this sample
    MANUAL = auto()  # Worker needs to be run manually
    UNKNOWN = auto()  # Worker cannot decide
    DEACTIVATE = auto()  # Deprecated
    DISABLED = auto()  # Worker disabled
    ERROR = auto()  # Worker failed
    OKAY = auto()  # Deprecated, needs to be deleted
    CLEAN = auto()  # Sample marked as clean by worker
    WARN = auto()  # Sample suspicious
    ALERT = auto()  # Sample malicious
    OVERWRITE = auto()  # This one is used on a case-by-case basis, and it will force a report to that status


@unique
class TypeObservable(Enum):
    DOMAIN = auto()
    IPV4 = auto()
    IPV6 = auto()
    EMAIL = auto()
    IBAN = auto()


@lru_cache(64)
def email_blocklist() -> list[str]:
    _path = get_homedir() / 'config' / 'email_blocklist.yml'
    if _path.exists():
        with _path.open() as config_file:
            config = yaml.safe_load(config_file.read())
        return config['blocklist']
    return []


@lru_cache(64)
def allowlist_default() -> list[str]:
    with (get_homedir() / 'config' / 'allowlist.yml').open() as config_file:
        config = yaml.safe_load(config_file.read())
    return config['allowlist']


@lru_cache(64)
def roles_from_config() -> dict[str, Role]:
    with (get_homedir() / 'config' / 'roles.yml').open() as config_file:
        config = yaml.safe_load(config_file.read())
    to_return = {}
    for r in config['roles']:
        actions = {key[4:]: value for key, value in r.items() if key.startswith('can_')}
        role = Role(name=r['name'], description=r['description'], actions=actions)
        to_return[r['name']] = role
    return to_return


@lru_cache(64)
def workers() -> dict[str, dict[str, Any]]:
    workers_dir = get_homedir() / 'pandora' / 'workers'
    # Sample config file
    worker_sample_default_config_file = workers_dir / 'base.yml.sample'
    with worker_sample_default_config_file.open() as f:
        default_sample_config = yaml.safe_load(f.read())

    worker_default_config_file = workers_dir / 'base.yml'
    if worker_default_config_file.exists():
        # load default parameters
        with worker_default_config_file.open() as f:
            default_config = yaml.safe_load(f.read())
    else:
        logger.warning(f'Workers config file ({worker_default_config_file}) does not exists, falling back to default.')

    all_configs = {}
    # load all individual config files
    for configfile in workers_dir.glob('*.yml'):
        if configfile.name == 'base.yml':
            continue

        module_file = workers_dir / f'{configfile.stem}.py'
        sample_config_file = workers_dir / f'{configfile}.sample'

        if not module_file.exists() and not sample_config_file.exists():
            # If we miss a .py  *and* a .yml.sample file, it means the module has been removed and we can just skip it.
            logger.warning(f'The module {configfile.stem} has been removed. Remove {configfile} to get rid of this warning.')
            continue
        if not module_file.exists():
            # we have a sample config file but no module, this is bad
            raise ConfigError(f'No worker available for {configfile}, you need to remove the yml file, or add a .py modulefile.')
        if not sample_config_file.exists():
            # we have a module but no sample config file, this is also bad
            raise ConfigError(f'No sample config file available for {configfile}, unable to load default config. Did you rename the yml.sample file instead of copying it? Please restore it.')

        with configfile.open() as f:
            module_config = yaml.safe_load(f.read())

        # get the default config from the sample file, as a fallback
        with sample_config_file.open() as f:
            module_config_sample = yaml.safe_load(f.read())

        all_configs[configfile.stem] = {
            'meta': {**default_sample_config['meta'], **default_config['meta'],
                     **module_config_sample['meta'], **module_config['meta']},
            'settings': {**default_sample_config['settings'], **default_config['settings']},
            'status_in_report': {}
        }

        if 'settings' in module_config_sample:
            all_configs[configfile.stem]['settings'].update(module_config_sample['settings'])
        if 'settings' in module_config:
            all_configs[configfile.stem]['settings'].update(module_config['settings'])

        if 'status_in_report' in module_config_sample:
            all_configs[configfile.stem]['status_in_report'].update(module_config_sample['status_in_report'])
        if 'status_in_report' in module_config:
            all_configs[configfile.stem]['status_in_report'].update(module_config['status_in_report'])

    return {name: all_configs[name] for name in sorted(all_configs)}


def make_bool(value: bool | int | str | None) -> bool:
    if value in [True, 1, '1']:
        return True
    return False


def make_bool_for_redis(value: bool | None) -> int:
    if value is True:
        return 1
    return 0


def expire_in_sec(time: str | int | None) -> int:
    """
    Try to parse time value and return the amount of seconds.
    :param time: time value to parse
    :return: seconds until expire
    """
    if not time:
        return 0
    t_match = re.fullmatch(r'(\d+)([smhd]?)', str(time))
    if t_match is None:
        raise Unsupported(f"impossible to parse cache '{time}'")
    if not t_match.group(2) or t_match.group(2) == 's':
        return int(timedelta(seconds=int(t_match.group(1))).total_seconds())
    if t_match.group(2) == 'm':
        return int(timedelta(minutes=int(t_match.group(1))).total_seconds())
    if t_match.group(2) == 'h':
        return int(timedelta(hours=int(t_match.group(1))).total_seconds())
    if t_match.group(2) == 'd':
        return int(timedelta(days=int(t_match.group(1))).total_seconds())
    return 0


@lru_cache(64)
def get_public_suffix_list() -> PublicSuffixList:
    # Initialize Public Suffix List
    try:
        psl_file = fetch()
        psl = PublicSuffixList(psl_file=psl_file)
    except Exception as e:
        logging.getLogger(__name__).warning(f'Unable to fetch the PublicSuffixList: {e}')
        psl = PublicSuffixList()
    return psl


@lru_cache(64)
def get_warninglists() -> WarningLists:
    return WarningLists(slow_search=False)


@lru_cache(64)
def get_disclaimers() -> dict[str, str]:
    disclaimer_path = get_homedir() / 'config' / 'disclaimer.tmpl'
    if not disclaimer_path.exists():
        disclaimer_path = get_homedir() / 'config' / 'disclaimer.tmpl.sample'
    special_disclaimer_path = get_homedir() / 'config' / 'special_disclaimer.tmpl'
    to_return = {'disclaimer': '', 'special_disclaimer': ''}
    with disclaimer_path.open() as f:
        to_return['disclaimer'] = f.read()
    if special_disclaimer_path.exists():
        with special_disclaimer_path.open() as f:
            to_return['special_disclaimer'] = f.read()
    return to_return


@lru_cache(64)
def get_email_template() -> str:
    with (get_homedir() / 'config' / 'email.tmpl').open() as f:
        return f.read()


@lru_cache(64)
def get_useragent_for_requests() -> str:
    return f'Pandora / {version("pandora")}'


class Seed():

    def __init__(self) -> None:
        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

    def get_task_uuid(self, seed: str) -> str | None:
        return self.redis.get(f'seed:{seed}')

    def add(self, task_uuid: str, time: str | int | None=None, seed: str | None=None) -> tuple[str, int]:
        expire = expire_in_sec(time)
        if not seed:
            seed = secrets.token_urlsafe()
        if expire:
            self.redis.setex(name=f'seed:{seed}', time=expire, value=task_uuid)
        else:
            # When seed is False (0, None)
            self.redis.set(name=f'seed:{seed}', value=task_uuid)
        return seed, expire
