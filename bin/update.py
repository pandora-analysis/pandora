#!/usr/bin/env python3

import argparse
import hashlib
import logging
import platform
import shlex
import shutil
import subprocess
import sys

from pathlib import Path

from pandora.default import get_homedir, get_config

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO)


def compute_hash_self():
    m = hashlib.sha256()
    with (get_homedir() / 'bin' / 'update.py').open('rb') as f:
        m.update(f.read())
        return m.digest()


def keep_going(ignore: bool=False):
    if ignore:
        return
    keep_going = input('Continue? (y/N) ')
    if keep_going.lower() != 'y':
        print('Okay, quitting.')
        sys.exit()


def run_command(command, expect_fail: bool=False, capture_output: bool=True):
    args = shlex.split(command)
    homedir = get_homedir()
    process = subprocess.run(args, cwd=homedir, capture_output=capture_output)
    if capture_output:
        print(process.stdout.decode())
    if process.returncode and not expect_fail:
        print(process.stderr.decode())
        sys.exit()


def check_poetry_version():
    args = shlex.split("poetry self -V")
    homedir = get_homedir()
    process = subprocess.run(args, cwd=homedir, capture_output=True)
    poetry_version_str = process.stdout.decode()
    version = poetry_version_str.split()[2]
    version_details = tuple(int(i) for i in version.split('.'))
    if version_details < (1, 1, 0):
        print('The project requires poetry >= 1.1.0, please update.')
        print('If you installed with "pip install --user poetry", run "pip install --user -U poetry"')
        print('If you installed via the recommended method, use "poetry self update"')
        print('More details: https://github.com/python-poetry/poetry#updating-poetry')
        sys.exit()


def check_unconfigured_workers(default_yes: bool=False):
    workers_dir = get_homedir() / 'pandora' / 'workers'
    for sample_config in workers_dir.glob('*.yml.sample'):
        if (workers_dir / sample_config.stem).exists():
            continue
        # The yml file is missing.
        print(f'\nNew worker available ({sample_config.stem}), but the config file is missing.')
        if default_yes:
            shutil.copy(sample_config, workers_dir / sample_config.stem)
            print(f'{sample_config.stem} enabled.')
            continue
        print('Do you want to configure it? If not, it will not be enabled.')
        keep_going = input('Continue? (y/N) ')
        if keep_going.lower() != 'y':
            print('Skipping.')
            continue
        print('Sample config:')
        with sample_config.open() as f:
            print('----------')
            print(f.read())
            print('----------')
        print('Do you want to use it?')
        keep_going = input('Continue? (y/N) ')
        if keep_going.lower() != 'y':
            print('Skipping.')
            continue
        shutil.copy(sample_config, workers_dir / sample_config.stem)
        print(f'{sample_config.stem} enabled.\n')


def main():
    parser = argparse.ArgumentParser(description='Pull latest release, update dependencies, update and validate the config files, update 3rd deps for the website.')
    parser.add_argument('--yes', default=False, action='store_true', help='Run all commands without asking.')
    args = parser.parse_args()

    old_hash = compute_hash_self()

    print('* Update repository.')
    keep_going(args.yes)
    run_command('git submodule init')
    run_command('git pull --recurse-submodules')
    new_hash = compute_hash_self()
    if old_hash != new_hash:
        print('Update script changed, please do "poetry run update"')
        sys.exit()

    check_poetry_version()

    print('* Install/update dependencies.')
    keep_going(args.yes)
    run_command('poetry install')

    print('* Validate configuration files.')
    keep_going(args.yes)
    run_command(f'poetry run {(Path("tools") / "validate_config_files.py").as_posix()} --check')

    print('* Update configuration files.')
    keep_going(args.yes)
    run_command(f'poetry run {(Path("tools") / "validate_config_files.py").as_posix()} --update')

    print('* Check if new workers are available')
    keep_going(args.yes)
    check_unconfigured_workers(args.yes)

    print('* Update third party dependencies for the website.')
    keep_going(args.yes)
    run_command(f'poetry run {(Path("tools") / "3rdparty.py").as_posix()}')

    print('* Restarting')
    keep_going(args.yes)
    if platform.system() == 'Windows':
        print('Restarting with poetry...')
        run_command('poetry run stop', expect_fail=True)
        run_command('poetry run start', capture_output=False)
        print('Started.')
    else:
        service = get_config('generic', 'systemd_service_name')
        p = subprocess.run(["systemctl", "is-active", "--quiet", service])
        try:
            p.check_returncode()
            print('Restarting with systemd...')
            run_command(f'sudo service {service} restart')
            print('done.')
        except subprocess.CalledProcessError:
            print('Restarting with poetry...')
            run_command('poetry run stop', expect_fail=True)
            run_command('poetry run start', capture_output=False)
            print('Started.')


if __name__ == '__main__':
    main()
