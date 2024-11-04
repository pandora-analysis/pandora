#!/usr/bin/env python3

from subprocess import Popen, run

from pandora.default import get_homedir


def main() -> None:
    # Just fail if the env isn't set.
    get_homedir()
    print('Start backend (redis)...')
    p = run(['run_backend', '--start'])
    try:
        p.check_returncode()
    except Exception:
        print('Failed to start the backend, exiting.')
        return
    print('done.')
    print('Start unoserver...')
    Popen(['unoserver_launcher'])
    print('done.')
    print('Start workers...')
    Popen(['workers_manager'])
    print('done.')
    print('Start IMAP fetcher...')
    Popen(['imap_fetcher'])
    print('done.')
    print('Start background processing...')
    Popen(['background_processing'])
    print('done.')
    print('Start website...')
    Popen(['start_website'])
    print('done.')


if __name__ == '__main__':
    main()
