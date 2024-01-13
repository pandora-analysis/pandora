#!/usr/bin/env python3

from subprocess import Popen, run

from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from pandora.default import get_homedir, get_socket_path


def main() -> None:
    get_homedir()
    with Popen(['shutdown']) as p:
        p.wait()
    try:
        r = Redis(unix_socket_path=get_socket_path('cache'), db=1)
        r.delete('shutdown')
        print('Shutting down databases...')
        p_backend = run(['run_backend', '--stop'])
        p_backend.check_returncode()
        print('done.')
    except RedisConnectionError:
        # Already down, skip the stacktrace
        pass


if __name__ == '__main__':
    main()
