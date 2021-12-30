#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

from pandora.default import AbstractManager


def main():
    AbstractManager.force_shutdown()
    time.sleep(5)
    while True:
        try:
            running = AbstractManager.is_running()
        except FileNotFoundError:
            print('Redis is already down.')
            break
        if not running:
            break
        print(running)
        time.sleep(5)


if __name__ == '__main__':
    main()
