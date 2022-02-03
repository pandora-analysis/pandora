#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from subprocess import Popen

from pandora.default import AbstractManager
from pandora.default import get_homedir

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO)


class UnoserverLauncher(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'unoserver'
        self.process = self._launch_unoserver()
        self.set_running()

    def _launch_unoserver(self):
        return Popen(['unoserver'], cwd=get_homedir())


def main():
    u = UnoserverLauncher()
    u.run(sleep_in_sec=10)


if __name__ == '__main__':
    main()
