#!/usr/bin/env python3

import logging

from datetime import datetime, timedelta

from unoserver.server import UnoServer  # type: ignore

from pandora.default import AbstractManager

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO)


class UnoserverLauncher(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'unoserver'

    def _launch_unoserver(self):
        unoserver = UnoServer()
        return unoserver.start(), datetime.now()

    def safe_run(self):
        # it sometimes fails but simply restarting the server fixes it
        self.process, start_time = self._launch_unoserver()
        self.set_running()
        retry = 0
        while True:
            self.run(sleep_in_sec=10)
            if self.shutdown_requested():
                break
            if retry >= 3:
                self.logger.critical(f'Unable to restart {self.script_name}.')
                break
            if datetime.now() - start_time > timedelta(seconds=60):
                retry = 0
            else:
                retry += 1
            self.process, start_time = self._launch_unoserver()
            self.set_running()


def main():
    u = UnoserverLauncher()
    u.safe_run()


if __name__ == '__main__':
    main()
