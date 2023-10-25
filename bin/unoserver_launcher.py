#!/usr/bin/env python3

import importlib
import logging
import logging.config
import shutil
import sys
import tempfile

from pathlib import Path
from typing import Optional

from pandora.default import AbstractManager, get_config

logging.config.dictConfig(get_config('logging'))


class UnoserverLauncher(AbstractManager):

    def __init__(self, loglevel: Optional[int]=None):
        super().__init__(loglevel)
        self.script_name = 'unoserver'
        # Initialize the server, doesn't start it.
        sys.path.append('/usr/lib/python3/dist-packages')
        module = importlib.import_module('unoserver.server')
        sys.path.pop()

        self.unoserver = module.UnoServer()
        self.tmpuserdir = tempfile.mkdtemp()
        self.unoserver.user_installation = Path(self.tmpuserdir).as_uri()
        self.process = self.unoserver.start()

    def _wait_to_finish(self):
        self.unoserver.stop()
        shutil.rmtree(self.tmpuserdir, ignore_errors=True)


def main():
    u = UnoserverLauncher()
    u.run(sleep_in_sec=5)


if __name__ == '__main__':
    main()
