#!/usr/bin/env python

from __future__ import annotations

import logging
import logging.config

from datetime import datetime, timedelta

from pymisp import PyMISP, MISPAttribute, MISPEvent

from pandora.default import AbstractManager, get_config
from pandora.helpers import Status
from pandora.pandora import Pandora
from pandora.user import User

logging.config.dictConfig(get_config('logging'))


class BackgroundProcessing(AbstractManager):

    def __init__(self, loglevel: int | None=None) -> None:
        super().__init__(loglevel)
        self.script_name = 'background_processing'
        self.pandora = Pandora()

        self.public_url = get_config('generic', 'public_url')

        # Prepare MISP post processing, if configured.
        misp_settings = get_config('generic', 'misp')
        if 'autosubmit' in misp_settings and misp_settings['autosubmit'].get('enabled'):
            self.misp_autosubmit_status = Status[misp_settings['autosubmit']['status']]
            self.misp = PyMISP(misp_settings['url'], misp_settings['apikey'], ssl=misp_settings['tls_verify'])
            self.misp_autosubmit = True
            self.misp_autopublish = misp_settings['autosubmit'].get('autopublish')
        else:
            self.misp_autosubmit = False

    def _to_run_forever(self) -> None:
        # Run processing after a task is done
        self.postprocessing()

    def _task_on_misp(self, internal_ref: str) -> bool:
        attributes = self.misp.search('attributes', value=internal_ref, limit=1, page=1, pythonify=True)
        if not attributes or not isinstance(attributes, list) or not isinstance(attributes[0], MISPAttribute):
            return False
        return True

    def postprocessing(self) -> None:
        # Only try to run postprocessing on tasks from the last 24h
        cut_date = datetime.now() - timedelta(hours=24)
        u = User('admin', last_ip='127.0.0.1', role='admin')
        for task in self.pandora.get_tasks(u, first_date=cut_date):
            # if MISP autosubmit enabled & task status is ALERT & task not already submitted => submit
            if (self.misp_autosubmit
                    and task.status >= self.misp_autosubmit_status
                    and not self._task_on_misp(task.uuid)):
                event = task.misp_export()
                new_event = self.misp.add_event(event, pythonify=True)
                if isinstance(new_event, MISPEvent) and self.misp_autopublish:
                    self.misp.publish(new_event)


def main() -> None:
    bp = BackgroundProcessing()
    bp.run(sleep_in_sec=10)


if __name__ == '__main__':
    main()
