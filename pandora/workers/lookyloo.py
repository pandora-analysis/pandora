#!/usr/bin/env python3

import logging

from pylookyloo import Lookyloo

from ..helpers import Status, get_useragent_for_requests
from ..task import Task
from ..report import Report

from .base import BaseWorker


class LookylooWorker(BaseWorker):

    apiurl: str
    autosubmit: bool

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int=logging.INFO, **options):
        super().__init__(module, worker_id, cache, timeout, loglevel, **options)
        self.client = Lookyloo(self.apiurl, get_useragent_for_requests())
        if not self.client.is_up:
            self.disabled = True
            self.logger.warning(f'Unable to connect to the Lookyloo instance: {self.apiurl}.')
            return

    def analyse(self, task: Task, report: Report):
        if not task.file.data:
            report.status = Status.NOTAPPLICABLE
            return
        if not task.file.is_html:
            report.status = Status.NOTAPPLICABLE
            return
        if not self.autosubmit:
            report.status = Status.MANUAL
            return

        lookyloo_report = self.client.enqueue(document=task.file.data, document_name=task.file.path.name)
        report.status = Status.UNKNOWN
        report.add_details('permaurl', lookyloo_report)
