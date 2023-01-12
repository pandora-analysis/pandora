#!/usr/bin/env python3

import logging
import sys

import asyncio
import pathlib
import urllib.parse

if sys.version_info < (3, 11):
    import irmacl_async  # type: ignore

from ..helpers import Status, expire_in_sec
from ..task import Task
from ..report import Report

from .base import BaseWorker


class Irma(BaseWorker):

    apiurl: str
    apitimeout: int

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int=logging.INFO, **options):
        super().__init__(module, worker_id, cache, timeout, loglevel, **options)
        if sys.version_info >= (3, 11):
            self.disabled = True
            self.logger.warning('Disabled, IRMA requires python <3.11.')
            return

        if not self.apiurl:
            self.disabled = True
            self.logger.warning('Disabled, missing apiurl.')
            return

        if self.apitimeout:
            self.apitimeout = expire_in_sec(self.apitimeout)

    async def _scan_task(self, task, report):
        # Set irma client config
        config = irmacl_async.apiclient.Config(api_endpoint=self.apiurl, timeout=self.apitimeout)
        async with irmacl_async.AAPI(config=config, anonymous=True) as api:
            scan = await api.scans.scan(pathlib.Path(task.file.path), linger=True, force=True)

            link = urllib.parse.urljoin(self.apiurl, f'/scans/{scan.external_id}')
            if scan.infected > 0:
                report.status = Status.ALERT
            report.add_details('Click on "Sign in anonymously" button to reach IRMA report.', link)

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False):
        if task.file.is_archive:
            report.status = Status.NOTAPPLICABLE
            return

        asyncio.run(self._scan_task(task, report))
