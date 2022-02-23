#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

import asyncio
import pathlib
import irmacl_async  # type: ignore
import urllib.parse

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class Irma(BaseWorker):

    apiurl: str
    apitimeout: int

    def __init__(self, module: str, name: str, cache: str, timeout: str,
                 loglevel: int=logging.INFO, **options):
        super().__init__(module, name, cache, timeout, loglevel, **options)
        if not self.apiurl:
            self.disabled = True
            return

    async def _scan_task(self, task, report):
        # Set irma client config
        config = irmacl_async.apiclient.Config(api_endpoint=self.apiurl, timeout=self.apitimeout)
        async with irmacl_async.AAPI(config=config, anonymous=True) as api:
            scan = await api.scans.scan(pathlib.Path(task.file.path), linger=True, force=True)

            link = urllib.parse.urljoin(self.apiurl, f'/scans/{scan.external_id}')
            if scan.infected > 0:
                report.status = Status.ALERT
            report.add_details('Click on "Sign in anonymously" button to reach IRMA report.', link)

    def analyse(self, task: Task, report: Report):
        if task.file.is_archive():
            report.status = Status.NOTAPPLICABLE
            return

        asyncio.run(self._scan_task(task, report))
