#!/usr/bin/env python3

from __future__ import annotations

import sys

from pymisp import PyMISP

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker, WorkerOption


if sys.version_info >= (3, 11):
    from typing import Unpack
else:
    from typing_extensions import Unpack


class MISP(BaseWorker):

    apikey: str
    apiurl: str
    tls_verify: bool
    max_event_count: int
    max_attribute_count: int

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int | None=None, **options: Unpack[WorkerOption]) -> None:
        super().__init__(module, worker_id, cache, timeout, loglevel, **options)
        if not self.apiurl or self.apiurl == '':
            self.disabled = True
            self.logger.warning('Disabled, missing apiurl.')
            return
        if not self.apikey or self.apikey == '':
            self.disabled = True
            self.logger.warning('Disabled, missing apikey.')
            return
        self.logger.info('misp initialized successfully')
        self.client = PyMISP(self.apiurl, self.apikey, self.tls_verify)

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        self.logger.info(f'analysing file {task.file.path}...')
        try:
            result = self.client.search(controller='attributes', value=[task.file.md5, task.file.sha1, task.file.sha256], to_ids=1, limit=self.max_attribute_count)
        except Exception as e:
            self.logger.error('unable to reach MISP, exception %s', e)
            report.status = Status.ERROR
            report.add_details('warning', 'Unable to reach MISP.')
            return

        if 'Attribute' in result and not result['Attribute']:
            self.logger.info('no attribute found')
            report.status = Status.NOTAPPLICABLE
            return

        # Hash is known so malicious
        self.logger.info('file %s is malicious', task.file.path)
        report.status = Status.ALERT
        events = []
        for attribute in result['Attribute']:
            if len(events) < self.max_event_count and attribute['event_id'] not in events:
                events.append(attribute['event_id'])
        report.add_details('permaurl', '\n'.join([f'{self.apiurl}/events/view/{i}' for i in events]))

        report.add_details('malicious', f'{result["Attribute"][0]["category"]} - {result["Attribute"][0]["comment"]}')
