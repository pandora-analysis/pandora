#!/usr/bin/env python3

from __future__ import annotations

import sys

from pymisp import PyMISP, MISPAttribute, PyMISPError

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
        try:
            self.client = PyMISP(self.apiurl, self.apikey, self.tls_verify)
        except PyMISPError as e:
            self.disabled = True
            self.logger.warning(f'Unable to enable the MISP Worker: {e}.')
            return
        self.logger.info('misp initialized successfully')

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        self.logger.info(f'analysing file {task.file.path}...')
        try:
            response = self.client.search(controller='attributes', value=[task.file.md5, task.file.sha1, task.file.sha256],  # type: ignore[type-var]
                                          to_ids=1, limit=self.max_attribute_count, pythonify=True)
        except Exception as e:
            self.logger.error('unable to reach MISP, exception %s', e)
            report.status = Status.ERROR
            report.add_details('warning', 'Unable to reach MISP.')
            return

        # If something goes poorly but isn't an exception, we don't have a list of attributes, but a dict with an errors key, log that
        if isinstance(response, dict) and 'errors' in response:
            self.logger.error('MISP returned an error: %s', response['errors'])
            report.status = Status.ERROR
            report.add_details('warning', 'MISP returned an error.')
            return

        attributes: list[MISPAttribute] = response  # type: ignore[assignment]

        if not attributes:
            self.logger.info('no attribute found')
            report.status = Status.NOTAPPLICABLE
            return

        # Hash is known so malicious
        self.logger.info('file %s is malicious', task.file.path)
        report.status = Status.ALERT
        events: list[int] = []
        for attribute in attributes:
            if len(events) < self.max_event_count and attribute.event_id not in events:
                events.append(attribute.event_id)
        report.add_details('permaurl', '\n'.join([f'{self.apiurl}/events/view/{i}' for i in events]))

        report.add_details('malicious', f'{attributes[0]["category"]} - {attributes[0]["comment"]}')
