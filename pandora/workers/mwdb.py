#!/usr/bin/env python3

from __future__ import annotations

from typing import Optional, Unpack

from mwdblib import MWDB
from mwdblib.exc import ObjectNotFoundError, MWDBError

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker, WorkerOption


class Mwdb(BaseWorker):

    apikey: str

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int | None=None, **options: Unpack[WorkerOption]) -> None:
        super().__init__(module, worker_id, cache, timeout, loglevel, **options)
        if not self.apikey:
            self.disabled = True
            self.logger.warning('Disabled, missing apikey.')
            return

        try:
            self.mymwdb = MWDB(api_key=self.apikey)
            # This call raise san exception if the API key is invalid
            self.mymwdb.api.request('get', '/api/auth/validate')
        except MWDBError as e:
            self.logger.warning(e)
            self.disabled = True

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        try:
            self.logger.debug(f'analysing file {task.file.path}...')
            result = self.mymwdb.query_file(task.file.sha256)
            # Not error so the sample is on MWDB
            report.status = Status.ALERT
            # we can set all the tags in malicious entry
            if result:
                malicious = result.tags
                report.add_details('malicious', set(malicious))
        except ObjectNotFoundError as e:
            self.logger.debug(e)
            report.status = Status.NOTAPPLICABLE
