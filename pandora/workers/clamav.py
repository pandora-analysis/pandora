#!/usr/bin/env python3

from __future__ import annotations

import os

import clamd  # type: ignore[import-untyped]

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class ClamAVWorker(BaseWorker):

    socket_path: str

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int | None=None, status_in_report: dict[str, str] | None=None,
                 **options: dict[str, str | int | bool]) -> None:
        super().__init__(module, worker_id, cache, timeout, loglevel, status_in_report, **options)

        if not self.socket_path or not os.path.exists(self.socket_path):
            self.disabled = True
            return
        self._socket = clamd.ClamdUnixSocket(path=self.socket_path)

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        self.logger.debug(f'analysing file {task.file.path}...')
        res = self._socket.instream(task.file.data)
        status, message = res['stream']
        if status == 'OK':
            report.status = Status.CLEAN
        elif status == 'FOUND':
            report.status = Status.ALERT
            report.add_details('malicious', message)
        elif status == 'ERROR':
            report.status = Status.ERROR
            report.add_details('error', message)
