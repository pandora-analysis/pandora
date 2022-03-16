#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os

import clamd  # type: ignore

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class ClamAVWorker(BaseWorker):

    socket_path: str

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int=logging.INFO, **options):
        super().__init__(module, worker_id, cache, timeout, loglevel, **options)

        if not self.socket_path or not os.path.exists(self.socket_path):
            self.disabled = True
            return
        self._socket = clamd.ClamdUnixSocket(path=self.socket_path)

    def analyse(self, task: Task, report: Report):
        self.logger.debug(f'analysing file {task.file.path}...')
        res = self._socket.scan(str(task.file.path))
        status, message = res[str(task.file.path)]
        if status == 'OK':
            report.status = Status.CLEAN
        elif status == 'FOUND':
            report.status = Status.ALERT
            report.add_details('malicious', message)
        elif status == 'ERROR':
            report.status = Status.ERROR
            report.add_details('error', message)
