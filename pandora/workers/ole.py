#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from oletools import oleid  # type: ignore
from oletools.oleid import RISK  # type: ignore

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class Ole(BaseWorker):

    def analyse(self, task: Task, report: Report):
        if not task.file.is_oletools_concerned:
            report.status = Status.NOTAPPLICABLE
            return

        self.logger.debug(f'analysing file {task.file.path}...')
        report.status = Status.CLEAN
        oid = oleid.OleID(task.file.path)
        malicious = []
        suspicious = []
        for i in oid.check():
            if i.risk in [RISK.HIGH, RISK.MEDIUM]:
                report.status = Status.ALERT
                malicious.append(i.description)

            elif report.status != Status.ALERT and i.risk == RISK.LOW:
                report.status = Status.WARN
                suspicious.append(i.description)
        if malicious:
            report.add_details('malicious', malicious)
        if suspicious:
            report.add_details('suspicious', suspicious)
