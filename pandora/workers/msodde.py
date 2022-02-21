#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from oletools import msodde  # type: ignore

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class MsoDDE(BaseWorker):

    def analyse(self, task: Task, report: Report):
        if not task.file.is_oletools_concerned:
            report.status = Status.NOTAPPLICABLE
            return

        self.logger.debug(f'analysing file {task.file.path}...')
        dde_parser = msodde.process_file(task.file.path, field_filter_mode='only dde')
        if dde_parser:
            report.status = Status.ALERT
            report.add_details('malicious', dde_parser)
