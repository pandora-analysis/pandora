#!/usr/bin/env python3

from oletools import msodde  # type: ignore

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker

# NOTES:
# https://github.com/decalage2/oletools/blob/6f8d1cdcd1a2cdf1e03482987bccc7d27121b4ce/oletools/msodde.py#L913
# * Use process_maybe_encrypted with passwords instead of process_file
# * The module supports all word & excel, rtf, csv and straight xml
# that is much more than task.file.is_oletools_concerned


class MsoDDE(BaseWorker):

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False):
        if not task.file.is_oletools_concerned:
            report.status = Status.NOTAPPLICABLE
            return

        self.logger.debug(f'analysing file {task.file.path}...')
        dde_parser = msodde.process_file(task.file.path, field_filter_mode='only dde')
        if dde_parser:
            report.status = Status.ALERT
            report.add_details('malicious', dde_parser)
