#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import traceback

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

        try:
            self.logger.debug(f'analysing file {task.file.path}...')
            dde_parser = msodde.process_file(task.file.path, field_filter_mode='only dde')
            if dde_parser:
                report.status = Status.ALERT
                report.add_details('malicious', dde_parser)

        except Exception as e:
            # File type is not supported by this module
            err = f'{repr(e)}\n{traceback.format_exc()}'
            self.logger.error(f'{err}')
            pass
