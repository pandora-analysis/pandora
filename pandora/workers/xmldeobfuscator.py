#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from XLMMacroDeobfuscator.deobfuscator import process_file  # type: ignore

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class XLMMacroDeobfuscator(BaseWorker):

    def analyse(self, task: Task, report: Report):
        if not task.file.is_oletools_concerned:
            return

        self.logger.debug(f'analysing file {task.file.path}...')
        result = process_file(file=task.file.path, noninteractive=True,
                              noindent=True,
                              output_formula_format='[[CELL-ADDR]], [[INT-FORMULA]]',
                              return_deobfuscated=True,
                              timeout=30)
        if result:
            report.status = Status.ALERT
            report.add_details('suspicious', result)
