#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from XLMMacroDeobfuscator.deobfuscator import process_file  # type: ignore
from xlrd2.biffh import XLRDError  # type: ignore


from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class XLMMacroDeobfuscator(BaseWorker):

    def analyse(self, task: Task, report: Report):
        if not task.file.is_oletools_concerned:
            report.status = Status.NOTAPPLICABLE
            return

        self.logger.debug(f'analysing file {task.file.path}...')

        try:
            result = process_file(file=task.file.path, noninteractive=True,
                                  noindent=True,
                                  output_formula_format='[[CELL-ADDR]], [[INT-FORMULA]]',
                                  return_deobfuscated=True,
                                  timeout=30)

            if result:
                report.status = Status.ALERT
                report.add_details('suspicious', result)
        except XLRDError as e:
            self.logger.debug(f'Unsupported file: {e}')
            report.status = Status.NOTAPPLICABLE
        except Exception as e:
            if str(e) == 'Input file type is not supported.':
                # Not the cleanest, but it is how the module works.
                report.status = Status.NOTAPPLICABLE
                return
            raise e
