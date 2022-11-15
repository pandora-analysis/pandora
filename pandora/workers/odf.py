#!/usr/bin/env python3

import zipfile

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class ODF(BaseWorker):

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False):
        if not task.file.is_odf:
            report.status = Status.NOTAPPLICABLE
            return

        self.logger.debug(f'analysing file {task.file.path}...')

        try:
            lodoc = zipfile.ZipFile(task.file.path, 'r')
            for f in lodoc.infolist():
                fname = f.filename.lower()
                if fname.startswith('script') or fname.startswith('basic') or \
                        fname.startswith('object') or fname.endswith('.bin'):
                    report.status = Status.ALERT
                    report.add_details('warning', "The file contains an indicator that could be related to a macro")
        except Exception as e:
            raise e
