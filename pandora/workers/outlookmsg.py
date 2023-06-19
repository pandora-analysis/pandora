#!/usr/bin/env python3

from extract_msg import AppointmentMeeting

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class OutlookMSG(BaseWorker):

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False):
        if not task.file.msg_data or not isinstance(task.file.msg_data, AppointmentMeeting):
            report.status = Status.NOTAPPLICABLE
            return

        self.logger.debug(f'analysing AppontmentMeeting in {task.file.path}...')

        if task.file.msg_data.reminderFileParameter is not None:
            report.status = Status.ALERT
            # suspicious for cve-2023-23397: https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/
            report.add_details('CVE-2023-23397', f'A parameter used to exploit this vulnerability is present in the mail: "{task.file.msg_data.reminderFileParameter}"')
