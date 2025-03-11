#!/usr/bin/env python3

from __future__ import annotations

import traceback

from jbxapi import JoeSandbox, JoeException  # type: ignore[import-untyped]

from ..helpers import Status, get_useragent_for_requests
from ..task import Task
from ..report import Report

from .base import BaseWorker


class JoeSandboxWorker(BaseWorker):

    apikey: str
    apiurl: str

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int | None=None,
                 status_in_report: dict[str, str] | None=None,
                 **options: dict[str, str | int | bool]) -> None:
        super().__init__(module, worker_id, cache, timeout, loglevel, status_in_report, **options)
        if not self.apikey:
            self.disabled = True
            self.logger.warning('Disabled, missing apikey.')
            return

        self.joesb = JoeSandbox(apikey=self.apikey, apiurl=self.apiurl,
                                accept_tac=True, user_agent=get_useragent_for_requests())
        try:
            response = self.joesb.account_info()
            self.logger.debug(response)
        except JoeException as e:
            self.logger.warning(e)
            self.disabled = True

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        try:
            self.logger.debug(f'analysing file {task.file.path}...')
            result = self.joesb.analysis_search(task.file.sha256)
            if not result:
                report.status = Status.NOTAPPLICABLE
                return

            malicious = []
            # We check all webid
            for entries in result:
                if 'webid' not in entries:
                    continue
                # we get all the results of analysis
                result_analysis = self.joesb.analysis_info(entries['webid'])
                if result_analysis['detection'] == 'malicious':
                    report.status = Status.ALERT
                    malicious.append(result_analysis['threatname'])
            if malicious:
                report.add_details('malicious', set(malicious))
        except JoeException as e:
            err = f'{repr(e)}\n{traceback.format_exc()}'
            self.logger.error(f'unknown error during analysis : {err}')
            report.status = Status.ERROR
