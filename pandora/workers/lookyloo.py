#!/usr/bin/env python3

from __future__ import annotations

from typing import Any

from pylookyloo import Lookyloo

from ..helpers import Status, get_useragent_for_requests
from ..task import Task
from ..report import Report

from .base import BaseWorker


class LookylooWorker(BaseWorker):

    apiurl: str
    autosubmit: bool
    public_listing: bool
    referer: str | None
    user_agent: str | None
    http_headers: dict[str, str]
    cookies: list[dict[str, Any]]
    proxy: str | None

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int | None=None,
                 status_in_report: dict[str, str] | None=None,
                 **options: dict[str, str | int | bool]) -> None:
        super().__init__(module, worker_id, cache, timeout, loglevel, status_in_report, **options)
        self.client = Lookyloo(self.apiurl, get_useragent_for_requests())
        if not self.client.is_up:
            self.disabled = True
            self.logger.warning(f'Unable to connect to the Lookyloo instance: {self.apiurl}.')

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        if not task.file.data:
            report.status = Status.NOTAPPLICABLE
            return
        if not task.file.is_html:
            report.status = Status.NOTAPPLICABLE
            return
        if not self.autosubmit and not manual_trigger:
            report.status = Status.MANUAL
            return

        lookyloo_report = self.client.submit(document=task.file.data,
                                             document_name=task.file.path.name,
                                             listing=self.public_listing,
                                             referer=self.referer,
                                             user_agent=self.user_agent,
                                             headers=self.http_headers,
                                             cookies=self.cookies,
                                             proxy=self.proxy
                                             )
        report.status = Status.UNKNOWN
        report.add_details('permaurl', lookyloo_report)
