#!/usr/bin/env python3

from __future__ import annotations

import traceback

from typing import Optional, Unpack
from urllib.parse import urljoin

import requests

from ..helpers import Status, get_useragent_for_requests
from ..task import Task
from ..report import Report

from .base import BaseWorker, WorkerOption


class HybridAnalysis(BaseWorker):

    apikey: str
    apiurl: str

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int | None=None, **options: Unpack[WorkerOption]) -> None:
        super().__init__(module, worker_id, cache, timeout, loglevel, **options)
        if not self.apikey:
            self.disabled = True
            self.logger.warning('Disabled, missing apikey.')
            return

        self._session = requests.Session()
        self._session.headers.update(
            {'api-key': self.apikey,
             'user-agent': get_useragent_for_requests(),
             'accept': 'application/json',
             'Content-Type': 'application/x-www-form-urlencoded'  # This is wrong, but the API wants it.
             }
        )
        try:
            response = self._session.get(urljoin(self.apiurl, 'key/current'))
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            self.logger.warning(e)
            self.disabled = True

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        try:
            self.logger.debug(f'analysing file {task.file.path}...')
            data = {'hash': task.file.sha256}
            response = self._session.post(urljoin(self.apiurl, 'search/hash'), data=data)
            response.raise_for_status()
            result = response.json()

            malicious = []
            for entries in result:
                if entries['verdict'] == 'malicious':
                    report.status = Status.ALERT
                    if entries['vx_family']:
                        malicious.append(entries['vx_family'])
            if malicious:
                report.add_details('malicious', set(malicious))
        except requests.exceptions.HTTPError as e:
            err = f'{repr(e)}\n{traceback.format_exc()}'
            self.logger.error(f'unknown error during analysis : {err}')
            report.status = Status.ERROR
