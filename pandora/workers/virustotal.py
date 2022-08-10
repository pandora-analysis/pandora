#!/usr/bin/env python3

import logging
import traceback

import vt  # type: ignore
from vt import error

from ..helpers import Status, get_useragent_for_requests
from ..task import Task
from ..report import Report

from .base import BaseWorker


class VirusTotal(BaseWorker):
    apikey: str

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int=logging.INFO, **options):
        super().__init__(module, worker_id, cache, timeout, loglevel, **options)
        if not self.apikey:
            self.disabled = True
            self.logger.warning('Disabled, missing apikey.')
            return
        self.client = vt.Client(self.apikey, agent=get_useragent_for_requests())

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False):
        try:
            self.logger.debug(f'analysing file {task.file.path}...')
            response = self.client.get_json(f'/files/{task.file.sha256}')
            if 'last_analysis_stats' in response['data']['attributes']:
                if response['data']['attributes']['last_analysis_stats'].get('malicious'):
                    report.status = Status.ALERT
                elif response['data']['attributes']['last_analysis_stats'].get('suspicious'):
                    report.status = Status.WARN
                elif (response['data']['attributes']['last_analysis_stats'].get('harmless')
                      # Not sure about the infected as clean?
                      or response['data']['attributes']['last_analysis_stats'].get('undetected')):
                    report.status = Status.CLEAN

            malicious = {}
            suspicious = {}
            harmless = {}
            undetected = []
            if response['data']['attributes'].get('last_analysis_results'):
                for key, detect in response['data']['attributes']['last_analysis_results'].items():
                    if detect['category'] == 'malicious':
                        malicious[key] = detect['result']
                    elif detect['category'] == 'suspicious':
                        suspicious[key] = detect['result']
                    elif detect['category'] == 'harmless':
                        harmless[key] = detect['result']
                    elif detect['category'] == 'undetected':
                        undetected.append(key)

            report.add_details('permaurl', f"https://www.virustotal.com/gui/file/{response['data']['id']}")
            if malicious:
                report.add_details('malicious', malicious)
            if suspicious:
                report.add_details('suspicious', suspicious)
            if harmless:
                report.add_details('harmless', harmless)
            if undetected:
                report.add_details('undetected', undetected)

        except error.APIError as e:
            if e.code == "NotFoundError":
                report.status = Status.NOTAPPLICABLE
                report.add_details('Information', 'Not known')
                return
            err = f'{repr(e)}\n{traceback.format_exc()}'
            self.logger.error(f'API: {err}')
            report.status = Status.ERROR
