#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

import yara

from ..default import get_homedir
from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class YaraWorker(BaseWorker):
    rulespath: str

    @property
    def rules(self) -> None:
        yara_files = list(self.rulespath.glob('**/*.yar'))
        most_recent = max(entry.stat().st_mtime for entry in yara_files)

        if not self.last_change or self.last_change < most_recent:
            self.last_change = most_recent
        else:
            return yara.load(str(self.savepath))

        rules = yara.compile(filepaths={str(path): str(path) for path in yara_files},
                             includes=True)
        rules.save(str(self.savepath))
        return rules

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int=logging.INFO, **options):
        super().__init__(module, worker_id, cache, timeout, loglevel, **options)
        if not self.rulespath:
            self.disabled = True
            return
        self.last_change = None

        self.rulespath = get_homedir() / 'yara_rules'
        self.savepath = self.rulespath / 'yara.compiled'

        try:
            # initialize the compiled rules
            self.rules
        except yara.Error as e:
            self.disabled = True
            self.logger.critical(f'Unable to initialize rules: {e}')

    def analyse(self, task: Task, report: Report):
        matches = [str(match) for match in self.rules.match(data=task.file.data.getvalue())]
        if matches:
            report.status = Status.ALERT
            report.add_details('Rules matches', matches)
