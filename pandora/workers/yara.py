#!/usr/bin/env python3

from __future__ import annotations

import yara  # type: ignore[import-not-found]

from ..default import get_homedir
from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class YaraWorker(BaseWorker):
    rulespath = get_homedir() / 'yara_rules'
    savepath = rulespath / 'yara.compiled'
    needs_external: list[str] = []  # list of filenames, used for children classes with yara files requiring external variables
    last_change: float | None = None

    @property
    def rules(self) -> yara.Rules:
        yara_files = list(self.rulespath.glob('**/*.yar'))
        yara_files = [y_file for y_file in self.rulespath.glob('**/*.yar') if y_file.name not in self.needs_external]
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
                 loglevel: int | None=None,
                 status_in_report: dict[str, str] | None=None,
                 **options: dict[str, str | int | bool]) -> None:
        super().__init__(module, worker_id, cache, timeout, loglevel, status_in_report, **options)

        self._init_rules()

        if not list(self.rulespath.glob('**/*.yar')):
            self.disabled = True
            return

        if not self.rulespath:
            self.disabled = True
            return
        self.last_change = None

        try:
            # initialize the compiled rules
            self.rules
        except yara.Error as e:
            self.disabled = True
            self.logger.critical(f'Unable to initialize rules: {e}')

    def _init_rules(self) -> None:
        self.logger.info('No need to initialize the Yara rules')

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        if not task.file.data:
            # Empty file
            report.status = Status.NOTAPPLICABLE
            return

        matches = [str(_match) for _match in self.rules.match(data=task.file.data.getvalue()) if _match]
        if matches:
            report.status = Status.ALERT
            report.add_details('Rules matches', matches)
