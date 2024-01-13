from __future__ import annotations

from ..exceptions import TooManyObservables
from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class Observables(BaseWorker):

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        try:
            task.init_observables_from_file()
            for observable in task.observables:
                report.status = observable.status
            if report.status >= Status.WARN:
                report.add_details('Warning', 'At least one observable in known as bad, click on the "Observables" tab for more.')
        except TooManyObservables:
            report.status = Status.WARN
            report.add_details('suspicious', 'There are too many observables in this file.')
