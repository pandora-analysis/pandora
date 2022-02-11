from ..task import Task
from ..report import Report

from .base import BaseWorker


class Preview(BaseWorker):

    def analyse(self, task: Task, report: Report):
        task.file.convert()
        task.file.make_previews()
