import logging
import time

from ..task import Task
from ..report import Report

from .base import BaseWorker


class Preview(BaseWorker):

    def __init__(self, module: str, name: str, cache: str, timeout: str, loglevel: int=logging.DEBUG):
        super().__init__(module=module, name=name, cache=cache, timeout=timeout, loglevel=loglevel)

    def analyse(self, task: Task, report: Report):
        task.file.convert()
        task.file.make_previews()
