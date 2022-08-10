from ..exceptions import NoPreview
from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class Preview(BaseWorker):

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False):
        try:
            task.file.convert()
            task.file.make_previews()
        except NoPreview:
            report.status = Status.NOTAPPLICABLE
        except Exception as e:
            self.logger.exception(e)
            self.logger.warning(f'Unable to generate preview, this is suspicious: {e}')
            report.status = Status.WARN
            report.add_details('suspicious', f'Unable to generate preview: {e}')
