from __future__ import annotations

from ..exceptions import NoPreview, Unsupported
from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class Preview(BaseWorker):

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        try:
            task.file.convert()
            task.file.make_previews(password=task.password or None)
        except NoPreview:
            report.status = Status.NOTAPPLICABLE
        except Unsupported as e:
            # Password-protected PDFs (and similar) cannot be rendered; do not treat as suspicious.
            message = str(e).lower()
            if 'password' in message:
                report.status = Status.NOTAPPLICABLE
                report.add_details('Info', 'Preview unavailable: file is password-protected.')
                return
            self.logger.critical(e)
            self.logger.warning(f'Unable to generate preview, this is suspicious: {e}')
            report.status = Status.WARN
            report.add_details('suspicious', 'Unable to generate preview.')
        except Exception as e:
            self.logger.critical(e)
            self.logger.warning(f'Unable to generate preview, this is suspicious: {e}')
            report.status = Status.WARN
            report.add_details('suspicious', 'Unable to generate preview.')
