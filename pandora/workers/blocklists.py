import logging
import mimetypes

from typing import Dict, List

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class Blocklists(BaseWorker):

    enable_extensions: bool
    malicious_extensions: List[str]
    enable_mimetypes: bool
    malicious_mimetypes: List[str]
    overwrite_extensions: List[str]

    # we sometimes have differences between magic and mimetypes from python
    # Example: text/x-python from mimetypes.guess_type and text/x-script.python from magic
    synonyms: Dict[str, List[str]] = {
        'text/x-python': ['text/x-script.python'],
        'application/x-cab': ['application/vnd.ms-cab-compressed'],
        'application/x-msdos-program': ['application/x-dosexec'],
        'message/rfc822': ['application/vnd.ms-outlook', 'text/plain'],
        'application/rar': ['application/x-rar']
    }

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int=logging.INFO, **options):
        super().__init__(module, worker_id, cache, timeout, loglevel, **options)

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False):
        report.status = Status.NOTAPPLICABLE
        if self.enable_extensions:
            ext = task.file.original_filename.rsplit(".", 1)[-1]
            if ext in self.overwrite_extensions:
                report.status = Status.OVERWRITE
                report.add_details('Info', f'The result for files with extension {ext} is overwritten by the admin. It generally means we cannot decide on the status of the file. Contact your admin for more details.')

            if ext in self.malicious_extensions:
                report.status = Status.ALERT
                report.add_details('Warning', f'The extension {ext} is considered as malicious by default.')

        if self.enable_mimetypes:
            if not task.file.mime_type:
                report.status = Status.ALERT
                report.add_details('Warning', 'Unable to find a mime type.')
            elif task.file.mime_type in self.malicious_mimetypes:
                report.status = Status.ALERT
                report.add_details('Warning', f'The mimetype {task.file.mime_type} is considered as malicious by default.')
            else:
                guessed_type, encoding = mimetypes.guess_type(task.file.original_filename)
                if not guessed_type:
                    report.status = Status.ALERT
                    report.add_details('Warning', 'Unable to guess the mimetype based on the filename.')
                else:
                    list_valid_mimetypes = [guessed_type]
                    if guessed_type in self.synonyms:
                        list_valid_mimetypes += self.synonyms[guessed_type]
                    if task.file.mime_type not in list_valid_mimetypes:
                        report.status = Status.WARN
                        report.add_details('Warning', f'The mimetype guessed from the filename ({guessed_type}) differs from the one guessed by magic ({task.file.mime_type}).')
