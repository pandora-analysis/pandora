import zipfile
import base64
import shutil

from io import BytesIO

import py7zr  # type: ignore

from ..default import safe_create_dir
from ..helpers import Status
from ..pandora import Pandora
from ..report import Report
from ..task import Task

from .base import BaseWorker


class Extractor(BaseWorker):

    MAX_EXTRACT_FILES = 15
    ZIP_PASSWORDS = ['', 'infected', 'virus', 'CERT_SOC', 'cert', 'pandora']

    def analyse(self, task: Task, report: Report):
        if not (task.file.is_archive or task.file.is_eml or task.file.is_msg):
            self.status = Status.NOTAPPLICABLE
            return
        pandora = Pandora()

        # TODO: Get observables
        # if task.file.links:
        #     task.set_observables(task.file.links)

        # Try to extract files from archive
        # TODO: Support other archive formats
        if task.file.is_archive:
            extracted_dir = task.file.directory / 'extracted'
            safe_create_dir(extracted_dir)
            extracted = False
            try:
                if task.file.mime_type == "application/x-7z-compressed":
                    for pwd in self.ZIP_PASSWORDS:
                        with py7zr.SevenZipFile(file=task.file.path, mode='r', password=pwd) as archive:
                            try:
                                archive.extractall(path=str(extracted_dir))
                            except BaseException:
                                extracted = False
                            else:
                                extracted = True
                                break
                else:
                    with zipfile.ZipFile(task.file.path) as archive:
                        for pwd in self.ZIP_PASSWORDS:
                            try:
                                archive.extractall(extracted_dir, pwd=pwd.encode())
                            except BaseException:
                                extracted = False
                            else:
                                extracted = True
                                break
            except BaseException:
                extracted = False

            if extracted:
                folders = [extracted_dir]
                while folders:
                    extract_dir = folders.pop()
                    for child in extract_dir.iterdir():
                        if child.is_file():
                            with child.open('rb') as f:
                                sample = f.read()
                            new_task = Task.new_task(user=task.user, sample=BytesIO(sample),
                                                     filename=child.name,
                                                     disabled_workers=task.disabled_workers,
                                                     parent=task)
                            pandora.add_extracted_reference(task, new_task)
                            pandora.enqueue_task(new_task)
                        elif child.is_dir():
                            folders.append(child)
            shutil.rmtree(extracted_dir)

        # Try to extract attachments from EML file
        if task.file.is_eml or task.file.is_msg:
            # noinspection PyBroadException
            try:
                if task.file.eml_data.get('attachment'):
                    extracted_dir = task.file.directory / 'extracted'
                    safe_create_dir(extracted_dir)
                    for attachment in task.file.eml_data['attachment']:
                        new_task = Task.new_task(user=task.user, sample=BytesIO(base64.b64decode(attachment['raw'])),
                                                 filename=attachment['filename'],
                                                 disabled_workers=task.disabled_workers,
                                                 parent=task)
                        pandora.add_extracted_reference(task, new_task)
                        pandora.enqueue_task(new_task)
                    shutil.rmtree(extracted_dir)
            except Exception as e:
                print(e)

        # TODO: support files with too many archived files and stop
        # If too many files do nothing and set warning
        # if task.extracted > self.max_files:
        #    e = f'archive contains more than {self.max_files} files'
        #    # task.set_report_warn(self, extracted=0, internal_status=Report.STATUS_WARN, error='Too Many Files', error_trace=e)
        #    self.logger.error(e)
