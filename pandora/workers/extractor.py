import zipfile
import base64
import shutil
import time

from io import BytesIO
from pathlib import Path
from typing import List

import py7zr  # type: ignore

from ..default import safe_create_dir
from ..helpers import Status
from ..pandora import Pandora
from ..report import Report
from ..task import Task
from ..file import File

from .base import BaseWorker


class Extractor(BaseWorker):

    MAX_EXTRACT_FILES = 15
    MAX_EXTRACTED_FILE_SIZE = 100 * 1000000  # 100Mb
    ZIP_PASSWORDS = ['', 'infected', 'virus', 'CERT_SOC', 'cert', 'pandora']

    def _extract_zip(self, archive_file: File, report: Report, dest_dir: Path) -> List[Path]:
        found_password = False
        extracted_files: List[Path] = []
        with zipfile.ZipFile(archive_file.path) as archive:
            for file_number, info in enumerate(archive.infolist()):
                if file_number >= self.MAX_EXTRACT_FILES:
                    self.logger.warning('Too many files in the archive, stop extracting.')
                    report.status = Status.ALERT
                    report.add_details('Warning', 'Too many files in the archive')
                    break
                is_encrypted = info.flag_bits & 0x1  # from https://github.com/python/cpython/blob/3.10/Lib/zipfile.py
                if is_encrypted and not found_password:
                    for pwd in self.ZIP_PASSWORDS:
                        try:
                            archive.read(info, pwd=pwd.encode())
                            archive.setpassword(pwd.encode())
                            found_password = True
                            break
                        except RuntimeError:
                            continue
                    else:
                        report.status = Status.WARN
                        report.add_details('Warning', 'File encrypted and unable to find password')
                        break
                if info.is_dir():
                    continue
                if info.file_size > self.MAX_EXTRACTED_FILE_SIZE:
                    self.logger.warning(f'Skipping file {info.filename}, too big ({info.file_size}).')
                    report.status = Status.WARN
                    report.add_details('Warning', f'Skipping file {info.filename}, too big ({info.file_size}).')
                    continue
                file_path = archive.extract(info, dest_dir)
                extracted_files.append(Path(file_path))
            else:
                # was able to extract everything, except files that are too big.
                if report.status == Status.RUNNING:
                    report.status = Status.CLEAN
        return extracted_files

    def _extract_7z(self, archive_file: File, report: Report, dest_dir: Path) -> List[Path]:
        # 7z can be encrypted at 2 places, headers, or files. if headers, we have to try.
        try:
            a = py7zr.SevenZipFile(file=archive_file.path, mode='r')
            a.close()
        except py7zr.exceptions.PasswordRequired:
            # NOTE: Not implemeted yet.
            report.status = Status.WARN
            report.add_details('Warning', 'Encypted archive, not supported yet')
            return []
            # TODO:
            # 1. loop over passwords until we find it
            # 2. if it works, set the password

        with py7zr.SevenZipFile(file=archive_file.path, mode='r') as archive:
            if archive.needs_password():
                # NOTE: Not implemeted yet.
                report.status = Status.WARN
                report.add_details('Warning', 'Encypted archive, not supported yet')
                return []
                # TODO:
                # 1. loop over passwords until we find it
                # 2. if it works, set the password

            if archive.archiveinfo().uncompressed >= self.MAX_EXTRACTED_FILE_SIZE:
                self.logger.warning(f'File {archive_file.path.name} too big ({archive.archiveinfo().uncompressed}).')
                report.status = Status.WARN
                report.add_details('Warning', f'File {archive_file.path.name} too big ({archive.archiveinfo().uncompressed}).')
                return []

            if len(archive.getnames()) > self.MAX_EXTRACT_FILES:
                self.logger.warning('Too many files in the archive.')
                report.status = Status.ALERT
                report.add_details('Warning', 'Too many files in the archive')
                return []

            archive.extractall(path=str(dest_dir))

        return [path for path in dest_dir.iterdir() if path.is_file()]

    def analyse(self, task: Task, report: Report):
        if not (task.file.is_archive or task.file.is_eml or task.file.is_msg):
            report.status = Status.NOTAPPLICABLE
            return
        pandora = Pandora()

        tasks = []

        # Try to extract files from archive
        # TODO: Support other archive formats
        if task.file.is_archive:
            extracted_dir = task.file.directory / 'extracted'
            safe_create_dir(extracted_dir)
            try:
                if task.file.mime_type == "application/x-7z-compressed":
                    extracted = self._extract_7z(task.file, report, extracted_dir)
                else:
                    extracted = self._extract_zip(task.file, report, extracted_dir)
            except BaseException as e:
                extracted = []
                self.logger.exception(e)

            if extracted:
                for ef in extracted:
                    with ef.open('rb') as f:
                        sample = f.read()
                    new_task = Task.new_task(user=task.user, sample=BytesIO(sample),
                                             filename=ef.name,
                                             disabled_workers=task.disabled_workers,
                                             parent=task)
                    pandora.add_extracted_reference(task, new_task)
                    pandora.enqueue_task(new_task)
                    tasks.append(new_task)
            shutil.rmtree(extracted_dir)

        # Try to extract attachments from EML file
        if task.file.is_eml or task.file.is_msg:
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
                        tasks.append(new_task)
                    shutil.rmtree(extracted_dir)
            except Exception as e:
                self.logger.exception(e)

        # wait for all the tasks to finish
        while True:
            if all(t.workers_done for t in tasks):
                break
            time.sleep(1)

        for t in tasks:
            if t.status > report.status:
                report.status = t.status
