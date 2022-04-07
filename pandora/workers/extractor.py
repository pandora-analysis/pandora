import zipfile
import base64
import shutil
import time
import bz2
from tarfile import TarFile
import gzip
import lzma

from io import BytesIO
from pathlib import Path
from typing import List, Optional

import py7zr  # type: ignore
import rarfile  # type: ignore

from ..default import safe_create_dir
from ..helpers import Status
from ..pandora import Pandora
from ..report import Report
from ..task import Task
from ..file import File

from .base import BaseWorker

# Notes:
# 1. Never blindly extract a file:
#    * check unpacked size with a method of the unpacker lib.
#      If it's not (bz2, gz, lzma), read the file up to MAX_EXTRACTED_FILE_SIZE
#      and throw an exception/warning if we reach that.
#    * check how many files are in an archive, preferably with a method of the unpacker lib.
#      If it is not possible, extract files until you reach MAX_EXTRACT_FILES
# => for those two reasons, we cannot use shutil.unpack_archive, which doesn't check anything

# 2. The file can have a password?
#    * figure out how to detect that => library method? exception?
#    * Is possible, keep it in one loop:
#        1. loop over all the files in the archive
#        2. inside that loop, try each possible password against 1st file
#        3. if something works, use a method to set the password in the lib
#       That's the clean approach, works on zip, and rar files
#
#    * Else:
#        1. Loop over each passwords, try to open the archive file until something works
#        2. Reopen the file with the working password
#       => 7z files

# TODO: Standard python lib
#   bz2, gz, lzma: can only contain one file, but it could be > MAX_EXTRACTED_FILE_SIZE
#   tar: Multiple files => check MAX_EXTRACT_FILES


class Extractor(BaseWorker):

    MAX_EXTRACT_FILES = 15
    MAX_EXTRACTED_FILE_SIZE = 100 * 1000000  # 100Mb
    ZIP_PASSWORDS = ['', 'virus', 'CERT_SOC', 'cert', 'pandora', 'infected', '123']

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

    def _extract_rar(self, archive_file: File, report: Report, dest_dir: Path) -> List[Path]:
        found_password = False
        extracted_files: List[Path] = []
        with rarfile.RarFile(archive_file.path) as archive:
            for file_number, info in enumerate(archive.infolist()):
                if file_number >= self.MAX_EXTRACT_FILES:
                    self.logger.warning('Too many files in the archive, stop extracting.')
                    report.status = Status.ALERT
                    report.add_details('Warning', 'Too many files in the archive')
                    break
                if info.needs_password() and not found_password:
                    for pwd in self.ZIP_PASSWORDS:
                        try:
                            with archive.open(info, pwd=pwd.encode()) as f:
                                f.read()
                            archive.setpassword(pwd.encode())
                            found_password = True
                            break
                        except rarfile.BadRarFile:
                            continue
                        except rarfile.PasswordRequired:
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

    def _try_password_7z(self, path) -> Optional[str]:
        for pwd in self.ZIP_PASSWORDS:
            try:
                with py7zr.SevenZipFile(file=path, mode='r', password=pwd) as archive:
                    files_in_archive = archive.getnames()
                    if files_in_archive:
                        archive.read(files_in_archive[0])
                        return pwd
            except py7zr.exceptions.PasswordRequired:
                continue
            except Exception:
                # TODO: notify that to the user?
                continue
        else:
            return None

    def _extract_7z(self, archive_file: File, report: Report, dest_dir: Path) -> List[Path]:
        # 7z can be encrypted at 2 places, headers, or files. if headers, we have to try.
        needs_password = False
        try:
            with py7zr.SevenZipFile(file=archive_file.path, mode='r') as archive:
                files_in_archive = archive.getnames()
                if files_in_archive:
                    archive.read(files_in_archive[0])
        except py7zr.exceptions.PasswordRequired:
            needs_password = True

        if needs_password:
            password = self._try_password_7z(archive_file.path)
            if password is None:
                report.status = Status.WARN
                report.add_details('Warning', 'Encypted archive, unable to find password')
                return []
        else:
            password = None

        with py7zr.SevenZipFile(file=archive_file.path, mode='r', password=password) as archive:
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

    def _extract_bz2(self, archive_file: File, report: Report, dest_dir: Path) -> List[Path]:
        # bz2 is a TAR archive, we basically need to unzip it and then extract the files from the TAR
        # No password can be used to protect a bz2, so we don't need to check for passwords this time
        # Sometimes the bz2 won't contain a TAR, but the way to unzip bz2 stays the same either way
        bz2file = bz2.BZ2File(archive_file.path)  # open the file
        data = bz2file.read(self.MAX_EXTRACTED_FILE_SIZE + 1)  # get the decompressed data
        if len(data) > self.MAX_EXTRACTED_FILE_SIZE:
            self.logger.warning(f'File {archive_file.path.name} too big ({len(data)}).')
            report.status = Status.WARN
            report.add_details('Warning', f'File {archive_file.path.name} too big ({len(data)}).')
            return []
        else:
            if archive_file.path.suffix == ".bz2":
                new_file_path = dest_dir / archive_file.path.name[:-4]  # assuming the filepath ends with .bz2
            else:
                new_file_path = dest_dir / archive_file.path.name
            open(new_file_path, 'wb').write(data)  # write an uncompressed file
            return [new_file_path]

    def _extract_tar(self, archive_file: File, report: Report, dest_dir: Path) -> List[Path]:
        # tar is not a compressed archive but a directory mainly used to regroup other directories
        extracted_files: List[Path] = []
        tar = TarFile(archive_file.path) # open the file
        tar_list = tar.getmembers()
        for file_number, tarinfo in enumerate(tar_list):
            if file_number >= self.MAX_EXTRACT_FILES:
                self.logger.warning('Too many files in the archive, stop extracting.')
                report.status = Status.ALERT
                report.add_details('Warning', 'Too many files in the archive')
                break
            if tarinfo.isfile():
                if tarinfo.size >= self.MAX_EXTRACTED_FILE_SIZE:
                    self.logger.warning(f'File {archive_file.path.name} too big ({tarinfo.size}).')
                    report.status = Status.WARN
                    report.add_details('Warning', f'File {archive_file.path.name} too big ({tarinfo.size}).')
                    continue
                tar.extract(tarinfo, dest_dir)
                file_path = dest_dir / tarinfo.name
                extracted_files.append(Path(file_path))
        return extracted_files

    def _extract_gz(self, archive_file: File, report: Report, dest_dir: Path) -> List[Path]:
        # gz is just like bz2, a compressed archive with a TAR directory inside
        gz_file = gzip.GzipFile(archive_file.path)
        data = gz_file.read(self.MAX_EXTRACTED_FILE_SIZE + 1)
        if len(data) > self.MAX_EXTRACTED_FILE_SIZE:
            self.logger.warning(f'File {archive_file.path.name} too big ({len(data)}).')
            report.status = Status.WARN
            report.add_details('Warning', f'File {archive_file.path.name} too big ({len(data)}).')
            return []
        else:
            if archive_file.path.suffix == ".gz":
                new_file_path = dest_dir / archive_file.path.name[:-3]  # assuming the filepath ends with .bz2
            else:
                new_file_path = dest_dir / archive_file.path.name
            open(new_file_path, 'wb').write(data)  # write an uncompressed file
            return [new_file_path]

    def _extract_lzma(self, archive_file: File, report: Report, dest_dir: Path) -> List[Path]:
        # lzma is just like bz2 and gz, a compressed archive with a TAR directory inside
        lzma_file = lzma.LZMAFile(archive_file.path)
        data = lzma_file.read(self.MAX_EXTRACTED_FILE_SIZE + 1)
        if len(data) > self.MAX_EXTRACTED_FILE_SIZE:
            self.logger.warning(f'File {archive_file.path.name} too big ({len(data)}).')
            report.status = Status.WARN
            report.add_details('Warning', f'File {archive_file.path.name} too big ({len(data)}).')
            return []
        else:
            if archive_file.path.suffix == ".lzma":
                new_file_path = dest_dir / archive_file.path.name[:-5]  # assuming the filepath ends with .bz2
            else:
                new_file_path = dest_dir / archive_file.path.name
            open(new_file_path, 'wb').write(data)  # write an uncompressed file
            return [new_file_path]

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
                elif task.file.mime_type == "application/x-rar":
                    extracted = self._extract_rar(task.file, report, extracted_dir)
                elif task.file.mime_type == "application/x-bzip2":
                    extracted = self._extract_bz2(task.file, report, extracted_dir)
                elif task.file.mime_type == "application/gzip":
                    extracted = self._extract_gz(task.file, report, extracted_dir)
                elif task.file.mime_type == "application/x-tar":
                    extracted = self._extract_tar(task.file, report, extracted_dir)
                elif task.file.mime_type == "application/x-lzma":
                    extracted = self._extract_lzma(task.file, report, extracted_dir)
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
                if task.file.eml_data and task.file.eml_data.get('attachment'):
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
