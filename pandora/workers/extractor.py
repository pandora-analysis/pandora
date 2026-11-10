from __future__ import annotations

import base64
import functools
import os
import re
import shutil
import tempfile
import time
import zipfile
import zlib

from bz2 import BZ2File
from gzip import GzipFile
from lzma import LZMAFile
from io import BytesIO
from pathlib import Path
from tarfile import TarFile
from typing import overload, Literal, TYPE_CHECKING, Any
from collections.abc import Sequence

from extract_msg.msg_classes import MessageBase, AppointmentMeeting
from extract_msg.attachments import AttachmentBase, SignedAttachment
from extract_msg import MSGFile, OleWriter
import msoffcrypto  # type: ignore[import-untyped]
import olefile  # type: ignore[import-untyped]
from oletools.oleobj import OleNativeStream, find_ole, sanitize_filename  # type: ignore[import-untyped]
from oletools.rtfobj import RtfObjParser  # type: ignore[import-untyped]
import pymupdf
from pure_magic_rs import MagicDb
import py7zr
import py7zr.io
from pycabfile import CabFile  # type: ignore[import-untyped]
import pycdlib
from pycdlib.facade import PyCdlibJoliet, PyCdlibUDF, PyCdlibRockRidge, PyCdlibISO9660
import pyzipper  # type: ignore[import-untyped]
import rarfile  # type: ignore[import-untyped]
from tzlocal import get_localzone_name

from ..default import safe_create_dir, PandoraException
from ..exceptions import ZipBomb, PathTransversal
from ..helpers import Status
from ..pandora import Pandora
from ..report import Report
from ..task import Task
from ..file import File

from .base import BaseWorker

if TYPE_CHECKING:
    from dfvfs.path.path_spec import PathSpec   # type: ignore[import-untyped]
    from dfvfs.volume import tsk_volume_system  # type: ignore[import-untyped]


def dfvfs_wrapper(func):  # type: ignore[no-untyped-def]
    # Importing dfvfs changes the timezone, we need to store the one set before, and reset it afterwards

    @functools.wraps(func)
    def reset_local_tz(*args, **kwargs):  # type: ignore[no-untyped-def]
        localtz = get_localzone_name()
        try:
            to_return = func(*args, **kwargs)
        finally:
            os.environ['TZ'] = localtz
            time.tzset()
        return to_return

    return reset_local_tz


# copied from https://github.com/RyanDFIR/unfurl/blob/main/unfurl/utils.py
def safe_decompress_daa(data: bytes, max_size: int = 500_000_000) -> bytes:
    """Decompress zlib or gzip data with a size limit to prevent zip bomb attacks.

    Uses wbits=47 (32 + MAX_WBITS) to auto-detect zlib or gzip format.

    :param data: Compressed bytes to decompress
    :param max_size: Maximum allowed decompressed size in bytes (defaults to 500M)
    :return: Decompressed bytes
    :raises ZipBomb: If decompressed data exceeds max_size
    :raises zlib.error: If decompression fails
    """
    decompressor = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
    result = decompressor.decompress(data, max_size)
    if decompressor.unconsumed_tail:
        raise ZipBomb("File too big.")
    return result

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


class Extractor(BaseWorker):

    max_files_in_archive: int
    max_files_in_recursive_archive: int
    max_recurse: int
    max_extracted_filesize_in_mb: int
    max_is_error: bool
    zip_passwords: list[str]

    _GENERIC_MAGIC_MIMES = frozenset({
        'application/octet-stream',
        'application/x-ole-storage',
        'application/vnd.ms-office',
        'application/cdfv2',
        'application/x-cfb',
        'inode/x-empty',
    })

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int | None=None,
                 status_in_report: dict[str, str] | None=None,
                 **options: dict[str, str | int | bool]) -> None:
        super().__init__(module, worker_id, cache, timeout, loglevel, status_in_report, **options)
        self.max_extracted_filesize = self.max_extracted_filesize_in_mb * 1000000

        # We might be getting integers from the config file
        self.zip_passwords = [str(pwd) for pwd in self.zip_passwords]

        if self.max_recurse < 1:
            raise PandoraException(f'[{module}] max_recurse must be at least 1 if the extractor worker is enabled.')

        # NOTE: if the number of max recurse is <= replicas + 1, the worker might get stuck:
        # https://github.com/pandora-analysis/pandora/issues/966#issuecomment-4670561558
        if self.max_recurse > self.meta['replicas'] + 1:
            raise PandoraException(f'[{module}] not enough replicas ({self.meta["replicas"]}) for the number of max recurse ({self.max_recurse}) should be at least ({self.max_recurse + 1}) .')

        self.magic_db = MagicDb()

    @property
    def passwords(self) -> list[str]:
        return self._passwords

    @passwords.setter
    def passwords(self, passwords: list[str]) -> None:
        self._passwords = passwords

    def __safe_save(self, forced_parent: Path, dest_path: Path, data: bytes) -> Path:
        resolved_path = dest_path.resolve()
        if not resolved_path.is_relative_to(forced_parent):
            # the dest path is outside of the parent
            raise PathTransversal(f'Path transversal attempt: {resolved_path}')
        with resolved_path.open('wb') as f:
            f.write(data)
        return resolved_path

    def _extract_iso(self, archive_file: File, report: Report, dest_dir: Path) -> list[Path]:
        iso = pycdlib.PyCdlib()
        extracted_files: list[Path] = []
        try:
            if not archive_file.data:
                return extracted_files
            iso.open_fp(archive_file.data)
            facade: PyCdlibJoliet | PyCdlibUDF | PyCdlibRockRidge | PyCdlibISO9660
            if iso.has_udf():
                facade = iso.get_udf_facade()
            elif iso.has_joliet():
                facade = iso.get_joliet_facade()
            elif iso.has_rock_ridge():
                facade = iso.get_rock_ridge_facade()
            else:
                facade = iso.get_iso9660_facade()
            for dirname, _, filelist in facade.walk('/'):
                if len(extracted_files) > self.max_files_in_archive:
                    break
                if not filelist:
                    continue
                for filename in filelist:
                    filename = filename.lstrip('/')
                    extracted = BytesIO()
                    facade.get_file_from_iso_fp(extracted, f'{dirname}/{filename}')
                    if extracted.getbuffer().nbytes >= self.max_extracted_filesize:
                        self.logger.warning(f'File {archive_file.path.name} too big ({extracted.getbuffer().nbytes}).')
                        report.status = Status.ERROR if self.max_is_error else Status.ALERT
                        report.add_details('Warning', f'File {archive_file.path.name} too big ({extracted.getbuffer().nbytes}).')
                        continue
                    if len(extracted_files) > self.max_files_in_archive:
                        break
                    tmp_dest_dir = dest_dir / f'.{dirname}'
                    safe_create_dir(tmp_dest_dir)
                    if ';' in filename:
                        filepath = tmp_dest_dir / filename.split(';')[0]
                    else:
                        filepath = tmp_dest_dir / filename
                    filepath = self.__safe_save(dest_dir, filepath, extracted.getvalue())
                    extracted_files.append(filepath)
            if len(extracted_files) > self.max_files_in_archive:
                self.logger.warning(f'Too many files in the archive (more than {self.max_files_in_archive}).')
                report.status = Status.ERROR if self.max_is_error else Status.ALERT
                report.add_details('Warning', f'Too many files in the archive (more than {self.max_files_in_archive}).')
        finally:
            try:
                iso.close()
            except Exception:  # nosec B110
                pass
        return extracted_files

    def _extract_zip(self, archive_file: File, report: Report, dest_dir: Path,  # type: ignore[no-untyped-def]
                     zip_reader=zipfile.ZipFile) -> list[Path]:
        found_password = False
        extracted_files: list[Path] = []
        with zip_reader(str(archive_file.path)) as archive:
            for file_number, info in enumerate(archive.infolist()):
                if file_number >= self.max_files_in_archive:
                    warning_msg = f'Too many files ({len(archive.infolist())}) in the archive, stopping at {self.max_files_in_archive}.'
                    self.logger.warning(warning_msg)
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', warning_msg)
                    break
                is_encrypted = info.flag_bits & 0x1  # from https://github.com/python/cpython/blob/3.10/Lib/zipfile.py
                if is_encrypted and not found_password:
                    for pwd in self.passwords:
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
                        report.add_extra('no_password', True)
                        break
                if info.is_dir():
                    continue
                if info.file_size > self.max_extracted_filesize:
                    warning_msg = f'Skipping file {info.filename}, too big ({info.file_size}).'
                    self.logger.warning(warning_msg)
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', warning_msg)
                    continue
                file_path = archive.extract(info, dest_dir)
                extracted_files.append(Path(file_path))
            else:
                # was able to extract everything, except files that are too big.
                if report.status == Status.RUNNING:
                    report.status = Status.CLEAN
        return extracted_files

    def _extract_rar(self, archive_file: File, report: Report, dest_dir: Path) -> list[Path]:
        found_password = False
        extracted_files: list[Path] = []
        with rarfile.RarFile(archive_file.path) as archive:
            if not archive.infolist():
                # Looks like there are no files in the archive, this is suspicious
                # Also, might be a REV file, which is potentially not supported
                self.logger.warning(f'Looks like the archive {archive_file.path} is empty.')
                # NOTE: There is a catchall for that.

            for file_number, info in enumerate(archive.infolist()):
                if file_number >= self.max_files_in_archive:
                    self.logger.warning(f'Too many files ({file_number}/{self.max_files_in_archive}) in the archive, stop extracting.')
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', f'Too many files ({file_number}/{self.max_files_in_archive}) in the archive')
                    break
                if info.needs_password() and not found_password:
                    for pwd in self.passwords:
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
                        report.add_extra('no_password', True)
                        break
                if info.is_dir():
                    continue
                if info.file_size > self.max_extracted_filesize:
                    self.logger.warning(f'Skipping file {info.filename}, too big ({info.file_size}).')
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', f'Skipping file {info.filename}, too big ({info.file_size}).')
                    continue
                file_path = archive.extract(info, dest_dir)
                extracted_files.append(Path(file_path))
            else:
                # was able to extract everything, except files that are too big.
                if report.status == Status.RUNNING:
                    report.status = Status.CLEAN
        return extracted_files

    def _try_password_7z(self, path: Path) -> str | None:
        for pwd in self.passwords:
            try:
                with py7zr.SevenZipFile(file=path, mode='r', password=pwd) as archive:
                    files_in_archive = archive.getnames()
                    if files_in_archive:
                        file_name = files_in_archive[0]
                        factory = py7zr.io.BytesIOFactory(1024)
                        archive.extract(targets=[file_name], factory=factory)
                        return pwd
            except py7zr.exceptions.PasswordRequired:
                continue
            except Exception:  # nosec B112
                # TODO: notify that to the user?
                continue
        return None

    def _extract_7z(self, archive_file: File, report: Report, dest_dir: Path) -> list[Path]:
        # 7z can be encrypted at 2 places, headers, or files. if headers, we have to try.
        needs_password = False
        try:
            with py7zr.SevenZipFile(file=archive_file.path, mode='r') as archive:
                files_in_archive = archive.getnames()
                if files_in_archive:
                    file_name = files_in_archive[0]
                    factory = py7zr.io.BytesIOFactory(1024)
                    archive.extract(targets=[file_name], factory=factory)
        except py7zr.exceptions.PasswordRequired:
            needs_password = True

        if needs_password:
            password = self._try_password_7z(archive_file.path)
            if password is None:
                report.status = Status.WARN
                report.add_details('Warning', 'Encrypted archive, unable to find password')
                report.add_extra('no_password', True)
                return []
        else:
            password = None

        with py7zr.SevenZipFile(file=archive_file.path, mode='r', password=password) as archive:
            if archive.archiveinfo().uncompressed >= self.max_extracted_filesize:
                self.logger.warning(f'File {archive_file.path.name} too big ({archive.archiveinfo().uncompressed}).')
                report.status = Status.ERROR if self.max_is_error else Status.ALERT
                report.add_details('Warning', f'File {archive_file.path.name} too big ({archive.archiveinfo().uncompressed}).')
                return []

            if len(archive.getnames()) > self.max_files_in_archive:
                self.logger.warning(f'Too many files ({len(archive.getnames())}/{self.max_files_in_archive}) in the archive.')
                report.status = Status.ERROR if self.max_is_error else Status.ALERT
                report.add_details('Warning', f'Too many files ({len(archive.getnames())}/{self.max_files_in_archive}) in the archive')
                return []

            archive.extractall(path=str(dest_dir))

        return [path for path in dest_dir.glob('**/*') if path.is_file()]

    def _extract_bz2(self, archive_file: File, report: Report, dest_dir: Path) -> list[Path]:
        # bz2 is a TAR archive, we basically need to unzip it and then extract the files from the TAR
        # No password can be used to protect a bz2, so we don't need to check for passwords this time
        # Sometimes the bz2 won't contain a TAR, but the way to unzip bz2 stays the same either way
        bz2file = BZ2File(archive_file.path)  # open the file
        data = bz2file.read(self.max_extracted_filesize + 1)  # get the decompressed data
        if len(data) > self.max_extracted_filesize:
            self.logger.warning(f'File {archive_file.path.name} too big ({len(data)}).')
            report.status = Status.ERROR if self.max_is_error else Status.ALERT
            report.add_details('Warning', f'File {archive_file.path.name} too big ({len(data)}).')
            return []

        if archive_file.path.suffix == ".bz2":
            new_file_path = dest_dir / archive_file.path.stem
        else:
            new_file_path = dest_dir / archive_file.path.name
        new_file_path = self.__safe_save(dest_dir, new_file_path, data)
        return [new_file_path]

    def _extract_tar(self, archive_file: File, report: Report, dest_dir: Path) -> list[Path]:
        # tar is not a compressed archive but a directory mainly used to regroup other directories
        extracted_files: list[Path] = []
        with TarFile(archive_file.path) as tar:
            for file_number, tarinfo in enumerate(tar.getmembers()):
                if file_number >= self.max_files_in_archive:
                    self.logger.warning(f'Too many files ({file_number}/{self.max_files_in_archive}) in the archive, stop extracting.')
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', f'Too many files ({file_number}/{self.max_files_in_archive}) in the archive')
                    break
                if not tarinfo.isfile():
                    continue
                if tarinfo.size >= self.max_extracted_filesize:
                    self.logger.warning(f'File {archive_file.path.name} too big ({tarinfo.size}).')
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', f'File {archive_file.path.name} too big ({tarinfo.size}).')
                    continue
                tar.extract(tarinfo, dest_dir, filter='data')
                file_path = dest_dir / tarinfo.name
                extracted_files.append(Path(file_path))
        return extracted_files

    def _extract_cab(self, archive_file: File, report: Report, dest_dir: Path) -> list[Path]:
        extracted_files: list[Path] = []
        # Code from https://github.com/vstinner/hachoir/issues/65#issuecomment-866965090
        if not archive_file.data:
            return extracted_files
        with CabFile(archive_file.path) as cab:
            for file_number, filename in enumerate(cab.namelist()):
                if file_number >= self.max_files_in_archive:
                    self.logger.warning(f'Too many files ({file_number}/{self.max_files_in_archive}) in the archive, stop extracting.')
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', f'Too many files ({file_number}/{self.max_files_in_archive}) in the archive')
                    break
                info = cab.getinfo(filename)
                if info.file_size >= self.max_extracted_filesize:
                    self.logger.warning(f'File {archive_file.path.name} too big ({info.file_size}).')
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', f'File {archive_file.path.name} too big ({info.file_size}).')
                    continue
                file = cab.read(filename)
                file_path = dest_dir / filename
                file_path = self.__safe_save(dest_dir, file_path, file)
                extracted_files.append(Path(file_path))
        return extracted_files

    def _extract_encrypted_office(self, archive_file: File, report: Report, dest_dir: Path) -> list[Path]:
        file = msoffcrypto.OfficeFile(archive_file.data)
        to_return: list[Path] = []
        if file.is_encrypted():
            decrypted = BytesIO()
            for pwd in self.passwords:
                try:
                    file.load_key(password=pwd)  # , verify_password=True)
                    file.decrypt(decrypted)
                    break
                except Exception as e:
                    # wrong password
                    self.logger.info(f'Incorrect password for office doc ({pwd}): {e}.')
                    continue
            if decrypted.getbuffer().nbytes > 0:
                d_path = dest_dir / f'decrypted_{archive_file.path.name}'
                to_return.append(d_path)
                with d_path.open('wb') as f:
                    f.write(decrypted.getbuffer())
            else:
                report.status = Status.WARN
                report.add_details('Warning', 'Unable to decrypt file.')
                report.add_extra('no_password', True)
        else:
            report.status = Status.NOTAPPLICABLE
        return to_return

    def _extract_gz(self, archive_file: File, report: Report, dest_dir: Path) -> list[Path]:
        # gz is just like bz2, a compressed archive with a TAR directory inside
        gz_file = GzipFile(archive_file.path)
        data = gz_file.read(self.max_extracted_filesize + 1)
        if len(data) > self.max_extracted_filesize:
            self.logger.warning(f'File {archive_file.path.name} too big ({len(data)}).')
            report.status = Status.ERROR if self.max_is_error else Status.ALERT
            report.add_details('Warning', f'File {archive_file.path.name} too big ({len(data)}).')
            return []
        if archive_file.path.suffix == ".gz":
            new_file_path = dest_dir / archive_file.path.stem
        else:
            new_file_path = dest_dir / archive_file.path.name
        new_file_path = self.__safe_save(dest_dir, new_file_path, data)
        return [new_file_path]

    def _extract_lzma(self, archive_file: File, report: Report, dest_dir: Path) -> list[Path]:
        # lzma is just like bz2 and gz, a compressed archive with a TAR directory inside
        lzma_file = LZMAFile(archive_file.path)
        data = lzma_file.read(self.max_extracted_filesize + 1)
        if len(data) > self.max_extracted_filesize:
            self.logger.warning(f'File {archive_file.path.name} too big ({len(data)}).')
            report.status = Status.ERROR if self.max_is_error else Status.ALERT
            report.add_details('Warning', f'File {archive_file.path.name} too big ({len(data)}).')
            return []
        if archive_file.path.suffix == ".lzma":
            new_file_path = dest_dir / archive_file.path.stem
        else:
            new_file_path = dest_dir / archive_file.path.name
        new_file_path = self.__safe_save(dest_dir, new_file_path, data)
        return [new_file_path]

    @overload
    def check_dfvfs(self, submitted_file: File, check_only: Literal[True]) -> bool:
        ...

    @overload
    def check_dfvfs(self, submitted_file: File, check_only: Literal[False]) -> list[tuple[PathSpec, tsk_volume_system.TSKVolumeSystem]]:
        ...

    @dfvfs_wrapper  # type: ignore[untyped-decorator]
    def check_dfvfs(self, submitted_file: File, check_only: bool) -> bool | list[tuple[PathSpec, tsk_volume_system.TSKVolumeSystem]]:
        to_process = []
        # pylint: disable=C0415
        from dfvfs.analyzer import analyzer  # type: ignore
        from dfvfs.lib import definitions, raw_helper, errors  # type: ignore
        from dfvfs.path import factory  # type: ignore
        from dfvfs.resolver import resolver  # type: ignore
        from dfvfs.volume import tsk_volume_system

        path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_OS, location=submitted_file.path)

        if type_indicators := analyzer.Analyzer.GetStorageMediaImageTypeIndicators(path_spec):
            # NOTE: type_indicators can be a list, we pick the 1st one, but might want to loop
            for ti in type_indicators:
                path = factory.Factory.NewPathSpec(ti, parent=path_spec)
                to_process.append(path)
        else:
            # The RAW storage media image type cannot be detected based on
            # a signature so we try to detect it based on common file naming
            # schemas.
            file_system = resolver.Resolver.OpenFileSystem(path_spec)
            raw_path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_RAW, parent=path_spec)
            try:
                glob_results = raw_helper.RawGlobPathSpec(file_system, raw_path_spec)
            except errors.PathSpecError:
                return False
            if not glob_results:
                return False
            # NOTE: what are we supposed to do if we have more?
            to_process = glob_results

        to_return = []
        for path_to_process in to_process:
            volume_path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_TSK_PARTITION, location='/', parent=path_to_process)
            try:
                volume_system = tsk_volume_system.TSKVolumeSystem()
                volume_system.Open(volume_path_spec)
                if check_only:
                    return True
                to_return.append((path_to_process, volume_system))
            except (OSError, errors.BackEndError):
                self.logger.info('Not supported by dfvfs')
            except Exception:
                self.logger.info('Unknown exception from dfvfs')
        if check_only:
            # at this stage, if we are in check_only and didn't return, it's not supported
            return False
        return to_return

    @dfvfs_wrapper  # type: ignore[untyped-decorator]
    def extract_with_dfvfs(self, archive_file: File, report: Report) -> list[tuple[str, BytesIO]]:
        extracted: list[tuple[str, BytesIO]] = []
        # pylint: disable=C0415
        from dfvfs.vfs.file_entry import FileEntry  # type: ignore
        from dfvfs.path import factory
        from dfvfs.resolver import resolver
        from dfvfs.lib import definitions

        def process_dir(file_entry: FileEntry) -> None:
            for sub_file_entry in file_entry.sub_file_entries:
                if len(extracted) >= self.max_files_in_archive:
                    self.logger.warning(f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive, stop extracting.')
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive')
                    break
                if sub_file_entry.IsFile():
                    file_object = sub_file_entry.GetFileObject()
                    file_content = BytesIO(file_object.read())
                    if file_content.getbuffer().nbytes >= self.max_extracted_filesize:
                        self.logger.warning(f'File {sub_file_entry.name} from {archive_file.path.name} too big ({file_content.getbuffer().nbytes}).')
                        report.status = Status.ERROR if self.max_is_error else Status.ALERT
                        report.add_details('Warning', f'File {archive_file.path.name} too big ({file_content.getbuffer().nbytes}).')
                        continue
                    if not file_content.getbuffer().nbytes:
                        # empty file
                        report.add_details('Warning', f'File {archive_file.path.name} is empty.')
                        self.logger.warning(f'File {archive_file.path.name} is empty.')
                    extracted.append((sub_file_entry.name, file_content))
                elif sub_file_entry.IsDirectory():
                    process_dir(sub_file_entry)

        for path_spec, volume_system in self.check_dfvfs(archive_file, False):  # pylint: disable=not-an-iterable
            for volume in volume_system.volumes:
                if volume_identifier := getattr(volume, 'identifier'):
                    volume = volume_system.GetVolumeByIdentifier(volume_identifier)
                    if not volume:
                        self.logger.warning(f'Unable to find volume {volume_identifier}')
                        continue

                    # We check the current partition
                    _path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_TSK_PARTITION,
                                                             location=f'/{volume.identifier}', parent=path_spec)

                    # We directly mount the /
                    mft_path_spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_TSK,
                                                                location='/', parent=_path_spec)

                    file_entry = resolver.Resolver.OpenFileEntry(mft_path_spec)
                    process_dir(file_entry)
                else:
                    self.logger.warning('Missing volume identifier, cannot do anything.')
        return extracted

    def extract_eml(self, eml_data: dict[str, Any]) -> list[tuple[str, BytesIO]]:
        extracted: list[tuple[str, BytesIO]] = []
        for attachment in eml_data['attachment']:
            extracted.append((attachment['filename'], BytesIO(base64.b64decode(attachment['raw']))))
        return extracted

    def extract_msg(self, msg_data: MessageBase | AppointmentMeeting) -> list[tuple[str, BytesIO]]:
        extracted: list[tuple[str, BytesIO]] = []
        for attachment in msg_data.attachments:
            if isinstance(attachment.data, bytes):
                blob = BytesIO(attachment.data)
            elif isinstance(attachment.data, MSGFile):
                blob = BytesIO()
                attachment.data.export(blob)
            if isinstance(attachment, AttachmentBase):
                extracted.append((attachment.getFilename(), blob))
            elif isinstance(attachment, SignedAttachment):
                extracted.append((attachment.name, blob))
        return extracted

    def _extract_daa(self, archive_file: File, report: Report, dest_dir: Path) -> list[tuple[str, BytesIO]]:
        def extract_header(data: bytes) -> dict[str, bytes]:
            header = {}
            header['magic'] = data[:16]
            header['size_first_offset'] = data[16:20]
            header['version'] = data[20:24]
            header['data_first_offset'] = data[24:28]
            # not sure what the two there are for, but sure
            header['b1'] = data[28:32]  # should be b'\x01\x00\x00\x00'
            header['b0'] = data[32:36]  # should be b'\x00\x00\x00\x00'
            header['chunksize'] = data[36:40]
            header['isosize'] = data[40:48]
            header['daasize'] = data[48:56]
            header['hdata'] = data[56:72]  # should be b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            header['crc'] = data[72:76]
            return header

        def getting_chuncklist(header: dict[str, Any], data: bytes) -> list[int]:
            chunklist = []
            size_first_offset = int.from_bytes(header['size_first_offset'], byteorder='little', signed=False)
            data_first_offset = int.from_bytes(header['data_first_offset'], byteorder='little', signed=False)
            for offset in range(size_first_offset, data_first_offset, 3):
                chunksize1, chunksize2, chunksize3 = data[offset:offset + 3]
                # We need to flip the byte : 0xAABBCC to 0xAACCBB
                finalchunksizeB = [chunksize1, chunksize3, chunksize2]
                finalchunksize = int.from_bytes(finalchunksizeB, 'big')
                chunklist.append(finalchunksize)
            return chunklist

        def unpackdata(header: dict[str, Any], chunksizes: list[int], data: bytes) -> bytes:
            raw = b""
            offset = int.from_bytes(header['data_first_offset'], byteorder='little', signed=False)
            for chunksize in chunksizes:
                packeddata = data[offset:offset + chunksize]
                offset += chunksize
                raw += safe_decompress_daa(packeddata, self.max_extracted_filesize)
                if len(raw) > self.max_extracted_filesize:
                    raise ZipBomb('File too big')
            return raw

        pseudo_file = archive_file.data
        if not pseudo_file:
            return []

        header = extract_header(pseudo_file.getvalue())
        if len(pseudo_file.getvalue()) != int.from_bytes(header['daasize'], byteorder='little', signed=False):
            # length is incorrect.
            self.logger.warning('Potentially invalid DAA file length')

        crc = zlib.crc32(pseudo_file.getvalue()[0:72])
        if crc != int.from_bytes(header['crc'], byteorder='little', signed=False):
            # invalid crc
            self.logger.warning('Invalid CRC')

        chunklist = getting_chuncklist(header, pseudo_file.getvalue())
        try:
            raw = unpackdata(header, chunklist, pseudo_file.getvalue())
            if len(raw) != int.from_bytes(header['isosize'], byteorder='little', signed=False):
                self.logger.warning('Potentially invalid ISO file length')
            return [('internal_iso_in_daa.iso', BytesIO(raw))]
        except ZipBomb:
            self.logger.warning(f'File {archive_file.path.name} too big.')
            report.status = Status.ERROR if self.max_is_error else Status.ALERT
            report.add_details('Warning', f'File {archive_file.path.name} too big.')
            return [('internal_iso_in_daa.iso', BytesIO())]

    def _embedded_filename(self, *candidates: str | None, index: int) -> str:
        for candidate in candidates:
            if not candidate:
                continue
            name = sanitize_filename(candidate)
            if name:
                return name
        return f'embedded_{index}.bin'

    @staticmethod
    def _normalize_extension(raw: str) -> str | None:
        token = raw.split('/')[0].strip().lower().lstrip('.')
        if not token or len(token) > 10 or not token.isalnum() or token == 'bin':  # nosec
            return None
        return f'.{token}'

    def _extension_from_magic(self, payload: bytes) -> str | None:
        if not payload:
            return None
        try:
            result = self.magic_db.best_magic_buffer(payload)
        except ValueError:
            return None
        mime = (result.mime_type or '').lower()
        if mime in self._GENERIC_MAGIC_MIMES:
            return None
        known = File.MIME_TYPE_EQUAL.get(mime)
        if known and known[1]:
            normalized = self._normalize_extension(known[1])
            if normalized:
                return normalized
        candidates = [self._normalize_extension(raw) for raw in (result.extensions or [])]
        candidates = [ext for ext in candidates if ext]
        if not candidates:
            return None
        routed = {ext for extensions in File.TYPE_EXTENSIONS.values() for ext in extensions}
        for ext in candidates:
            if ext in routed:
                return ext
        return candidates[0]

    def _payload_extension(self, payload: bytes, compobj: bytes | None=None) -> str:
        """Infer a safe extension from magic first, then optional CompObj hints."""
        ext = self._extension_from_magic(payload)
        if ext:
            return ext
        if compobj:
            lowered = compobj.lower()
            if b'acrobat' in lowered or b'pdf' in lowered:
                return '.pdf'
            if b'word.document' in lowered or b'msworddoc' in lowered:
                return '.doc'
            if b'excel' in lowered or b'worksheet' in lowered:
                return '.xls'
            if b'powerpoint' in lowered:
                return '.ppt'
            if b'package' in lowered:
                return '.bin'
        if payload.startswith(olefile.MAGIC):
            return '.ole'
        return '.bin'

    def _compobj_bytes(self, ole: Any, root: list[str] | None=None) -> bytes | None:
        path = (root or []) + ['\x01CompObj']
        try:
            if ole.exists(path):
                return ole.openstream(path).read()
        except Exception as e:
            self.logger.warning(f'Unable to read CompObj for {"/".join(path)}: {e}')
        return None

    def _objectpool_extension(self, ole: Any, root: list[str]) -> str:
        """Guess a file extension from CompObj / well-known streams under an ObjectPool entry."""
        try:
            if ole.exists(root + ['WordDocument']):
                return '.doc'
            if ole.exists(root + ['Workbook']) or ole.exists(root + ['Book']):
                return '.xls'
            if ole.exists(root + ['PowerPoint Document']):
                return '.ppt'
        except Exception:  # nosec B110
            pass
        return self._payload_extension(b'', self._compobj_bytes(ole, root))

    def _extract_ole10native(self, ole: Any, report: Report, extracted: list[tuple[str, BytesIO]],
                             index: int) -> tuple[int, bool]:
        found_native = False
        for path_parts in ole.listdir():
            if path_parts[-1].lower() != '\x01ole10native':
                continue
            found_native = True
            if len(extracted) >= self.max_files_in_archive:
                self.logger.warning(f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive, stop extracting.')
                report.status = Status.ERROR if self.max_is_error else Status.ALERT
                report.add_details('Warning', f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive')
                break
            stream = None
            try:
                stream = ole.openstream(path_parts)
                opkg = OleNativeStream(stream)
                if opkg.is_link:
                    continue
                if opkg.actual_size is None:
                    continue
                if opkg.actual_size > self.max_extracted_filesize:
                    self.logger.warning(f'Skipping file {opkg.filename}, too big ({opkg.actual_size}).')
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', f'Skipping file {opkg.filename}, too big ({opkg.actual_size}).')
                    continue
                payload = stream.read(opkg.actual_size)
                if not payload:
                    continue
                filename = self._embedded_filename(opkg.filename, opkg.src_path, opkg.temp_path, index=index)
                extracted.append((filename, BytesIO(payload)))
                index += 1
            except Exception as e:
                self.logger.warning(f'Unable to extract OLE native stream: {e}')
            finally:
                if stream is not None:
                    stream.close()
        return index, found_native

    def _extract_ole_contents(self, ole: Any, report: Report, extracted: list[tuple[str, BytesIO]],
                              index: int) -> tuple[int, bool]:
        """
        Unwrap non-Package OLE embeds that store the raw payload in a CONTENTS stream
        (e.g. Acrobat.Document objects inside OOXML xl/embeddings/*.bin).

        Safety: only reads the known CONTENTS stream, enforces max size, sanitizes the
        filename, and prefers magic-byte typing over trusting CompObj labels.
        """
        found_contents = False
        # Exact stream name only — do not walk arbitrary OLE streams.
        contents_paths = [
            path_parts for path_parts in ole.listdir()
            if path_parts[-1].upper() == 'CONTENTS'
        ]
        if not contents_paths:
            return index, found_contents

        compobj = self._compobj_bytes(ole)
        for path_parts in contents_paths:
            found_contents = True
            if len(extracted) >= self.max_files_in_archive:
                self.logger.warning(f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive, stop extracting.')
                report.status = Status.ERROR if self.max_is_error else Status.ALERT
                report.add_details('Warning', f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive')
                break
            stream = None
            try:
                stream = ole.openstream(path_parts)
                # Read one byte past the limit so oversized payloads are detected without loading unbounded data blindly.
                payload = stream.read(self.max_extracted_filesize + 1)
                if not payload:
                    continue
                if len(payload) > self.max_extracted_filesize:
                    self.logger.warning(f'Skipping OLE CONTENTS stream, too big ({len(payload)}).')
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', f'Skipping OLE CONTENTS stream, too big ({len(payload)}).')
                    continue
                ext = self._payload_extension(payload, compobj)
                filename = self._embedded_filename(f'embedded_{index}{ext}', index=index)
                if not filename.lower().endswith(ext):
                    filename = f'{filename}{ext}'
                report.add_details('Embedded Files Found', f'OLE CONTENTS ({ext.lstrip(".") or "bin"})')
                extracted.append((filename, BytesIO(payload)))
                index += 1
            except Exception as e:
                self.logger.warning(f'Unable to extract OLE CONTENTS stream: {e}')
            finally:
                if stream is not None:
                    stream.close()
        return index, found_contents

    def _extract_objectpool(self, ole: Any, report: Report, extracted: list[tuple[str, BytesIO]],
                            index: int) -> int:
        """Reconstruct nested OLE objects stored under ObjectPool (non-Package embeds)."""
        children: set[str] = set()
        try:
            for path_parts in ole.listdir(streams=True, storages=True):
                if len(path_parts) >= 2 and path_parts[0] == 'ObjectPool':
                    children.add(path_parts[1])
        except Exception as e:
            self.logger.warning(f'Unable to list ObjectPool: {e}')
            return index

        for child in sorted(children):
            if len(extracted) >= self.max_files_in_archive:
                self.logger.warning(f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive, stop extracting.')
                report.status = Status.ERROR if self.max_is_error else Status.ALERT
                report.add_details('Warning', f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive')
                break
            root = ['ObjectPool', child]
            # Ole10Native under this entry is already handled by _extract_ole10native.
            try:
                has_native = any(
                    list(path_parts[:2]) == root and path_parts[-1].lower() == '\x01ole10native'
                    for path_parts in ole.listdir()
                )
            except Exception:
                has_native = False
            if has_native:
                continue
            tmp_path = None
            try:
                writer = OleWriter()  # nolint
                writer.fromOleFile(ole, rootPath=root)
                with tempfile.NamedTemporaryFile(suffix='.ole', delete=False) as tmp:
                    tmp_path = Path(tmp.name)
                writer.write(str(tmp_path))
                payload = tmp_path.read_bytes()
                if not payload or not olefile.isOleFile(BytesIO(payload)):
                    continue
                if len(payload) > self.max_extracted_filesize:
                    filename = f'embedded_{index}{self._objectpool_extension(ole, root)}'
                    self.logger.warning(f'Skipping file {filename}, too big ({len(payload)}).')
                    report.status = Status.ERROR if self.max_is_error else Status.ALERT
                    report.add_details('Warning', f'Skipping file {filename}, too big ({len(payload)}).')
                    continue
                ext = self._objectpool_extension(ole, root)
                filename = self._embedded_filename(f'objectpool_{child}{ext}', index=index)
                if not filename.lower().endswith(ext):
                    filename = f'{filename}{ext}'
                report.add_details('Embedded Files Found', f'ObjectPool/{child}')
                extracted.append((filename, BytesIO(payload)))
                index += 1
            except Exception as e:
                self.logger.warning(f'Unable to extract ObjectPool/{child}: {e}')
            finally:
                if tmp_path is not None:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except Exception:  # nosec B110
                        pass
        return index

    def _extract_office_embedded(self, archive_file: File, report: Report, dest_dir: Path) -> list[tuple[str, BytesIO]]:
        extracted: list[tuple[str, BytesIO]] = []
        if not archive_file.data:
            report.status = Status.NOTAPPLICABLE
            return extracted

        data = archive_file.data.getvalue()
        index = 1
        try:
            for ole in find_ole(str(archive_file.path), data):
                if ole is None:
                    continue
                try:
                    index, _ = self._extract_ole10native(ole, report, extracted, index)
                    if len(extracted) < self.max_files_in_archive:
                        index, _ = self._extract_ole_contents(ole, report, extracted, index)
                    if len(extracted) < self.max_files_in_archive:
                        index = self._extract_objectpool(ole, report, extracted, index)
                finally:
                    try:
                        ole.close()
                    except Exception:  # nosec B110
                        pass
                if len(extracted) >= self.max_files_in_archive:
                    break
        except Exception as e:
            self.logger.exception(e)
            report.status = Status.WARN
            report.add_details('Warning', f'Unable to extract {archive_file.path.name}: {e}.')
            return extracted

        # Also pick Open XML embeddings that are not OLE packages (or OLE without unwrapable streams).
        if zipfile.is_zipfile(archive_file.path) and len(extracted) < self.max_files_in_archive:
            try:
                with zipfile.ZipFile(archive_file.path) as archive:
                    for info in archive.infolist():
                        if len(extracted) >= self.max_files_in_archive:
                            self.logger.warning(f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive, stop extracting.')
                            report.status = Status.ERROR if self.max_is_error else Status.ALERT
                            report.add_details('Warning', f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive')
                            break
                        name_lower = info.filename.lower()
                        if info.is_dir() or '/embeddings/' not in f'/{name_lower}':
                            continue
                        if info.file_size > self.max_extracted_filesize:
                            self.logger.warning(f'Skipping file {info.filename}, too big ({info.file_size}).')
                            report.status = Status.ERROR if self.max_is_error else Status.ALERT
                            report.add_details('Warning', f'Skipping file {info.filename}, too big ({info.file_size}).')
                            continue
                        member = archive.read(info)
                        if not member:
                            continue
                        if member.startswith(olefile.MAGIC):
                            ole = None
                            already_unwrapped = False
                            try:
                                ole = olefile.OleFileIO(BytesIO(member))
                                for path_parts in ole.listdir():
                                    leaf = path_parts[-1].lower()
                                    # Ole10Native / CONTENTS are handled above via find_ole — skip raw .bin.
                                    if leaf in {'\x01ole10native', 'contents'}:
                                        already_unwrapped = True
                                        break
                            except Exception as e:
                                self.logger.warning(f'Unable to parse embedded OLE {info.filename}: {e}')
                            finally:
                                if ole is not None:
                                    try:
                                        ole.close()
                                    except Exception:  # nosec B110
                                        pass
                            if already_unwrapped:
                                continue
                            # Embedded OLE without known payload streams: queue the .bin itself.
                            filename = self._embedded_filename(Path(info.filename).name, index=index)
                            extracted.append((filename, BytesIO(member)))
                            index += 1
                        else:
                            filename = self._embedded_filename(Path(info.filename).name, index=index)
                            extracted.append((filename, BytesIO(member)))
                            index += 1
            except Exception as e:
                self.logger.exception(e)
                report.status = Status.WARN
                report.add_details('Warning', f'Unable to extract {archive_file.path.name}: {e}.')

        if not extracted:
            report.status = Status.NOTAPPLICABLE
        return extracted

    def _extract_rtf(self, archive_file: File, report: Report, dest_dir: Path) -> list[tuple[str, BytesIO]]:
        extracted: list[tuple[str, BytesIO]] = []
        if not archive_file.data:
            report.status = Status.NOTAPPLICABLE
            return extracted

        try:
            rtf = RtfObjParser(archive_file.data.getvalue())
            rtf.parse()
        except Exception as e:
            self.logger.exception(e)
            report.status = Status.WARN
            report.add_details('Warning', f'Unable to extract {archive_file.path.name}: {e}.')
            return extracted

        index = 1
        for obj in rtf.objects:
            if not getattr(obj, 'is_package', False) or not getattr(obj, 'olepkgdata', None):
                continue
            if len(extracted) >= self.max_files_in_archive:
                self.logger.warning(f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive, stop extracting.')
                report.status = Status.ERROR if self.max_is_error else Status.ALERT
                report.add_details('Warning', f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive')
                break
            payload = obj.olepkgdata
            if len(payload) > self.max_extracted_filesize:
                self.logger.warning(f'Skipping file {obj.filename}, too big ({len(payload)}).')
                report.status = Status.ERROR if self.max_is_error else Status.ALERT
                report.add_details('Warning', f'Skipping file {obj.filename}, too big ({len(payload)}).')
                continue
            filename = self._embedded_filename(obj.filename, getattr(obj, 'src_path', None),
                                               getattr(obj, 'temp_path', None), index=index)
            extracted.append((filename, BytesIO(payload)))
            index += 1

        if not extracted:
            report.status = Status.NOTAPPLICABLE
        return extracted

    def _is_ics(self, archive_file: File) -> bool:
        # Prefer File.is_ics when present; keep a fallback for older images without that property.
        is_ics_prop = getattr(type(archive_file), 'is_ics', None)
        if isinstance(is_ics_prop, property):
            try:
                return bool(archive_file.is_ics)
            except Exception:  # nosec B110
                pass
        if archive_file.path.suffix.lower() in {'.ics', '.ical', '.ifb', '.vcs'}:
            return True
        return archive_file.mime_type in {
            'text/calendar',
            'application/ics',
            'text/x-vcalendar',
        }

    def _extract_pdf_embedded(self, archive_file: File, report: Report,
                              task: Task | None=None) -> list[tuple[str, BytesIO]]:
        extracted: list[tuple[str, BytesIO]] = []
        try:
            with pymupdf.open(str(archive_file.path)) as doc:  # type: ignore[no-untyped-call]
                # needs_pass can stay true even after a successful authenticate(); trust the return value.
                locked = bool(doc.needs_pass)
                if locked and task is not None and task.password:
                    try:
                        if doc.authenticate(task.password):
                            locked = False
                    except Exception as e:
                        self.logger.warning(f'Unable to authenticate PDF with provided password: {e}')
                if locked:
                    report.add_details('Warning', 'PDF is password-protected; unable to extract embedded files.')
                    report.add_extra('no_password', True)
                    report.status = Status.NOTAPPLICABLE
                    return extracted

                for item in range(doc.embfile_count()):
                    if len(extracted) >= self.max_files_in_archive:
                        self.logger.warning(f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive, stop extracting.')
                        report.status = Status.ERROR if self.max_is_error else Status.ALERT
                        report.add_details('Warning', f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive')
                        break
                    try:
                        info = doc.embfile_info(item)
                        content = doc.embfile_get(item)
                    except Exception as e:
                        self.logger.warning(f'Unable to read embedded PDF file #{item}: {e}')
                        continue
                    if not content:
                        continue
                    if len(content) > self.max_extracted_filesize:
                        filename = self._embedded_filename(info.get('filename') if isinstance(info, dict) else None,
                                                           index=len(extracted) + 1)
                        self.logger.warning(f'Skipping file {filename}, too big ({len(content)}).')
                        report.status = Status.ERROR if self.max_is_error else Status.ALERT
                        report.add_details('Warning', f'Skipping file {filename}, too big ({len(content)}).')
                        continue
                    filename = self._embedded_filename(
                        info.get('filename') if isinstance(info, dict) else None,
                        index=len(extracted) + 1,
                    )
                    report.add_details('Embedded Files Found', str(info))
                    extracted.append((filename, BytesIO(content)))
        except Exception as e:
            self.logger.exception(e)
            report.status = Status.WARN
            report.add_details('Warning', f'Unable to extract {archive_file.path.name}: {e}.')
            return extracted

        if not extracted:
            report.status = Status.NOTAPPLICABLE
        return extracted

    def _unfold_ics(self, content: str) -> str:
        return re.sub(r'\r?\n[ \t]', '', content)

    def _ics_attach_filename(self, params: dict[str, str], index: int) -> str:
        for key in ('X-FILENAME', 'FILENAME', 'X-APPLE-FILENAME'):
            if key in params and params[key]:
                name = sanitize_filename(params[key])
                if name:
                    return name
        fmttype = params.get('FMTTYPE', '')
        if '/' in fmttype:
            subtype = fmttype.split('/', 1)[1].split(';', 1)[0].strip()
            if subtype:
                return f'embedded_{index}.{sanitize_filename(subtype) or "bin"}'
        return f'embedded_{index}.bin'

    def _extract_ics(self, archive_file: File, report: Report, dest_dir: Path,
                     task: Task | None=None) -> list[tuple[str, BytesIO]]:
        extracted: list[tuple[str, BytesIO]] = []
        if not archive_file.data:
            report.status = Status.NOTAPPLICABLE
            return extracted

        try:
            content = archive_file.data.getvalue().decode('utf-8', errors='replace')
            unfolded = self._unfold_ics(content)
        except Exception as e:
            self.logger.exception(e)
            report.status = Status.WARN
            report.add_details('Warning', f'Unable to extract {archive_file.path.name}: {e}.')
            return extracted

        index = 1
        for line in unfolded.splitlines():
            if not line.upper().startswith('ATTACH'):
                continue
            try:
                # ATTACH;PARAM=value:payload  OR  ATTACH:payload
                if ':' not in line:
                    continue
                left, value = line.split(':', 1)
                params: dict[str, str] = {}
                for part in left.split(';')[1:]:
                    if '=' not in part:
                        continue
                    key, val = part.split('=', 1)
                    params[key.upper()] = val.strip().strip('"')
                value = value.strip()
                encoding = params.get('ENCODING', '').upper()
                value_type = params.get('VALUE', '').upper()

                if encoding == 'BASE64' or value_type == 'BINARY':
                    if len(extracted) >= self.max_files_in_archive:
                        self.logger.warning(f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive, stop extracting.')
                        report.status = Status.ERROR if self.max_is_error else Status.ALERT
                        report.add_details('Warning', f'Too many files ({len(extracted)}/{self.max_files_in_archive}) in the archive')
                        break
                    # VALUE=BINARY without ENCODING is still typically base64 in practice for ATTACH.
                    payload = base64.b64decode(value, validate=False)
                    if len(payload) > self.max_extracted_filesize:
                        filename = self._ics_attach_filename(params, index)
                        self.logger.warning(f'Skipping file {filename}, too big ({len(payload)}).')
                        report.status = Status.ERROR if self.max_is_error else Status.ALERT
                        report.add_details('Warning', f'Skipping file {filename}, too big ({len(payload)}).')
                        continue
                    if not payload:
                        continue
                    filename = self._ics_attach_filename(params, index)
                    extracted.append((filename, BytesIO(payload)))
                    index += 1
                elif value_type == 'URI' or value.lower().startswith(('http://', 'https://', 'file://')):
                    if task is not None:
                        task.add_observable(value, 'url')
                    report.add_details('Warning', f'URI attachment (not downloaded): {value}')
            except Exception as e:
                self.logger.warning(f'Unable to parse ICS ATTACH line: {e}')

        if not extracted:
            # URI attachments are recorded as observables above; nothing to unpack either way.
            report.status = Status.NOTAPPLICABLE
        return extracted

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        # The files supported by dfvfs generally don't have proper mime types, so we just try it on everything.
        dfvfs_info = self.check_dfvfs(task.file, True)
        if not (task.file.is_archive or task.file.is_eml or task.file.is_msg or dfvfs_info
                or self._is_ics(task.file) or task.file.is_rtf or task.file.is_pdf
                or task.file.type in ['DOC', 'PPT', 'XLS']):
            report.status = Status.NOTAPPLICABLE
            return

        # Check if we reach the max recursivity (archive in archive in archive...)
        _curtask = task
        _cur_recurse = self.max_recurse
        _cur_max_files_in_recurse = self.max_files_in_recursive_archive
        while _cur_recurse > 0 and _cur_max_files_in_recurse > 0:
            if not _curtask.parent:
                break
            _curtask = _curtask.parent
            _cur_recurse -= 1
            _cur_max_files_in_recurse -= len(_curtask.extracted)

        if _cur_recurse <= 0:
            self.logger.warning(f'File {task.file.path.name} is too deep in the recursion chain (>{self.max_recurse}).')
            report.status = Status.ERROR if self.max_is_error else Status.ALERT
            report.add_details('Warning', f'File {task.file.path.name} is too deep in the recursion chain (>{self.max_recurse}). If you want to scan it anyway, click on Actions > Rescan file.')
            return

        if _cur_max_files_in_recurse <= 0:
            self.logger.warning(f'File {task.file.path.name} cannot be extracted, too many files (>{self.max_files_in_recursive_archive}) in the recursive archive.')
            report.status = Status.ERROR if self.max_is_error else Status.ALERT
            report.add_details('Warning', f'File {task.file.path.name} cannot be extracted, too many files (>{self.max_files_in_recursive_archive}) in the recursive archive. If you want to scan it anyway, click on Actions > Rescan file.')
            return

        if not task.user:
            raise PandoraException(f'[{task.uuid}] The task user is missing. Should not happen, but investigate if it does.')

        pandora = Pandora()

        tasks: list[Task] = []
        extracted_dir = task.file.directory / 'extracted'
        safe_create_dir(extracted_dir)
        extracted: Sequence[Path | tuple[str, BytesIO]] = []

        if task.password:
            self.passwords = [task.password]
        else:
            self.passwords = self.zip_passwords

        # Try to extract files from archive
        # TODO: Support other archive formats
        if task.file.is_archive:
            try:
                if task.file.mime_type == "application/x-7z-compressed":
                    extracted = self._extract_7z(task.file, report, extracted_dir)
                elif task.file.mime_type == "application/vnd.ms-cab-compressed":
                    extracted = self._extract_cab(task.file, report, extracted_dir)
                elif task.file.mime_type == "application/x-rar":
                    extracted = self._extract_rar(task.file, report, extracted_dir)
                elif task.file.mime_type == "application/x-bzip2":
                    extracted = self._extract_bz2(task.file, report, extracted_dir)
                elif task.file.mime_type == "application/gzip":
                    extracted = self._extract_gz(task.file, report, extracted_dir)
                elif task.file.mime_type == "application/x-tar":
                    extracted = self._extract_tar(task.file, report, extracted_dir)
                elif task.file.mime_type in ["application/x-lzma", "application/x-xz", "application/x-lzip"]:
                    extracted = self._extract_lzma(task.file, report, extracted_dir)
                elif task.file.mime_type == "application/x-iso9660-image":
                    extracted = self._extract_iso(task.file, report, extracted_dir)
                elif task.file.mime_type == "application/zip":
                    extracted = self._extract_zip(task.file, report, extracted_dir)
                    if not extracted:
                        report.clear_extras()
                        report.clear_details()
                        report.reset_status()
                        extracted = self._extract_zip(task.file, report, extracted_dir, pyzipper.AESZipFile)
                elif task.file.mime_type == "application/pandora-daa":
                    extracted = self._extract_daa(task.file, report, extracted_dir)
                else:
                    raise PandoraException(f'Unsupported mimetype: {task.file.mime_type}')
            except PathTransversal as e:
                self.logger.warning(f'Attempted to trigger a path transversal: {e}')
                report.status = Status.ALERT
                report.add_details('Warning', 'Archive attempted a path transversal.')
                extracted = []
            except BaseException as e:
                report.status = Status.WARN
                report.add_details('Warning', f'Unable to extract {task.file.path.name}: {e}.')
                report.add_extra('no_password', True)
                extracted = []
                self.logger.exception(e)

        # Try to extract attachments from EML file
        if task.file.is_eml:
            if not task.file.eml_data or 'attachment' not in task.file.eml_data or not task.file.eml_data['attachment']:
                report.status = Status.NOTAPPLICABLE
            else:
                try:
                    extracted = self.extract_eml(task.file.eml_data)
                except Exception as e:
                    self.logger.exception(e)

        elif task.file.is_msg:
            if not task.file.msg_data or not task.file.msg_data.attachments:
                report.status = Status.NOTAPPLICABLE
            else:
                try:
                    extracted = self.extract_msg(task.file.msg_data)
                except Exception as e:
                    self.logger.exception(e)

        elif dfvfs_info:
            # this is a dfvfs supported file
            try:
                extracted = self.extract_with_dfvfs(task.file, report)
            except Exception as e:
                self.logger.exception('dfVFS dislikes it.')
                report.status = Status.WARN
                report.add_details('Warning', f'Unable to process with dfVFS {task.file.path.name}: {e}.')

        elif task.file.type in ['DOC', 'PPT', 'XLS']:
            # check if the file is encrypted
            try:
                extracted = self._extract_encrypted_office(task.file, report, extracted_dir)
            except Exception as e:
                # Minimal / unusual Office containers can make msoffcrypto raise; still try embeddings.
                self.logger.warning(f'Unable to check office encryption for {task.file.path.name}: {e}')
                report.status = Status.NOTAPPLICABLE
                extracted = []
            if report.status == Status.NOTAPPLICABLE:
                # Not encrypted: look for embedded objects instead.
                report.reset_status()
                try:
                    extracted = self._extract_office_embedded(task.file, report, extracted_dir)
                except Exception as e:
                    self.logger.exception(e)
                    report.status = Status.WARN
                    report.add_details('Warning', f'Unable to extract {task.file.path.name}: {e}.')
                    extracted = []

        elif task.file.is_rtf:
            try:
                extracted = self._extract_rtf(task.file, report, extracted_dir)
            except Exception as e:
                self.logger.exception(e)
                report.status = Status.WARN
                report.add_details('Warning', f'Unable to extract {task.file.path.name}: {e}.')
                extracted = []

        elif self._is_ics(task.file):
            try:
                extracted = self._extract_ics(task.file, report, extracted_dir, task)
            except Exception as e:
                self.logger.exception(e)
                report.status = Status.WARN
                report.add_details('Warning', f'Unable to extract {task.file.path.name}: {e}.')
                extracted = []

        elif task.file.is_pdf:
            try:
                extracted = self._extract_pdf_embedded(task.file, report, task)
            except Exception as e:
                self.logger.exception(e)
                report.status = Status.WARN
                report.add_details('Warning', f'Unable to extract {task.file.path.name}: {e}.')
                extracted = []

        if not extracted and report.status != Status.NOTAPPLICABLE:
            report.status = Status.WARN
            report.add_details('Warning', 'Nothing to extract.')

        for ef in extracted:
            if isinstance(ef, Path):
                filename = ef.name
                with ef.open('rb') as f:
                    sample = BytesIO(f.read())
            else:
                filename, sample = ef
            new_task = Task.new_task(user=task.user, sample=sample,
                                     filename=filename,
                                     disabled_workers=task.disabled_workers,
                                     parent=task,
                                     password=task.password or None)
            pandora.add_extracted_reference(task, new_task)
            pandora.enqueue_task(new_task)
            tasks.append(new_task)

        shutil.rmtree(extracted_dir)

        if not tasks and not report.status == Status.NOTAPPLICABLE:
            # Nothing was extracted
            report.status = Status.WARN
            report.add_details('Warning', 'Looks like the archive is empty (?). This is suspicious.')
        elif report.status not in [Status.ERROR, Status.WARN, Status.ALERT, Status.OVERWRITE]:
            # wait for all the workers to finish, or have one of them raising an ALERT
            try:
                while not all(t.workers_done for t in tasks):
                    for t in tasks:
                        # If any of the task is marked as ALERT or OVERWRITE, we can quit.
                        if t.workers_done and t.status >= Status.ALERT:
                            report.add_details('Warning', 'There are suspicious files in this archive, click on the "Extracted" tab for more.')
                            break
                    time.sleep(1)
            except TimeoutError:
                # The extracted tasks can take a very long time, force the status in that case
                report.add_details('Warning', 'The extracted task(s) took too long, click on the "Extracted" tab for more.')
                report.status = Status.OVERWRITE
            else:
                all_status = [t.status for t in tasks if t.workers_done]
                if all_status:
                    report.status = max(all_status)
