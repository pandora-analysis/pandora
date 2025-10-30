from __future__ import annotations

import base64
import functools
import os
import shutil
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
from extract_msg import MSGFile
from hachoir.stream import StringInputStream  # type: ignore[import-untyped]
from hachoir.parser.archive import CabFile  # type: ignore[import-untyped]
import py7zr
import py7zr.io
import pycdlib
from pycdlib.facade import PyCdlibJoliet, PyCdlibUDF, PyCdlibRockRidge, PyCdlibISO9660
import pyzipper  # type: ignore[import-untyped]
import rarfile  # type: ignore[import-untyped]
from tzlocal import get_localzone_name

from ..default import safe_create_dir, PandoraException
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

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int | None=None,
                 status_in_report: dict[str, str] | None=None,
                 **options: dict[str, str | int | bool]) -> None:
        super().__init__(module, worker_id, cache, timeout, loglevel, status_in_report, **options)
        self.max_extracted_filesize = self.max_extracted_filesize_in_mb * 1000000

        # We might be getting integers from the config file
        self.zip_passwords = [str(pwd) for pwd in self.zip_passwords]

    @property
    def passwords(self) -> list[str]:
        return self._passwords

    @passwords.setter
    def passwords(self, passwords: list[str]) -> None:
        self._passwords = passwords

    def _extract_iso(self, archive_file: File, report: Report, dest_dir: Path) -> list[Path]:
        iso = pycdlib.PyCdlib()  # type: ignore[attr-defined]
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
                    with filepath.open('wb') as f:
                        f.write(extracted.getvalue())
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
        with new_file_path.open('wb') as f:
            f.write(data)  # write an uncompressed file
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
                tar.extract(tarinfo, dest_dir)
                file_path = dest_dir / tarinfo.name
                extracted_files.append(Path(file_path))
        return extracted_files

    def _extract_cab(self, archive_file: File, report: Report, dest_dir: Path) -> list[Path]:
        extracted_files: list[Path] = []
        # Code from https://github.com/vstinner/hachoir/issues/65#issuecomment-866965090
        if not archive_file.data:
            return extracted_files
        cab = CabFile(StringInputStream(archive_file.data.getvalue()))
        cab["folder_data[0]"].getSubIStream()
        folder_data = BytesIO(cab["folder_data[0]"].uncompressed_data)
        for file_number, file in enumerate(cab.array("file")):
            if file_number >= self.max_files_in_archive:
                self.logger.warning(f'Too many files ({file_number}/{self.max_files_in_archive}) in the archive, stop extracting.')
                report.status = Status.ERROR if self.max_is_error else Status.ALERT
                report.add_details('Warning', f'Too many files ({file_number}/{self.max_files_in_archive}) in the archive')
                break
            if file["filesize"].value >= self.max_extracted_filesize:
                self.logger.warning(f'File {archive_file.path.name} too big ({file["filesize"].value}).')
                report.status = Status.ERROR if self.max_is_error else Status.ALERT
                report.add_details('Warning', f'File {archive_file.path.name} too big ({file["filesize"].value}).')
                continue
            file_path = dest_dir / file["filename"].value
            with file_path.open('wb') as f:
                f.write(folder_data.read(file["filesize"].value))
            extracted_files.append(Path(file_path))
        return extracted_files

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
        with new_file_path.open('wb') as f:
            f.write(data)  # write an uncompressed file
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
        with new_file_path.open('wb') as f:
            f.write(data)  # write an uncompressed file
        return [new_file_path]

    @overload
    def check_dfvfs(self, submitted_file: File, check_only: Literal[True]) -> bool:
        ...

    @overload
    def check_dfvfs(self, submitted_file: File, check_only: Literal[False]) -> list[tuple[PathSpec, tsk_volume_system.TSKVolumeSystem]]:
        ...

    @dfvfs_wrapper  # type: ignore[misc]
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

    @dfvfs_wrapper  # type: ignore[misc]
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
                raw += zlib.decompress(packeddata, -zlib.MAX_WBITS)
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
        raw = unpackdata(header, chunklist, pseudo_file.getvalue())
        if len(raw) != int.from_bytes(header['isosize'], byteorder='little', signed=False):
            self.logger.warning('Potentially invalid ISO file length')
        return [('internal_iso_in_daa.iso', BytesIO(raw))]

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        # The files supported by dfvfs generally don't have proper mime types, so we just try it on everything.
        dfvfs_info = self.check_dfvfs(task.file, True)
        if not (task.file.is_archive or task.file.is_eml or task.file.is_msg or dfvfs_info):
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

        if _cur_recurse < 0:
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

        # Try to extract files from archive
        # TODO: Support other archive formats
        if task.file.is_archive:
            if task.password:
                self.passwords = [task.password]
            else:
                self.passwords = self.zip_passwords
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
                                     parent=task)
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
