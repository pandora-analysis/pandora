import hashlib
import importlib
import logging
import re
import shutil
import sys
import traceback

from datetime import datetime, timezone
from functools import cached_property, lru_cache
from io import BytesIO
from pathlib import Path
from typing import Optional, List, Union, Dict, cast, Set, Tuple
from uuid import uuid4
from zipfile import ZipFile

import exiftool  # type: ignore
import fitz  # type: ignore
import magic
import pikepdf

from oletools.msodde import process_maybe_encrypted  # type: ignore
from PIL import Image, ImageDraw, ImageFont  # type: ignore
from pymisp import MISPEvent, MISPObject
from pymisp.tools import make_binary_objects, FileObject
from svglib.svglib import svg2rlg  # type: ignore
from reportlab.graphics import renderPDF  # type: ignore
import textract  # type: ignore
from weasyprint import HTML, default_url_fetcher  # type: ignore

from eml_parser import EmlParser
from extract_msg import openMsg, MessageBase

from .default import get_config
from .exceptions import Unsupported, NoPreview, InvalidPandoraObject
from .helpers import make_bool, make_bool_for_redis
from .storage_client import Storage
from .text_parser import TextParser


@lru_cache
def dirty_load_unoconverter():
    sys.path.append('/usr/lib/python3/dist-packages')
    module = importlib.import_module('unoserver.converter')
    sys.path.pop()
    return module


def html_to_pdf(source: Union[str, bytes, Path], dest: str) -> None:

    def disable_fetch_weasyprint(url: str, timeout=10, ssl_context=None):
        raise ValueError(f'Fetching is disabled, ignoring: {url}')

    if isinstance(source, str):
        html = HTML(string=source, url_fetcher=default_url_fetcher if get_config('generic', 'weasyprint_fetch_ressources') else disable_fetch_weasyprint)
    elif isinstance(source, bytes):
        html = HTML(file_obj=BytesIO(source), url_fetcher=default_url_fetcher if get_config('generic', 'weasyprint_fetch_ressources') else disable_fetch_weasyprint)
    elif isinstance(source, Path):
        html = HTML(source, url_fetcher=default_url_fetcher if get_config('generic', 'weasyprint_fetch_ressources') else disable_fetch_weasyprint)
    html.write_pdf(dest)


def office_to_pdf(source: Union[Path, bytes], dest: str) -> None:
    converter = dirty_load_unoconverter().UnoConverter()
    try:
        if isinstance(source, Path):
            converter.convert(source, outpath=dest)
        elif isinstance(source, bytes):
            converter.convert(indata=source, outpath=dest)
    except AttributeError as e:
        # Happens when the file is password protected, might be happening on other occasions
        raise Unsupported(f"The Office document is probably password protected, this feature isn't supported yet - Error message: {e}.") from e


class File:
    MIME_TYPE_EQUAL: Dict[str, List[str]] = {
        'application/zip': ['ARC', 'zip'],
        'application/x-bzip2': ['ARC', 'bz2'],
        'application/java-archive': ['ARC', 'jar'],
        'application/x-tar': ['ARC', 'tar'],
        'application/gzip': ['ARC', 'gz'],
        'application/x-lzma': ['ARC', 'lzma'],
        'application/x-xz': ['ARC', 'lzma'],
        'application/x-lz': ['ARC', 'lzma'],
        'application/x-7z-compressed': ['ARC', '7z'],
        'application/x-rar': ['ARC', 'rar'],
        'application/x-iso9660-image': ['ARC', 'iso'],
        'application/vnd.ms-cab-compressed': ['ARC', 'cab'],
        'text/css': ['CSS', 'css'],
        'text/csv': ['CSV', 'csv'],
        'application/msword': ['DOC', 'doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['DOC', 'docx'],
        'application/vnd.oasis.opendocument.text': ['ODF', 'odt'],
        'application/vnd.oasis.opendocument.text-template': ['ODF', 'ott'],
        'application/vnd.oasis.opendocument.text-web': ['ODF', 'oth'],
        'application/vnd.oasis.opendocument.text-master': ['ODF', 'odm'],
        'application/vnd.oasis.opendocument.spreadsheet': ['ODF', 'ods'],
        'application/vnd.oasis.opendocument.spreadsheet-template': ['ODF', 'ots'],
        'application/vnd.oasis.opendocument.chart': ['ODF', 'odc'],
        'application/vnd.oasis.opendocument.presentation': ['ODF', 'odp'],
        'application/vnd.oasis.opendocument.presentation-template': ['ODF', 'otp'],
        'application/vnd.oasis.opendocument.graphics': ['ODF', 'odg'],
        'application/vnd.oasis.opendocument.graphics-template': ['ODF', 'otg'],
        'application/vnd.oasis.opendocument.formula': ['ODF', 'otf'],
        'application/vnd.oasis.opendocument.database': ['ODF', 'odb'],
        'application/vnd.oasis.opendocument.image': ['ODF', 'odi'],
        'application/vnd.openofficeorg.extension': ['ODF', 'oxt'],
        'message/rfc822': ['EML', 'eml'],
        'text/html': ['HTM', 'html'],
        'application/xhtml+xml': ['HTM', 'html'],
        'image/bmp': ['IMG', 'bmp'],
        'image/gif': ['IMG', 'gif'],
        'image/x-icon': ['IMG', 'ico'],
        'image/jpeg': ['IMG', 'jpg'],
        'image/png': ['IMG', 'png'],
        'image/svg+xml': ['SVG', 'svg'],
        'image/tiff': ['IMG', 'tiff'],
        'image/webp': ['IMG', 'webp'],
        'application/vnd.ms-outlook': ['MSG', 'msg'],
        'application/pdf': ['PDF', 'pdf'],
        'application/vnd.ms-powerpoint': ['PPT', 'ppt'],
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['PPT', 'pptx'],
        'application/mspowerpoint': ['PPT', 'ppt'],
        'application/powerpoint': ['PPT', 'ppt'],
        'application/x-mspowerpoint': ['PPT', 'ppt'],
        'text/rtf': ['RTF', 'rtf'],
        'application/x-javascript': ['JSC', 'js'],
        'application/javascript': ['JSC', 'js'],
        'text/javascript': ['JSC', 'js'],
        'text/plain': ['TXT', 'txt'],
        'text/xml': ['TXT', 'xml'],
        'text/x-php': ['TXT', 'php'],
        'application/vnd.ms-excel': ['XLS', 'xls'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['XLS', 'xlsx']
    }

    TYPE_EXTENSIONS: Dict[str, Set[str]] = {
        'ARC': {'.zip', '.tar', '.gz', '.bz2', '.bz', '.rar', '.7z', 'lzma'},
        'BIN': {'.bin', '.iso'},
        'CSS': {'.css'},
        'CSV': {'.csv'},
        'DOC': {'.doc', '.docx', '.odt'},
        'EML': {'.eml'},
        'EXE': {'.exe', '.dll'},
        'HTM': {'.htm', '.html', '.xht', '.xhtml'},
        'IMG': {'.png', '.gif', '.bmp', '.jpg', '.jpeg', '.ico'},
        'JSC': {'.js'},
        'MSG': {'.msg'},
        'PDF': {'.pdf'},
        'PPT': {'.ppt', '.pptx'},
        'RTF': {'.rtf'},
        'SCR': {'.vb', '.vbs', '.php', '.ps1'},
        'TXT': {'.txt'},
        'XLS': {'.xls', '.xlsx', '.ods'}
    }
    TYPE_ICONS: Dict[str, str] = {
        'ARC': 'file-zip',
        'BIN': 'file-binary',
        'CSS': 'filetype-css',
        'CSV': 'file-excel',
        'DOC': 'file-word',
        'EML': 'envelope',
        'EXE': 'filetype-exe',
        'HTM': 'filetype-html',
        'IMG': 'filetype-jpg',
        'JSC': 'filetype-js',
        'MSG': 'envelope',
        'PDF': 'file-pdf',
        'PPT': 'file-ppt',
        'RTF': 'file-word',
        'SCR': 'file-code',
        'TXT': 'filetype-txt',
        'XLS': 'file-excel',
    }
    TYPE_INFO: Dict[str, str] = {
        'ARC': 'Archive file',
        'BIN': 'Binary file',
        'CSS': 'Cascading Style Sheet',
        'CSV': 'MS Excel document',
        'DOC': 'MS Word document',
        'EML': 'Message file',
        'EXE': 'Executable file',
        'HTM': 'HTML file',
        'IMG': 'Image file',
        'JSC': 'JavaScript file',
        'MSG': 'Microsoft Outlook message',
        'PDF': 'PDF file',
        'PPT': 'MS PowerPoint document',
        'RTF': 'Rich Text Format document',
        'SCR': 'Script file',
        'TXT': 'Text file',
        'XLS': 'MS Excel document',
    }
    OLETOOLS_TYPES: Set[str] = {'DOC', 'PPT', 'RTF', 'XLS'}
    UNOCONV_TYPES: Set[str] = {'CSS', 'DOC', 'JSC', 'PPT', 'RTF', 'TXT', 'XLS'}
    FOLDER_MODE = 0o2775
    FILE_MODE = 0o0664
    SUBPROCESS_TIMEOUT: int = 30

    DATA_CHARSETS: List[str] = [
        'utf8',
        'latin1',
        'ascii'
    ]

    @classmethod
    def new_file(cls, filepath: Path, filename: str) -> 'File':
        file = cls(filepath, original_filename=filename)
        file.store()
        return file

    def __init__(self, path: Union[Path, str], original_filename: str, uuid: Optional[str]=None, *,
                 save_date: Optional[Union[str, datetime]]=None,
                 md5: Optional[str]=None, sha1: Optional[str]=None, sha256: Optional[str]=None,
                 size: Optional[Union[int, str]]=None,
                 mime_type: Optional[str]=None,
                 deleted: Union[bool, int, str]=False):
        """
        Generate File object.
        :param path: absolute file path
        :param uuid: file uuid
        :param original_filename: original filename as uploaded
        :param save_date: file save date
        :param md5: MD5 signature of file content
        :param sha1: SHA1 signature of file content
        :param sha256: SHA256 signature of file content
        :param size: file size in bytes
        :param deleted: whether if the file has been deleted
        """

        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.storage = Storage()

        # NOTE: they're alny used by the text conversion method, is it expected?
        self.error = ''
        self.error_trace = ''

        if isinstance(path, str):
            self.path: Path = Path(path)
        else:
            self.path = path

        if not uuid:
            self.uuid = str(uuid4())
        else:
            self.uuid = uuid
        self.original_filename: str = original_filename
        self.deleted: bool = make_bool(deleted)

        if not self.path.exists():
            self.deleted = True

        self._md5: Optional[str] = None
        self._sha1: Optional[str] = None
        self._sha256: Optional[str] = None
        self._text: Optional[str] = None
        self._size: int = 0
        self._mime_type: str = ''
        if self.deleted:
            # Hashes should have been stored and must be present in the parameter
            # If the file is still on disk, they're initialized ondemand
            if not md5 or not sha1 or not sha256:
                raise InvalidPandoraObject(f'The hashes should have been initialized. md5: {md5}, sha1: {sha1}, sha256: {sha256}')
            if not size:
                raise InvalidPandoraObject(f'The size {size} should have been initialized.')
            if not mime_type:
                self.mime_type = 'Unknown'
            else:
                self.mime_type = mime_type

            self.md5 = md5
            self.sha1 = sha1
            self.sha256 = sha256
            self.size = int(size)

        if save_date:
            if isinstance(save_date, str):
                self.save_date = datetime.fromisoformat(save_date)
                self.save_date = self.save_date.astimezone(timezone.utc)
            else:
                self.save_date = save_date
        else:
            self.save_date = datetime.now(timezone.utc)

    def store(self) -> None:
        self.storage.set_file(self.to_dict)

    def convert(self) -> None:
        if self.is_unoconv_concerned:
            office_to_pdf(self.path, f'{self.path}.pdf')

        if self.is_svg:
            drawing = svg2rlg(self.path)
            renderPDF.drawToFile(drawing, f'{self.path}.pdf')

        if self.is_image:
            image = Image.open(self.path)
            im = image.convert('RGB')
            im.save(f'{self.path}.pdf')

        if self.is_html:
            html_to_pdf(self.path, f'{self.path}.pdf')

        if self.msg_data:
            if self.msg_data.body:
                office_to_pdf(self.msg_data.body.encode(), f'{self.path}_body_txt.pdf')

            try:
                if self.msg_data.htmlBody:
                    html_to_pdf(self.msg_data.htmlBody, f'{self.path}_body_html.pdf')
            except Exception as e:
                self.logger.warning(f'Unable to generate a preview of the HTML body: {e}')

        if self.eml_data:
            # get all content -> make it a PDF
            if 'body' in self.eml_data:
                for i, body_part in enumerate(self.eml_data['body']):
                    if 'content_type' in body_part and self.MIME_TYPE_EQUAL.get(body_part['content_type']):
                        body_part_type = self.MIME_TYPE_EQUAL[body_part['content_type']][0]
                        if body_part_type == 'HTM':
                            html_to_pdf(body_part['content'], f'{self.path}_body_{i}.pdf')
                        elif body_part_type == 'TXT':
                            converter = dirty_load_unoconverter().UnoConverter()
                            converter.convert(indata=body_part['content'].encode(), outpath=f'{self.path}_body_{i}.pdf')
                        else:
                            print('Unexpected body type:', body_part_type)
                    else:
                        # Assume txt
                        converter = dirty_load_unoconverter().UnoConverter()
                        converter.convert(indata=body_part['content'].encode(), outpath=f'{self.path}_body_{i}.pdf')

    def make_previews(self) -> None:
        if self.is_pdf:
            to_convert = [self.path]
        elif self.is_unoconv_concerned or self.is_html or self.is_image or self.is_svg:
            to_convert = [Path(f'{self.path}.pdf')]
        elif self.eml_data:
            to_convert = list(self.directory.glob(f'{self.path.name}_body_*.pdf'))
        elif self.msg_data and self.msg_data.body:
            to_convert = list(self.directory.glob(f'{self.path.name}_body_*.pdf'))
        else:
            raise NoPreview('Preview not supported for this file format')

        for i, p in enumerate(to_convert):
            doc = fitz.open(p)
            if doc.needs_pass:
                raise Unsupported("The PDF is password protected, this feature isn't supported yet.")
            digits = len(str(doc.page_count))
            for page in doc:
                pix = page.get_pixmap()
                img_name = self.directory / f"preview-{i}-{page.number:0{digits}}.png"
                pix.save(img_name)

    @property
    def previews(self) -> List[Path]:
        return sorted(self.directory.glob('preview-*.png'))

    @property
    def previews_archive(self) -> Optional[Path]:
        if not self.previews:
            return None
        archive_file = self.directory / 'previews.zip'
        if not archive_file.exists():
            with ZipFile(archive_file, 'w') as zipObj:
                for preview in self.previews:
                    zipObj.write(preview, arcname=preview.name)

        return archive_file

    @property
    def directory(self) -> Path:
        return self.path.parent

    @cached_property
    def data(self) -> Optional[BytesIO]:
        """
        Property to get file content in binary format.
        :return (BytesIO|None): file content or None if file is not reachable
        """
        if not self.path.exists():
            return None
        with self.path.open('rb') as f:
            return BytesIO(f.read())

    @property
    def to_dict(self) -> Dict[str, Union[str, int]]:
        return {
            'path': str(self.path),
            'uuid': self.uuid,
            'md5': self.md5,
            'sha1': self.sha1,
            'sha256': self.sha256,
            'size': self.size,
            'mime_type': self.mime_type,
            'original_filename': self.original_filename,
            'save_date': self.save_date.isoformat(),
            'deleted': make_bool_for_redis(self.deleted)
        }

    @property
    def to_web(self) -> Dict[str, Union[str, int, List[str]]]:
        to_return = cast(Dict[str, Union[str, int, List[str]]], self.to_dict)
        to_return['previews'] = [str(path) for path in self.previews]
        return to_return

    def __str__(self) -> str:
        return str(self.path)

    @property
    def md5(self) -> str:
        """
        Property to get hexadecimal form of file content MD5 signature.
        :return (str|None): hexadecimal string or None if file is not reachable
        """
        if self._md5 is None and self.data:
            self._md5 = hashlib.md5(self.data.getvalue()).hexdigest() if self.data is not None else None  # nosec B324, B303
        return self._md5 if self._md5 else ''

    @md5.setter
    def md5(self, value: str):
        self._md5 = value  # nosec B303

    @property
    def sha1(self) -> str:
        """
        Property to get hexadecimal form of file content SHA1 signature.
        :return (str): hexadecimal string or None if file is not reachable
        """
        if self._sha1 is None and self.data:
            self._sha1 = hashlib.sha1(self.data.getvalue()).hexdigest() if self.data is not None else None  # nosec B324, B303
        return self._sha1 if self._sha1 else ''

    @sha1.setter
    def sha1(self, value: str):
        self._sha1 = value  # nosec B303

    @property
    def sha256(self) -> str:
        """
        Property to get hexadecimal form of file content SHA256 signature.
        :return (str): hexadecimal string or None if file is not reachable
        """
        if self._sha256 is None and self.data:
            self._sha256 = hashlib.sha256(self.data.getvalue()).hexdigest() if self.data is not None else None
        return self._sha256 if self._sha256 else ''

    @sha256.setter
    def sha256(self, value: str):
        self._sha256 = value

    @property
    def mime_type(self) -> str:
        if not self._mime_type and self.data:
            self._mime_type = magic.from_buffer(self.data.getvalue(), mime=True)
        return self._mime_type

    @mime_type.setter
    def mime_type(self, mime_type: str):
        self._mime_type = mime_type

    def delete(self) -> None:
        """
        Delete from disk uploaded file and all other files in the same directory
        """
        # NOTE: Make sure all the settings (especially hashes and size) we want to store are initialized
        self.to_dict  # pylint: disable=W0104
        if self.directory and self.directory.exists():
            shutil.rmtree(self.directory, ignore_errors=True)
        self.deleted = True
        self.store()

    @property
    def size(self) -> int:
        """
        Return size of file content
        :return: file content size
        """
        if not self._size and self.data:
            self._size = self.data.getbuffer().nbytes
        return self._size

    @size.setter
    def size(self, value: int):
        self._size = value

    @cached_property
    def type(self) -> str:
        """
        Guess file type from mimeType or extension.
        :return (str): file type or None if file is not reachable
        """
        # Guess type from mime-type
        if self.mime_type in self.MIME_TYPE_EQUAL:
            return self.MIME_TYPE_EQUAL[self.mime_type][0]

        # Guess type from extension
        for type_, extensions in self.TYPE_EXTENSIONS.items():
            if self.path.suffix in extensions:
                return type_

        # Default type to BIN (??)
        return 'BIN'

    @cached_property
    def _extension_for_textract(self) -> Optional[str]:
        """
        Textract expects a specific list of extensions, sanitize the one we have.
        :return (str): file type or None if file is not reachable
        """
        # Guess extension from mime-type
        for mime_type, p_type in self.MIME_TYPE_EQUAL.items():
            if self.mime_type == mime_type:
                return p_type[1]

        # Guess type from extension
        if self.path.suffix:
            return self.path.suffix

        # Default extension to None
        return None

    @cached_property
    def text(self) -> str:
        """
        Property to get file text content.
        :return: text content
        """
        try:
            if self.is_html or self.is_eml or self.is_txt:
                if self.data:
                    return self.data.getvalue().decode(errors='replace')
                return ''
            # Use of textract module for all file types
            return textract.process(self.path, extension=self._extension_for_textract).decode(errors='replace')

        except textract.exceptions.ShellError:
            if self.is_doc:
                # Specific error when doc file is too small for some obscure reason
                # TODO try something with catdoc
                pass
        except textract.exceptions.ExtensionNotSupported:
            # Extension not supported by textract
            pass
        except BaseException as e:
            self.error = 'Text conversion error'
            self.error_trace = f'{e}\n{traceback.format_exc()}'
        return ''

    @cached_property
    def text_preview(self) -> BytesIO:
        max_width = 2000
        max_height = 5000
        try:
            font = ImageFont.load_default()
            text_width = 0
            lines = self.text.splitlines()
            for line in lines:
                w, text_height = font.getsize(line.encode('latin-1', 'ignore'))
                if w > text_width:
                    text_width = w
            text_height = text_height * len(lines)
            out = Image.new("L", (text_width if text_width < max_width else max_width,
                                  text_height if text_height < max_height else max_height), 255)
            d = ImageDraw.Draw(out)
            d.text((10, 10), self.text.encode('latin-1', 'ignore'), font=font, fill=0)
            to_return = BytesIO()
            out.save(to_return, 'PNG', optimize=True)
            to_return.seek(0)
        except Exception as e:
            # Cannot build preview
            out = Image.new("L", (500, 50), 255)
            d = ImageDraw.Draw(out)
            d.multiline_text((5, 5), f"Unable to generate text preview:\n{e}", fill=0)
            to_return = BytesIO()
            out.save(to_return, 'PNG', optimize=True)
            to_return.seek(0)
        return to_return

    @property
    def observables(self) -> Dict[str, Set[str]]:
        """
        Extract observables from file content
        """
        observables: Dict[str, Set[str]] = {'ip-dst': set(), 'iban': set(), 'url': set(), 'hostname': set(), 'email': set()}

        if self.eml_data:
            for body in self.eml_data['body']:
                if 'ip' in body:
                    observables['ip-dst'].update(body['ip'])
                if 'uri' in body:
                    observables['url'].update(body['uri'])
                if 'email' in body:
                    observables['email'].update(body['email'])
        elif self.is_pdf and self.data:
            try:
                with pikepdf.open(self.data) as pdf_file:
                    for page in pdf_file.pages:
                        if not page:
                            continue
                        try:
                            if not page.get("/Annots"):
                                continue
                        except Exception as e:
                            # this call can trigger an exception
                            self.logger.warning(f'Unable to process a page: {e}')
                            continue
                        for annots in page["/Annots"]:  # type: ignore
                            if not annots.get("/A"):
                                continue
                            uri = annots["/A"].get("/URI")
                            if uri is not None:
                                observables['url'].add(str(uri))
            except Exception as e:
                self.logger.warning(f'Unable to process PDF in file {self.uuid}: {e}')
        elif self.is_oletools_concerned:
            try:
                oid = process_maybe_encrypted(self.path)
                # This call returns a string. If we're lucky, it's going to be one indicator/line
                # and we can try to add them in the proper type
                for line in oid.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    splitted_line = line.split(' ', 1)
                    if len(splitted_line) == 2 and splitted_line[0] == "HYPERLINK":
                        url = re.findall('"(.*)" .*', splitted_line[1])
                        if url:
                            observables['url'].add(url[0])
                    else:
                        self.logger.warning(f'Unknown indicator: {line}')
            except Exception as e:
                self.logger.warning(f'Unable to process OLE file: {e}')

        # Try to extract observables from text
        if self.text:
            tp = TextParser(self.text.replace('\r\n', '\n'))
            observables['ip-dst'].update(tp.ips)
            observables['iban'].update(tp.ibans)
            observables['url'].update(tp.urls)
            observables['hostname'].update(tp.hostnames)
            observables['email'].update(tp.emails)

        return observables

    @cached_property
    def eml_data(self) -> Optional[Dict]:
        if not self.is_eml:
            return None
        ep = EmlParser(include_raw_body=True, include_attachment_data=True)
        return ep.decode_email(eml_file=self.path)

    @cached_property
    def msg_data(self) -> Optional[MessageBase]:
        # NOTE: the msg file can be other things than a message.
        # See https://github.com/TeamMsgExtractor/msg-extractor/blob/master/extract_msg/utils.py
        if not self.is_msg:
            return None
        msg = openMsg(self.path, delayAttachments=True)
        if not issubclass(msg, MessageBase):
            raise Unsupported(f'msg file must be a message, other formats are not supported yet. Type: {type(msg)}')
        return msg

    @cached_property
    def metadata(self) -> Dict[str, str]:
        """
        Get file metadata.
        :return (dict): metadata
        """
        metadata: Dict[str, str] = {}
        if not self.path.exists():
            return {}
        exiftool_path = get_config('generic', 'exiftool_path')
        if not exiftool_path or not Path(exiftool_path).exists():
            exiftool_path = None
        try:
            with exiftool.ExifToolHelper(executable=exiftool_path) as et:
                for key, value in et.get_metadata([str(self.path)])[0].items():
                    if any(key.lower().startswith(word) for word in ('sourcefile', 'exiftool:', 'file:')):
                        continue
                    key = key.split(':')[-1]
                    key = re.sub(r"([A-Z]+)([A-Z][a-z])", r'\1 \2', key)
                    key = re.sub(r"([a-z\d])([A-Z])", r'\1 \2', key)
                    metadata[key] = value
        except Exception as e:
            self.logger.critical(f'Unable to use exiftool, probably because the version is too old: {e}')
            metadata = {}
        return metadata

    @property
    def icon(self) -> Optional[str]:
        """
        Get web icon for file type.
        :return (str|None): icon name or None if unknown type
        """
        return self.TYPE_ICONS.get(self.type)

    @property
    def info(self) -> Optional[str]:
        """
        Get type info for web display.
        :return (str|None): type info or None if unknown type
        """
        return self.TYPE_INFO.get(self.type)

    @property
    def is_oletools_concerned(self) -> bool:
        """
        Whether this file is concerned by oletools scans.
        :return (bool): boolean
        """
        return self.type in self.OLETOOLS_TYPES

    @property
    def is_unoconv_concerned(self) -> bool:
        """
        Whether this file is concerned by unoconv.
        :return (bool): boolean
        """
        return self.type in self.UNOCONV_TYPES

    @property
    def is_archive(self) -> bool:
        """
        Whether this file is an archive.
        :return (bool): boolean
        """
        return self.type == 'ARC'

    @property
    def is_rtf(self) -> bool:
        """
        Whether this file is a RTF.
        :return (bool): boolean
        """
        return self.type == 'RTF'

    @property
    def is_pdf(self) -> bool:
        """
        Whether this file is a PDF.
        :return (bool): boolean
        """
        return self.type == 'PDF'

    @property
    def is_eml(self) -> bool:
        """
        Whether this file is an EML.
        :return (bool): boolean
        """
        return self.type == 'EML'

    @property
    def is_msg(self) -> bool:
        """
        Whether this file is a MSG.
        :return (bool): boolean
        """
        return self.type == 'MSG'

    @property
    def is_txt(self) -> bool:
        """
        Whether this file is a TXT.
        :return (bool): boolean
        """
        return self.type == 'TXT'

    @property
    def is_doc(self) -> bool:
        """
        Whether this file is a DOC.
        :return (bool): boolean
        """
        return self.type == 'DOC'

    @property
    def is_odf(self) -> bool:
        """
        Whether this file is an OpenDocument.
        :return (bool): boolean
        """
        return self.type == 'ODF'

    @property
    def is_svg(self) -> bool:
        """
        Whether this file is an SVG.
        :return (bool): boolean
        """
        return self.type == 'SVG'

    @property
    def is_image(self) -> bool:
        """
        Whether this file is an image.
        :return (bool): boolean
        """
        return self.type == 'IMG'

    @property
    def is_html(self) -> bool:
        """
        Whether this file is an HTML.
        :return (bool): boolean
        """
        return self.type == 'HTM'

    @property
    def is_script(self) -> bool:
        """
        Whether this file is a script.
        :return (bool): boolean
        """
        return self.type == 'SCR'

    @property
    def is_javascript(self) -> bool:
        """
        Whether this file is a javascript.
        :return (bool): boolean
        """
        return self.type == 'JSC'

    @property
    def is_executable(self) -> bool:
        """
        Whether this file is an exe.
        :return (bool): boolean
        """
        return self.type == 'EXE'

    def misp_export(self) -> Optional[Tuple[FileObject, Optional[MISPObject], Optional[List[MISPObject]]]]:
        try:
            # Currently only extract indicators from binary files (PE, ELF, MachO)
            return make_binary_objects(pseudofile=self.data, filename=self.original_filename)
        except Exception:
            traceback.print_exc()
        return None

    def populate_misp_event(self, event: MISPEvent) -> None:
        objs = self.misp_export()
        if not objs:
            return
        fo, peo, seos = objs

        if seos:
            for s in seos:
                event.add_object(s)
        if peo:
            if hasattr(peo, 'certificates') and hasattr(peo, 'signers'):
                for c in peo.certificates:  # type: ignore
                    event.add_object(c)
                for s in peo.signers:  # type: ignore
                    event.add_object(s)
                del peo.certificates  # type: ignore
                del peo.signers  # type: ignore
            if hasattr(peo, 'sections'):
                del peo.sections  # type: ignore
            event.add_object(peo)
        if fo:
            event.add_object(fo)
