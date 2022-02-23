#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import re

from collections import defaultdict
from datetime import datetime
from typing import List, Set, Tuple, Dict

from oletools import oleid, ooxml  # type: ignore
from oletools.ftguess import FTYPE, CONTAINER, FType_Generic_OLE, FType_Generic_OpenXML, FileTypeGuesser  # type: ignore
from oletools.oleid import RISK  # type: ignore
from oletools.oleobj import get_logger, find_ole, find_external_relationships, OleObject  # type: ignore
from oletools.olevba import VBA_Parser  # type: ignore
from oletools.rtfobj import RtfObjParser, re_executable_extensions  # type: ignore
# from oletools.thirdparty.xxxswf import xxxswf  # type: ignore

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker

# This module doesn't look for DDE stuff, this is done by the msodde module


class Ole(BaseWorker):

    def __init__(self, module: str, worker_id: int, cache: str, timeout: str,
                 loglevel: int=logging.DEBUG, **options):
        super().__init__(module, worker_id, cache, timeout, loglevel, **options)
        log = get_logger('oleobj')
        log.setLevel(logging.DEBUG)
        # log = get_logger('olevba')
        # log.setLevel(logging.DEBUG)

    def _get_meta_attributes(self, meta, attributes_list):
        to_return = {}
        for attrib in attributes_list:
            attribute = getattr(meta, attrib)
            if isinstance(attribute, bytes):
                try:
                    attribute = attribute.decode()
                except UnicodeDecodeError:
                    self.logger.debug(f'Unable to decode {attrib}')
                    continue
            if isinstance(attribute, datetime):
                attribute = attribute.isoformat()
            if not attribute:
                continue
            to_return[attrib] = attribute
        return to_return

    def process_ole(self, ole) -> Tuple[Status, Dict]:
        details = {'malicious': ''}
        status = Status.CLEAN
        if ole.format_id == OleObject.TYPE_EMBEDDED:
            details['format'] = 'Embedded'
        elif ole.format_id == OleObject.TYPE_LINKED:
            details['format'] = 'Linked'
        else:
            details['format'] = 'Unknown'
        if ole.is_package:
            status = Status.WARN
            details['package'] = f'Filename: {ole.filename}\nSource path: {ole.src_path}\nTemp path = {ole.temp_path}\nMD5 = {ole.olepkgdata_md5}'
            _, temp_ext = os.path.splitext(ole.temp_path)
            _, file_ext = os.path.splitext(ole.filename)
            if temp_ext != file_ext:
                status = Status.ALERT
                details['malicious'] += f'Modified extension {temp_ext} -> {file_ext}'
            if re_executable_extensions.match(temp_ext) or re_executable_extensions.match(file_ext):
                status = Status.ALERT
                details['malicious'] += f'Embedded file executable: {temp_ext} - {file_ext}'
        else:
            if hasattr(ole, 'olepkgdata_md5'):
                details['ole'] = f'MD5 = {ole.olepkgdata_md5}'

        if ole.clsid is not None:
            details['CLSID'] = ole.clsid
            details['CLSID description'] = ole.clsid_desc
            if 'CVE' in ole.clsid_desc:
                status = Status.ALERT

        if ole.class_name == b'OLE2Link':
            status = Status.ALERT
            details['exploit'] = 'Possibly an exploit for the OLE2Link vulnerability (VU#921560, CVE-2017-0199)'
            pat = re.compile(b'(?:[\\x20-\\x7E][\\x00]){3,}')
            words = [w.decode('utf-16le') for w in pat.findall(ole.oledata)]
            urls: Set[str] = set()
            for w in words:
                if "http" in w:
                    urls.add(w)
                else:
                    print(w)
            details['URLs'] = sorted(urls)  # type: ignore
        elif ole.class_name.lower().startswith(b'equation.3'):
            status = Status.ALERT
            details['exploit'] = 'Possibly an exploit for the Equation Editor vulnerability (VU#421280, CVE-2017-11882)'

        if not details['malicious']:
            details.pop('malicious')
        return status, details

    def _process_macros(self, filetype: FileTypeGuesser):
        # NOTE: must pass a filepath because of XLMMacroDeobfuscator
        # Code copied from: https://github.com/decalage2/oletools/blob/master/oletools/oleid.py#L415
        details = defaultdict(list)
        vba_parser = VBA_Parser(filetype.filepath)
        for type_entry, keyword, description in vba_parser.analyze_macros(show_decoded_strings=True, deobfuscate=False):
            details[type_entry].append(description)
        return Status.ALERT, details

    def analyse(self, task: Task, report: Report):
        self.logger.debug(f'analysing file {task.file.path}...')
        oid = oleid.OleID(task.file.path)
        # We must initialize a bunch of internal variables in order to run the calls below
        # And we cannot simply run oid.check() because it closes the olefile
        oid.ftg = FileTypeGuesser(filepath=oid.filename, data=oid.data)
        if oid.ftg.container == CONTAINER.OLE:
            oid.ole = oid.ftg.olefile

        if oid.ftg.filetype in [FTYPE.UNKNOWN, FTYPE.EXE_PE]:
            report.status = Status.NOTAPPLICABLE
            return

        report.status = Status.CLEAN

        malicious: List[str] = []
        suspicious: List[str] = []
        info: List[str] = []

        if oid.ole:
            # Get meta
            meta = oid.ole.get_metadata()
            summary = self._get_meta_attributes(meta, meta.SUMMARY_ATTRIBS)
            docsum = self._get_meta_attributes(meta, meta.DOCSUM_ATTRIBS)
            report.add_details('summary', summary)
            report.add_details('docsum', docsum)

            # Check encryption
            encryption = oid.check_encrypted()
            if encryption.risk == RISK.ERROR:
                report.status = Status.ALERT
                malicious.append(encryption.description)
            elif encryption.risk in [RISK.LOW, RISK.NONE]:
                info.append(encryption.description)
            else:
                # New risk level from lib, shouldn't happen.
                report.status = Status.ALERT
                malicious.append(encryption.description)

            # get object pool
            pool = oid.check_object_pool()
            if pool.value:
                report.status = Status.ALERT
                suspicious.append(pool.description)
                # in theory, we can get to the pool stuff with
                # oid.ole.openstream('ObjectPool')
                # https://github.com/decalage2/olefile/blob/master/olefile/olefile.py#L1929
                # and get a OleStream out of that (BytesIO pseudofile)
                # https://github.com/decalage2/olefile/blob/5ae06e937cd18afebfb49239e8f20b099605136f/olefile/olefile.py#L563
                # what to do with that is unclear but we might be able to pass it to OleFileIO
                # and keep going.

            flash = oid.check_flash()
            if flash.value > 0:
                # Nothing good in that.
                report.status = Status.ALERT
                malicious.append(encryption.description)

                # NOTE Taken from
                # https://github.com/decalage2/oletools/blob/master/oletools/pyxswf.py#L124
                # Commented because it prints instead of returning something we can use
                # xxxswf.disneyland must be rewritten

                # for direntry in oid.ole.direntries:
                #    if direntry is not None and direntry.entry_type == olefile.STGTY_STREAM:
                #        f = oid.ole._open(direntry.isectStart, direntry.size)
                #        data = f.getvalue()
                #        if b'FWS' in data or b'CWS' in data:
                #            xxxswf.disneyland(f, direntry.name, options)
                #        f.close()

        elif oid.ftg.is_openxml():
            # okay, this is hell.
            # INFO: ooxml.XmlParser *requires* a path
            xmlparser = ooxml.XmlParser(str(task.file.path))
            # external relationships
            # same as oid.check_external_relationships(), but gets the details.
            for rel_type, attribute in find_external_relationships(xmlparser):
                report.status = Status.ALERT
                malicious.append(f'{rel_type} - {attribute}')

            for olefile in find_ole(task.file.original_filename, task.file.data.getvalue()):
                report.status = Status.ALERT
                malicious.append('Has embedded OLE resource.')
                # TODO Process as a normal olefile

        elif oid.ftg.filetype == FTYPE.RTF:
            # process RTF
            rtf = RtfObjParser(task.file.data.getvalue())
            rtf.parse()
            # If all goes well, rtf.objects contains olefiles and we want to process them
            # with whatever is going on in there
            # https://github.com/decalage2/oletools/blob/dfbcabb957644769d17dfbb367eb3a52167c0506/oletools/rtfobj.py#L880
            for obj in rtf.objects:
                if not obj.is_ole:
                    continue
                status, details = self.process_ole(obj)
                report.status = status
                for k, v in details.items():
                    report.add_details(k, v)

            # NOTE Taken from
            # https://github.com/decalage2/oletools/blob/master/oletools/pyxswf.py#L124
            # Commented because it prints instead of returning something we can use
            # xxxswf.disneyland must be rewritten

            # for obj in rtf.objects:
            #    if b'FWS' in obj.rawdata or b'CWS' in obj.rawdata:
            #        f = BytesIO(obj.rawdata)
            #        xxxswf.disneyland(f, name, options)

        if (issubclass(oid.ftg.ftype, FType_Generic_OLE)
                or issubclass(oid.ftg.ftype, FType_Generic_OpenXML)):
            # Macros, RTF don't have that
            vba_indicator, xlm_indicator = oid.check_macros()
            info.append(vba_indicator.description)
            info.append(xlm_indicator.description)
            if vba_indicator.risk != RISK.NONE or xlm_indicator.risk != RISK.NONE:
                # has macro
                # NOTE: must pass the file on disk:
                # https://github.com/decalage2/oletools/blob/be16ef425c30c689c92ef33cb1af7f930adfd69f/oletools/oleid.py#L459
                status, details = self._process_macros(oid.ftg)
                report.status = status
                for k, v in details.items():
                    report.add_details(k, v)

        if malicious:
            report.add_details('malicious', malicious)
        if suspicious:
            report.add_details('suspicious', suspicious)
        if info:
            report.add_details('info', info)
