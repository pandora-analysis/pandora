#!/usr/bin/env python3

from __future__ import annotations

import re

import pymupdf
from pymupdf import Document

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class Pdf(BaseWorker):

    check_encrypted: bool
    check_javascript: bool
    check_suspicious_object: bool

    def _is_encrypted(self, doc: Document) -> bool:
        try:
            return doc.is_encrypted
        except Exception as e:
            self.logger.warning(f'Unable to check encoding for PDF file: {e}')
            return False

    def _get_stream(self, doc: Document, xref: int) -> bytes | None:
        # Try to extract stream data
        if not doc.xref_is_stream(xref):  # type: ignore[no-untyped-call]
            return None
        try:
            data = doc.xref_stream(xref)  # type: ignore[no-untyped-call]
            if data:
                return data
        except Exception as e:
            self.logger.warning(f"Failed to extract stream from xref {xref}: {e}")

        try:
            # Extract raw bytes as a fallback
            return doc.xref_stream_raw(xref)  # type: ignore[no-untyped-call]
        except Exception as e:
            self.logger.warning(f"Failed to extract raw stream from xref {xref}: {e}")
            return None

    def _extract_javascript(self, doc: Document) -> list[str]:
        js_scripts: list[str] = []
        js_indicators = ["/JS", "/JavaScript"]
        try:
            for xref in range(1, doc.xref_length()):  # type: ignore[no-untyped-call]
                # Check for JavaScript in objects
                try:
                    obj_dict = doc.xref_object(xref, compressed=True)  # type: ignore[no-untyped-call]
                    if obj_dict is None:
                        continue
                except (RuntimeError, ValueError, TypeError) as e:
                    self.logger.warning(f"Skipping xref {xref}: {e}")
                    continue

                for key in js_indicators:
                    if key in obj_dict:
                        js_type = doc.xref_get_key(xref, key[1:])  # type: ignore[no-untyped-call]
                        if js_type != ("null", "null"):
                            if js_type[0] == "string":  # Directly embedded JavaScript
                                js_scripts.append(js_type[1])
                            elif js_type[0] == "xref":  # JavaScript referenced in another object
                                try:
                                    js_ref = int(js_type[1].split()[0])
                                    stream = self._get_stream(doc, js_ref)
                                    if stream:
                                        js_scripts.append(stream.decode('utf-8', errors='replace'))
                                except Exception as e:
                                    self.logger.warning(f'Unable to read referenced stream: {e}')
                        else:
                            js_scripts.append(f'{key} found in object {xref}: {obj_dict}')

        except Exception as e:
            self.logger.warning(f'Unable to extract JavaScript from PDF file: {e}')

        seen: set[str] = set()
        unique_scripts = []
        for script in js_scripts:
            if script not in seen:
                seen.add(script)
                unique_scripts.append(script)

        return unique_scripts

    def _detect_suspicious_objects(self, doc: Document) -> list[str]:
        try:
            suspicious_objects = []
            # /RichMedia and /XFA are commonly abused; /AA /OpenAction /Launch are classic auto-actions.
            alert_keywords = ["/AA", "/OpenAction", "/Launch", "/RichMedia", "/XFA"]
            for xref in range(1, doc.xref_length()):  # type: ignore[no-untyped-call]
                try:
                    obj_dict = doc.xref_object(xref, compressed=False)  # type: ignore[no-untyped-call]
                    if obj_dict is None:
                        continue
                except (RuntimeError, ValueError, TypeError) as e:
                    self.logger.warning(f"Skipping xref {xref}: {e}")
                    continue

                for keyword in alert_keywords:
                    # Use regex to reduce FPs, especially with /AA
                    if len(re.findall(keyword + '(?![A-Za-z])', obj_dict)) > 0:
                        suspicious_objects.append(f'{keyword} found in object {xref}: {obj_dict}')
                        # Attempt to extract the object content if possible
                        try:
                            content = self._get_stream(doc, xref)
                            if content:
                                suspicious_objects.append(content.decode('utf-8', errors='ignore'))
                        except Exception as e:
                            self.logger.warning(f'Unable to read referenced stream: {e}')

        except Exception as e:
            self.logger.warning(f'Unable to detect suspicious objects in PDF file: {e}')

        return suspicious_objects

    def _detect_acroform(self, doc: Document) -> bool:
        """AcroForm alone is common; flag for awareness (WARN), not automatic ALERT."""
        try:
            for xref in range(1, doc.xref_length()):  # type: ignore[no-untyped-call]
                try:
                    obj_dict = doc.xref_object(xref, compressed=True)  # type: ignore[no-untyped-call]
                except (RuntimeError, ValueError, TypeError):
                    continue
                if obj_dict and re.search(r'/AcroForm(?![A-Za-z])', obj_dict):
                    return True
        except Exception as e:
            self.logger.warning(f'Unable to detect AcroForm in PDF file: {e}')
        return False

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        if not task.file.is_pdf:
            report.status = Status.NOTAPPLICABLE
            return

        self.logger.debug(f'Analysing PDF file {task.file.path}...')
        try:
            is_encrypted = False
            still_locked = False
            js_scripts = []
            suspicious_objects = []
            has_acroform = False

            with pymupdf.open(str(task.file.path)) as doc:  # type: ignore[no-untyped-call]
                # needs_pass can stay true even after a successful authenticate(); trust the return value.
                still_locked = bool(doc.needs_pass)
                if still_locked and task.password:
                    try:
                        if doc.authenticate(task.password):
                            still_locked = False
                    except Exception as e:
                        self.logger.warning(f'Unable to authenticate PDF with provided password: {e}')

                if self.check_encrypted:
                    is_encrypted = self._is_encrypted(doc) or still_locked or bool(doc.needs_pass)
                if self.check_javascript:
                    js_scripts = self._extract_javascript(doc)
                if self.check_suspicious_object:
                    suspicious_objects = self._detect_suspicious_objects(doc)
                    has_acroform = self._detect_acroform(doc)

            if is_encrypted:
                report.add_details("Is Encrypted", "Yes")
            if js_scripts:
                report.add_details("Javascript Found", js_scripts)
            if suspicious_objects:
                report.add_details("Suspicious Objects Found", suspicious_objects)
            if has_acroform:
                report.add_details("AcroForm", "PDF contains an AcroForm dictionary.")

            # Embedded files are handled by the extractor worker.
            # Encryption alone must not be WARN/ALERT (#912): incomplete analysis -> ERROR.
            if js_scripts or suspicious_objects:
                report.status = Status.ALERT
            elif still_locked:
                report.status = Status.ERROR
                report.add_details('Warning', 'Password-protected PDF; unable to fully analyse.')
                report.add_extra('no_password', True)
            elif has_acroform:
                report.status = Status.WARN
            else:
                report.status = Status.CLEAN
        except Exception as e:
            self.logger.warning(f'Unable to process PDF file: {e}')
