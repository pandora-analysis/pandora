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
    check_embedded_files: bool

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
            for xref in range(1, doc.xref_length()):  # type: ignore[no-untyped-call]
                try:
                    obj_dict = doc.xref_object(xref, compressed=True)  # type: ignore[no-untyped-call]
                    if obj_dict is None:
                        continue
                except (RuntimeError, ValueError, TypeError) as e:
                    self.logger.warning(f"Skipping xref {xref}: {e}")
                    continue

                # Check for /AA, /OpenAction OR /Launch
                for keyword in ["/AA", "/OpenAction", "/Launch"]:
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

    def _detect_embedded_files(self, doc: Document) -> list[str]:
        try:
            embedded_files = []
            for item in range(doc.embfile_count()):
                embedded_files.append(str(doc.embfile_info(item)))

        except Exception as e:
            self.logger.warning(f'Unable to detect embedded files in PDF file: {e}')

        return embedded_files

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        if not task.file.is_pdf:
            report.status = Status.NOTAPPLICABLE
            return

        self.logger.debug(f'Analysing PDF file {task.file.path}...')
        try:
            is_encrypted = False
            js_scripts = []
            suspicious_objects = []
            embedded_files = []

            with pymupdf.open(str(task.file.path)) as doc:  # type: ignore[no-untyped-call]
                if self.check_encrypted:
                    is_encrypted = self._is_encrypted(doc)
                if self.check_javascript:
                    js_scripts = self._extract_javascript(doc)
                if self.check_suspicious_object:
                    suspicious_objects = self._detect_suspicious_objects(doc)
                if self.check_embedded_files:
                    embedded_files = self._detect_embedded_files(doc)

            if is_encrypted:
                report.add_details("Is Encrypted", "Yes")
            if js_scripts:
                report.add_details("Javascript Found", js_scripts)
            if suspicious_objects:
                report.add_details("Suspicious Objects Found", suspicious_objects)
            if embedded_files:
                report.add_details("Embedded Files Found", embedded_files)

            if js_scripts or is_encrypted or suspicious_objects or embedded_files:
                if is_encrypted:
                    report.status = Status.WARN
                if js_scripts or suspicious_objects or embedded_files:
                    report.status = Status.ALERT
            else:
                report.status = Status.CLEAN

        except Exception as e:
            self.logger.warning(f'Unable to process PDF file: {e}')
