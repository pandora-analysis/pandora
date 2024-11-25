#!/usr/bin/env python3

from __future__ import annotations

import fitz # type: ignore[import-untyped]

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker

class Pdf(BaseWorker):

    check_encrypted: bool
    check_javascript: bool
    check_suspicious_object: bool
    check_embedded_files: bool

    def _is_encrypted(self, file_path: str) -> bool:
        try:
            doc = fitz.open(file_path)
            return doc.is_encrypted
        except Exception as e:
            self.logger.warning(f'Unable to check encoding for PDF file: {e}')
            return False

    def _extract_javascript(self, file_path: str) -> list[str]:
        try:
            js_scripts = []
            doc = fitz.open(file_path)
            for xref in range(1, doc.xref_length()):
                # Check for /JS and /JavaScript entries
                obj_dict = doc.xref_object(xref, compressed=True)

                for key in ["/JS", "/JavaScript"]:
                    if key in obj_dict:
                        js_type = doc.xref_get_key(xref, key[1:])
                        if js_type != ("null", "null"):
                            if js_type[0] == "string":  # Directly embedded JavaScript
                                js_scripts.append(js_type[1])
                            elif js_type[0] == "xref":  # JavaScript referenced in another object
                                js_ref = int(js_type[1].split()[0])
                                js_code = doc.xref_stream(js_ref).decode('utf-8')
                                js_scripts.append(js_code)

        except Exception as e:
            self.logger.warning(f'Unable to extract JavaScript from PDF file: {e}')

        return js_scripts

    def _detect_suspicious_objects(self, file_path: str) -> list[str]:
        try:
            suspicious_objects = []
            doc = fitz.open(file_path)
            for xref in range(1, doc.xref_length()):
                obj_dict = doc.xref_object(xref, compressed=True)
                # Check for /AA and /OpenAction
                for keyword in ["/AA", "/OpenAction"]:
                    if keyword in obj_dict:
                        suspicious_objects.append(f'{keyword} found in object {xref}: {obj_dict}')
                        # Attempt to extract the object content if possible
                        try:
                            content = doc.xref_stream(xref)
                            suspicious_objects.append(content.decode('utf-8', errors='ignore'))
                        except:
                            pass

        except Exception as e:
            self.logger.warning(f'Unable to detect suspicious objects in PDF file: {e}')

        return suspicious_objects

    def _detect_embedded_files(self, file_path: str) -> list[str]:
        try:
            embedded_files = []
            doc = fitz.open(file_path)
            for item in range(doc.embfile_count()):
                embedded_files.append(doc.embfile_info(item))

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

            if self.check_encrypted:
                is_encrypted = self._is_encrypted(str(task.file.path))
            if self.check_javascript:
                js_scripts = self._extract_javascript(str(task.file.path))
            if self.check_suspicious_object:
                suspicious_objects = self._detect_suspicious_objects(str(task.file.path))
            if self.check_embedded_files:
                embedded_files = self._detect_embedded_files(str(task.file.path))

            report_data = {
                "Is Encoded": is_encrypted,
                "Javascript Found": js_scripts,
                "Suspicious Objects Found": suspicious_objects,
                "Embedded Files Found": embedded_files,
            }
            report_data = {k: v for k, v in report_data.items() if v}

            if js_scripts or is_encrypted or suspicious_objects or embedded_files:
                report.status = Status.ALERT
                report.add_details('malicious', report_data)
            else:
                report.status = Status.CLEAN
                report.add_details('analysis', report_data)

        except Exception as e:
            self.logger.warning(f'Unable to process PDF file: {e}')
