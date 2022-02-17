#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import traceback

from typing import Dict, Any, Tuple, Optional

from pyhashlookup import Hashlookup

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


class HashlookupWorker(BaseWorker):

    def __init__(self, module: str, name: str, cache: str, timeout: str,
                 loglevel: int=logging.DEBUG, **options):
        super().__init__(module, name, cache, timeout, loglevel, **options)

        try:
            self.hashlookup = Hashlookup()
            self.hashlookup.info()
        except Exception as e:
            self.logger.warning(e)
            self.disabled = True

    def _check_result(self, result: Dict[str, Any]) -> Tuple[Optional[bool], Dict]:
        if 'message' in result:
            # Unknown in db
            return None, {}

        legit = None
        details = {}
        if 'KnownMalicious' in result:
            legit = False
            details['malicious'] = result['KnownMalicious']

        if 'hashlookup:trust' in result:
            if 'source' in result:
                details['source'] = result['source']
            if 'FileName' in result:
                details['filename'] = result['FileName']
            if result['hashlookup:trust'] < 50:
                legit = False
            elif legit is not False:
                legit = True
        return legit, details

    def analyse(self, task: Task, report: Report):
        try:
            self.logger.debug(f'analysing file {task.file.path}...')
            # Run a lookup against all the hashes, as hashlookup gaters multiple
            # sources with different hashes available
            result_md5 = self.hashlookup.md5_lookup(task.file.md5)
            result_sha1 = self.hashlookup.sha1_lookup(task.file.sha1)
            result_sha256 = self.hashlookup.sha256_lookup(task.file.sha256)

            md5_legit, md5_details = self._check_result(result_md5)
            sha1_legit, sha1_details = self._check_result(result_sha1)
            sha256_legit, sha256_details = self._check_result(result_sha256)

            if all(v is None for v in [md5_legit, sha1_legit, sha256_legit]):
                # Not in the database, we can't tell
                report.status = Status.NOTAPPLICABLE
            elif any(v is False for v in [md5_legit, sha1_legit, sha256_legit]):
                # If any of hits is legit false, it's bad.
                report.status = Status.ALERT
            elif any(v is True for v in [md5_legit, sha1_legit, sha256_legit]):
                # At least one it known and probably safe
                report.status = Status.CLEAN

            if md5_legit is not None:
                report.add_details('md5', md5_details)
            if sha1_legit is not None:
                report.add_details('sha1', sha1_details)
            if sha256_legit is not None:
                report.add_details('sha256', sha256_details)

        except Exception as e:
            err = f'{repr(e)}\n{traceback.format_exc()}'
            self.logger.debug(f'Not found {err}')
            report.status = Status.ERROR
