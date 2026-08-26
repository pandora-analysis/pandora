from __future__ import annotations

import re

from typing import Any

from ..helpers import Status
from ..task import Task
from ..report import Report

from .base import BaseWorker


# ---------------------------------------------------------------------------
# Built-in default regex patterns for each category.
# These can be EXTENDED or OVERRIDDEN via the worker's .yml config file
# by defining a `patterns` list under the relevant category.
# ---------------------------------------------------------------------------

_DEFAULT_PATTERNS: dict[str, list[str]] = {
    'api_keys': [
        # AWS
        r'(?i)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
        r'(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s]*[=:]\s*["\']?[A-Za-z0-9/+=]{40}',
        # OpenAI
        r'sk-[A-Za-z0-9]{32,}',
        # Google API key
        r'AIza[0-9A-Za-z\-_]{35}',
        # GitHub PAT (classic and fine-grained)
        r'ghp_[A-Za-z0-9]{36}',
        r'github_pat_[A-Za-z0-9_]{82}',
        # Slack
        r'xox[baprs]-[0-9A-Za-z\-]{10,}',
        # Generic Bearer / API token in HTTP headers (config files, etc.)
        r'(?i)(authorization|bearer|api[_\-]?key|token)["\s]*[=:]["\s]*[A-Za-z0-9\-_\.]{20,}',
    ],
    'credentials': [
        # password = "something" style (key=value or key: value)
        r'(?i)(password|passwd|secret|private[_\-]?key|api[_\-]?secret)\s*[=:]\s*["\']?[^\s"\']{6,}',
        # DSN-style connection strings with embedded credentials
        r'(?i)(mysql|postgres|mongodb|redis|amqp)://[^:]+:[^@]+@',
    ],
    'pii_financial': [
        # IBAN (basic structural pattern; 15–34 alphanumeric chars after 2-letter country + 2 digits)
        r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b',
        # Credit card numbers (Luhn groups, common separators)
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        # US SSN
        r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
    ],
    'pii_contact': [
        # Email addresses
        r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}',
        # International phone numbers (+xx ... format)
        r'\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{1,4}[\s\-]?\d{1,9}',
    ],
}


class SensitiveContentDetection(BaseWorker):
    """
    Regex-based worker that scans file text content for sensitive data.

    All detection categories are disabled by default and must be explicitly
    enabled in the worker's .yml configuration file. Regex patterns for each
    category can also be extended or replaced via the config.
    """

    # Typed attributes set by BaseWorker from config settings
    max_scan_bytes: int
    categories: dict[str, Any]

    def _extract_text(self, task: Task) -> str | None:
        """
        Best-effort text extraction from the task file.
        Returns None if the file cannot be decoded as text.
        """
        try:
            path = task.file.path
            with open(path, 'rb') as fh:
                raw = fh.read(self.max_scan_bytes)
            # Try UTF-8 first, then latin-1 as a safe fallback
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError:
                return raw.decode('latin-1', errors='replace')
        except Exception:
            return None

    def _get_patterns_for_category(self, category_key: str, category_cfg: dict[str, Any]) -> list[str]:
        """
        Return the regex pattern list for a category.
        If the config defines a 'patterns' list, it overrides the defaults.
        """
        if 'patterns' in category_cfg and isinstance(category_cfg['patterns'], list):
            return category_cfg['patterns']
        return _DEFAULT_PATTERNS.get(category_key, [])

    def analyse(self, task: Task, report: Report, manual_trigger: bool = False) -> None:
        # ----------------------------------------------------------------
        # Step 1: extract text
        # ----------------------------------------------------------------
        text = self._extract_text(task)
        if text is None:
            report.status = Status.NOTAPPLICABLE
            report.add_details('Info', 'File could not be read as text; sensitive content detection skipped.')
            return

        # Strip null bytes (common in binary blobs decoded as latin-1)
        text = text.replace('\x00', '')

        # ----------------------------------------------------------------
        # Step 2: iterate over configured categories
        # ----------------------------------------------------------------
        categories: dict[str, Any] = getattr(self, 'categories', {})
        any_category_enabled = False
        found_anything = False

        for category_key, category_cfg in categories.items():
            if not isinstance(category_cfg, dict):
                continue
            if not category_cfg.get('enabled', False):
                continue

            any_category_enabled = True
            patterns = self._get_patterns_for_category(category_key, category_cfg)
            matches: list[str] = []

            for pattern in patterns:
                try:
                    for m in re.finditer(pattern, text):
                        # Truncate match to avoid leaking full secrets in the report
                        match_str = m.group(0)
                        if len(match_str) > 60:
                            match_str = match_str[:57] + '...'
                        matches.append(match_str)
                except re.error:
                    # Malformed pattern in config – log but don't crash
                    self.logger.warning(f'Invalid regex pattern in category {category_key!r}: {pattern!r}')

            if matches:
                found_anything = True
                # Use the detection_id naming convention: <category_key>_found
                detection_id = f'{category_key}_found'
                report.status = detection_id

                # Human-friendly category name from config, fallback to key
                display_name = category_cfg.get('name', category_key.replace('_', ' ').title())
                count = len(matches)
                sample = matches[:3]
                sample_str = ', '.join(f'`{s}`' for s in sample)
                suffix = f' (and {count - 3} more)' if count > 3 else ''
                report.add_details(
                    'Warning',
                    f'[{display_name}] {count} potential match(es) found: {sample_str}{suffix}'
                )

        # ----------------------------------------------------------------
        # Step 3: set final status
        # ----------------------------------------------------------------
        if not any_category_enabled:
            # No categories configured — mark as not applicable
            report.status = Status.NOTAPPLICABLE
        elif not found_anything:
            report.status = Status.CLEAN
