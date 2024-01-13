from __future__ import annotations

import re

from typing import Any

from .helpers import get_public_suffix_list


class TextParser:
    URL_REGEX = r''.join([
        r"""(?i)\b((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)""",
        r"""(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+""",
        r"""(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?]))"""
    ])
    URL_REGEX_SIMPLE = r'(h([a-z]){2}p[s]?://([^<>\s"\)])+)'
    HOSTNAME_REGEX = r'((([\w\-]+\.)+)([\w\-]+))\.?'
    EMAIL_REGEX = r'([\w\-\.\_]+@(([\w\-]+\.)+)([a-zA-Z]{2,6}))\.?'
    IP_REGEX = r''.join([
        r"((?<![\d\.])(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
        r"\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/[0-9]{2})?(?![\d\.]))"
    ])
    IBAN_REGEX = r''.join([
        r'(([a-zA-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{4}[0-9]{3}(([a-zA-Z0-9]{1,4}){0,4}))|([a-zA-Z]{2}[\s]?[0-9]{2}[\s]',
        r'[a-zA-Z0-9]{4}[\s][0-9]{4}[\s][0-9]{3}(([a-zA-Z0-9]{1,4}[\s]?){0,4}))|([a-zA-Z]{2}[\s][0-9]{2}[\s]',
        r'[a-zA-Z0-9]{4}[0-9]{4}[0-9]{3}(([a-zA-Z0-9]{1,4}){0,4}))|([a-zA-Z]{2}[0-9]{2}[\+][a-zA-Z0-9]{4}[\+][0-9]{4}',
        r'[\+][0-9]{3}(([a-zA-Z0-9]{1,4}[\+]?){0,4})[\+]))'
    ])

    def __init__(self, text: Any) -> None:
        self.tlds = get_public_suffix_list().tlds
        self.text = str(text) or ''
        self.ips = self._find_ips()
        self.ibans = self._find_ibans()
        self.urls = self._find_urls()
        self.hostnames = self._find_hostnames()
        self.emails = self._find_emails()

    def _find_ips(self) -> set[str]:
        ips = set()
        text = self.text.replace('[.]', '.')
        for match in re.finditer(self.IP_REGEX, text):
            ips.add(match.group(1))
        return ips

    def _find_ibans(self) -> set[str]:
        ibans = set()
        for match in re.finditer(self.IBAN_REGEX, self.text):
            ibans.add(re.sub(r'\s\+', '', match.group(1)))
        return ibans

    def _find_urls(self) -> set[str]:
        urls = set()
        simple_pattern = re.compile(self.URL_REGEX_SIMPLE, re.VERBOSE)
        complex_pattern = re.compile(self.URL_REGEX, re.VERBOSE)
        for match in re.finditer(simple_pattern, self.text):
            url = match.group(1)
            if complex_pattern.match(url):
                # Remove ","
                if "," in url:
                    url = url.split(',')[0]
                # Remove trailing . and /
                url = url.rstrip('./')
                # Remove trailing html entities
                if url.endswith('&nbsp;'):
                    url = url[:-6]
                if url.endswith('&gt;'):
                    url = url[:-4]
                urls.add(url)
        return urls

    def _find_hostnames(self) -> set[str]:
        hostnames = set()
        text = self.text.replace("[.]", ".")
        for match in re.finditer(self.HOSTNAME_REGEX, text):
            hostname = match.group(1).lower()
            tld = hostname.split('.')[-1]
            if tld in self.tlds:
                hostnames.add(hostname)
        return hostnames

    def _find_emails(self) -> set[str]:
        emails = set()
        # Replace [a] with @
        text = self.text.replace("[a]", "@")
        for match in re.finditer(self.EMAIL_REGEX, text):
            emails.add(match.group(1))
        return emails
