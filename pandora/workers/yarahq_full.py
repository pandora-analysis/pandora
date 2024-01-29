#!/usr/bin/env python3

from __future__ import annotations

import re

from datetime import datetime, timedelta
from io import BytesIO
from zipfile import ZipFile

import yara  # type: ignore[import-not-found]
import requests

from ..default import get_homedir, PandoraException

from .yara import YaraWorker


class YaraHQFullWorker(YaraWorker):
    url = 'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip'
    rulespath = get_homedir() / 'yara_repos' / 'yara-hq-full'
    rulesfile = rulespath / 'yara-rules-full.yar'
    savepath = rulespath / 'yara.compiled'
    creation_date: datetime

    def _init_rules(self) -> None:
        self.logger.info(f'Initializing yara rules from {self.url}')
        self.fetch_rules()

    def fetch_rules(self) -> None:
        self.logger.info(f'Fetching yara rules from {self.url}')
        self.rulespath.mkdir(parents=True, exist_ok=True)
        full_rules_zip = requests.get(self.url, timeout=10)
        with ZipFile(BytesIO(full_rules_zip.content)) as zip_file:
            with zip_file.open('packages/full/yara-rules-full.yar') as rulesfile:
                with self.rulesfile.open('wb') as savefile:
                    savefile.write(rulesfile.read())

    @property
    def rules(self) -> yara.Rules:
        if not self.rulesfile.exists():
            # That should not happen, the module should have been disabled
            raise PandoraException(f'YaraHQFull rules file {self.rulesfile} does not exist')

        with self.rulesfile.open() as _f:
            _creation_date = re.findall("Creation Date: (.*)", _f.read())
        if _creation_date:
            self.creation_date = datetime.strptime(_creation_date[0], '%Y-%m-%d')
        else:
            raise PandoraException(f'YaraHQFull rules file {self.rulesfile} does not contain a creation date')

        if self.creation_date < datetime.today() - timedelta(days=1):
            self.fetch_rules()
        return super().rules
