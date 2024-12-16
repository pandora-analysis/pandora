#!/usr/bin/env python3

from __future__ import annotations

import time

from datetime import datetime
from io import BytesIO
from zipfile import ZipFile

import yara  # type: ignore[import-not-found]
import requests

from ..default import get_homedir

from .yara import YaraWorker


class YaraHubWorker(YaraWorker):
    url = 'https://yaraify.abuse.ch/yarahub/yaraify-rules.zip'
    rulespath = get_homedir() / 'yara_repos' / 'yarahub'
    savepath = rulespath / 'yara.compiled'
    creation_date: datetime
    needs_external = [
        'yes.yar',  # broken (?)
        'Sus_Obf_Enc_Spoof_Hide_PE.yar',  # matches on everything
        'golang_david_CSC846.yar',  # matches on everything
    ]

    def _init_rules(self) -> None:
        if not self.rulespath.exists():
            self.rulespath.mkdir(parents=True, exist_ok=True)
            self.logger.info(f'Initializing yara rules from {self.url}')
            self.fetch_rules()

    def fetch_rules(self) -> None:
        try:
            (self.rulespath / 'lock').touch(exist_ok=False)
        except FileExistsError:
            self.logger.info('Another process is already fetching the rules.')
            # just making sure the lock isn't very old and should be removed
            if (self.rulespath / 'lock').stat().st_mtime < time.time() - 3600:
                self.logger.info('Removing old lock')
                (self.rulespath / 'lock').unlink()
            else:
                return
        self.logger.info(f'Fetching yara rules from {self.url}')
        full_rules_zip = requests.get(self.url, timeout=10)
        with ZipFile(BytesIO(full_rules_zip.content)) as zip_file:
            for name in zip_file.namelist():
                if name.endswith('.yar'):
                    with zip_file.open(name) as rulesfile:
                        with (self.rulespath / name).open('wb') as savefile:
                            savefile.write(rulesfile.read())
        (self.rulespath / 'lock').unlink()
        # TODO: delete old files?
        with (self.rulespath / 'last_update').open('w') as last_update:
            last_update.write(str(datetime.now().isoformat()))

    @property
    def rules(self) -> yara.Rules:
        if (self.rulespath / 'last_update').exists() and self.savepath.exists():
            with (self.rulespath / 'last_update').open('r') as last_update:
                last_update_date = datetime.fromisoformat(last_update.read()).date()

            if last_update_date < datetime.now().date():
                self.fetch_rules()
        else:
            self.fetch_rules()
        return super().rules
