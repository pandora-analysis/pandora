#!/usr/bin/env python3

from __future__ import annotations

import os

import yara  # type: ignore[import-not-found]

from ..default import get_homedir
from ..helpers import Status
from ..task import Task
from ..report import Report

from .yara import YaraWorker


class YaraSignatureBaseWorker(YaraWorker):
    rulespath = get_homedir() / 'yara_repos' / 'signature-base'
    savepath = rulespath / 'yara.compiled'
    needs_external = ['generic_anomalies.yar', 'general_cloaking.yar',
                      'gen_webshells_ext_vars.yar',
                      'thor_inverse_matches.yar', 'yara_mixed_ext_vars.yar',
                      'configured_vulns_ext_vars.yar',
                      'gen_fake_amsi_dll.yar',
                      'gen_mal_3cx_compromise_mar23.yar',
                      'yara-rules_vuln_drivers_strict_renamed.yar',
                      'expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar',
                      'gen_vcruntime140_dll_sideloading.yar',
                      'expl_connectwise_screenconnect_vuln_feb24.yar',
                      'gen_susp_obfuscation.yar',
                      'apt43_machine_names.yar',  # This one requires the magic module enabled with yara-python, this is not possible without compiling manually
                      ]
    last_change: float | None = None

    def rules_with_external_vars(self, filename: str, filepath: str, filetype: str, owner: str) -> yara.Rules:
        extension = os.path.splitext(filename)[1]
        yara_files = [y_file for y_file in self.rulespath.glob('**/*.yar')
                      if y_file.name in self.needs_external and y_file.name != 'apt43_machine_names.yar']
        rules = yara.compile(filepaths={str(path): str(path) for path in yara_files},
                             includes=True,
                             externals={'filename': filename, 'filepath': filepath,
                                        'extension': extension, 'filetype': filetype,
                                        'owner': owner})
        return rules

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        if not task.file.data:
            report.status = Status.NOTAPPLICABLE
            return

        super().analyse(task=task, report=report)

        filetype = task.file.type  # only match in generic_anomalies.yar for "GIF"
        owner = ''  # only match in yara_mixed_ext_vars.yar for "confluence"
        rules_external = self.rules_with_external_vars(
            filename=task.file.original_filename, filepath=task.file.original_filename,
            filetype=filetype, owner=owner)
        matches = [str(match) for match in rules_external.match(data=task.file.data.getvalue()) if match]
        if matches:
            report.status = Status.ALERT
            report.add_details('Rules matches', matches)
