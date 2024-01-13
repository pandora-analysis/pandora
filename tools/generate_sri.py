#!/usr/bin/env python3

import base64
import hashlib
import json

from pathlib import Path
from typing import Dict, Any

from pandora.default import get_homedir


def sri_for_dir(directory: Path) -> Dict[str, Any]:
    to_return: Dict[str, Any] = {}
    for entry in directory.iterdir():
        if entry.name.startswith('.'):
            continue
        if entry.is_dir():
            sris = sri_for_dir(entry)
            if sris:
                to_return[entry.name] = sri_for_dir(entry)
        elif entry.is_file():
            with entry.open('rb') as f:
                to_return[entry.name] = base64.b64encode(hashlib.sha512(f.read()).digest()).decode('utf-8')
    return to_return


if __name__ == '__main__':
    dest_dir = get_homedir() / 'website' / 'web'

    to_save: Dict[str, Any] = {'static': sri_for_dir(dest_dir / 'static')}

    with (dest_dir / 'sri.txt').open('w') as fw:
        json.dump(to_save, fw, indent=2, sort_keys=True)
