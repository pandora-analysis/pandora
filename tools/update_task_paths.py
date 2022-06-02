#!/usr/bin/env python3

import shutil

from pandora.storage_client import Storage
from pandora.task import Task
from pandora.default import get_homedir, safe_create_dir

s = Storage()

for t in s.get_tasks():
    task = Task(**t)  # type: ignore
    if task.file.directory.parent.name != 'tasks':
        continue
    new_dir = get_homedir() / 'tasks' / str(task.file.save_date.year) / f'{task.file.save_date.month:02}' / task.uuid
    safe_create_dir(new_dir.parent)
    shutil.move(task.file.directory, new_dir)
    task.file.path = new_dir / task.file.path.name
    task.file.store()
