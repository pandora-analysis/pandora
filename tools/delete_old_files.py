#!/usr/bin/env python3
import argparse
import sys

from datetime import datetime

from pandora.pandora import Pandora
from pandora.user import User


def delete_old_files(d: datetime):
    p = Pandora()
    u = User('admin', last_ip='127.0.0.1', role='admin')
    for task in p.get_tasks(u, last_date=d, first_date=0):
        task.file.delete()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Delete old files.')
    parser.add_argument('--date', required=True, help="Cut off date, isoformat (YYYY-MM-DD).")
    args = parser.parse_args()

    cutoff_date = datetime.fromisoformat(args.date)

    keep_going_str = input(f'All the files older than {cutoff_date.isoformat()} will be deleted. Continue? (y/N) ')
    if keep_going_str.lower() != 'y':
        sys.exit('Ok, quitting.')

    delete_old_files(cutoff_date)
