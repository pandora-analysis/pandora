#!/usr/bin/env python3

from pandora.storage_client import Storage

s = Storage()
for key in s.storage.keys('users:*'):
    s.storage.delete(key)
