#!/usr/bin/env python3

from pandora.storage_client import Storage

s = Storage()
for uuid in s.storage.zrevrangebyscore('tasks', '+Inf', '-Inf'):
    print(uuid)
    print(s.storage.hgetall(f'tasks:{uuid}'))
    s.storage.hdel(f'tasks:{uuid}', 'status')
    print(s.storage.hgetall(f'tasks:{uuid}'))
