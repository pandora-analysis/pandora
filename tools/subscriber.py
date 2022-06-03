#!/usr/bin/env python3

import time

from pandora.pandora import Pandora
from pandora.default import get_config

# NOTE: By default, redis only listen on a socket. In order to access it from an other
#       system, you probably want to start the redis cache database as listening on a port too.
#       This is the config file you need to edit: cache/cache.conf - and search for "port"
# In that case, initialize your subscriber this way:
# redis  = redis.Redis(host='<host>', port=<port>, db=0)
# subscriber = redis.pubsub()

p = Pandora()
subscriber = p.redis.pubsub()

subscriber.subscribe(get_config('generic', 'channels')['channel_submission'])
while True:
    msg = subscriber.get_message()
    if msg:
        print(msg)
    time.sleep(1)
