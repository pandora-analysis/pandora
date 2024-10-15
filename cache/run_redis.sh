#!/bin/bash

set -e
set -x

if [ -f  ../../valkey/src/valkey-server ]; then
    ../../valkey/src/valkey-server ./cache.conf
else [ -f ../../redis/src/redis-server ]; then
    ../../redis/src/redis-server ./cache.conf
