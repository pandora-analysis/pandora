#!/bin/bash

set -e
set -x

../../redis/src/redis-server ./storage.conf
