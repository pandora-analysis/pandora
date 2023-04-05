#!/bin/bash

set -e
set -x

if test -f "../../kvrocks/src/kvrocks"; then
    ../../kvrocks/src/kvrocks -c kvrocks.conf
else
    ../../kvrocks/build/kvrocks -c kvrocks.conf
fi
