#!/bin/bash

set -e
set -x

if test -f "../../kvrocks/build/kvrocks"; then
    ../../kvrocks/build/kvrocks -c kvrocks.conf
else
    ../../kvrocks/src/kvrocks -c kvrocks.conf
fi
