#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
libdir=../lib/.libs:../libpacketdump/.libs
export LD_LIBRARY_PATH="$libdir:/usr/local/lib/"
export DYLD_LIBRARY_PATH="${libdir}"

exec "$DIR/test-hotplug" "$@"
