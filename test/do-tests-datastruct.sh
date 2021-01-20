#!/bin/sh

OK=0
FAIL=""

do_test() {
	if $@; then
		OK=$(( OK + 1 ))
	else
		FAIL="$FAIL
$*"
	fi
}

libdir=../lib/.libs:../libpacketdump/.libs
export LD_LIBRARY_PATH="$libdir"
export DYLD_LIBRARY_PATH="${libdir}"
echo Testing vector
do_test ./test-datastruct-vector
echo Testing deque
do_test ./test-datastruct-deque
echo Testing ringbuffer
do_test ./test-datastruct-ringbuffer
echo
echo "Tests passed: $OK"
echo "Tests failed: $FAIL"
