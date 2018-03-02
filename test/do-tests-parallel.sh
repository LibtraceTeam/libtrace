#!/bin/bash

OK=0
FAIL=""

do_test() {
	if $@; then
		OK=$[ $OK + 1 ]
	else
		FAIL="$FAIL
$@"
	fi
}

libdir=../lib/.libs:../libpacketdump/.libs
export LD_LIBRARY_PATH="$libdir:/usr/local/lib/"
export DYLD_LIBRARY_PATH="${libdir}"

rm -f traces/*.out.*
echo \* Read erf
do_test ./test-format-parallel erf

echo \* Read erf provenance
do_test ./test-format-parallel erfprov

echo \* Read pcap
do_test ./test-format-parallel pcap

echo \* Read pcapfile
do_test ./test-format-parallel pcapfile

echo \* Read pcapfilens
do_test ./test-format-parallel pcapfilens

echo \* Read legacyatm
do_test ./test-format-parallel legacyatm

echo \* Read legacyeth
do_test ./test-format-parallel legacyeth

echo \* Read legacypos
do_test ./test-format-parallel legacypos

echo \* Read tsh
do_test ./test-format-parallel tsh

echo \* Read rawerf
do_test ./test-format-parallel rawerf 

echo \* Read pcapng
do_test ./test-format-parallel pcapng

echo \* Read testing hasher function
do_test ./test-format-parallel-hasher erf

echo \* Read testing single-threaded datapath
do_test ./test-format-parallel-singlethreaded erf

echo \* Read testing single-threaded hasher datapath
do_test ./test-format-parallel-singlethreaded-hasher erf

echo \* Read stress testing with 100 threads
do_test ./test-format-parallel-stressthreads erf

echo \* Read testing reporter thread
do_test ./test-format-parallel-reporter erf

echo \* Testing Trace-Time Playback
do_test ./test-tracetime-parallel

echo
echo "Tests passed: $OK"
echo "Tests failed: $FAIL"
