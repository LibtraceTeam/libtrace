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
export LD_LIBRARY_PATH="$libdir:/usr/local/lib/"
export DYLD_LIBRARY_PATH="${libdir}"

rm -f traces/*.out.*
echo \* Read erf
do_test ./test-format-parallel -r erf

echo \* Read erf provenance
do_test ./test-format-parallel -r erfprov

echo \* Read pcap
do_test ./test-format-parallel -r pcap

echo \* Read pcapfile
do_test ./test-format-parallel -r pcapfile

echo \* Read pcapfilens
do_test ./test-format-parallel -r pcapfilens

echo \* Read legacyatm
do_test ./test-format-parallel -r legacyatm

echo \* Read legacyeth
do_test ./test-format-parallel -r legacyeth

echo \* Read legacypos
do_test ./test-format-parallel -r legacypos

echo \* Read tsh
do_test ./test-format-parallel -r tsh

echo \* Read rawerf
do_test ./test-format-parallel -r rawerf

echo \* Read pcapng
do_test ./test-format-parallel -r pcapng

echo \* Read etsilive
if command -v socat > /dev/null
then
	{
		sleep 1;
		socat - TCP:127.0.0.1:60198 < ./traces/etsi_10_pings_HI3.raw_tcp > /dev/null
	} &
	do_test ./test-format-parallel -p -c 20 -t 1 -r etsilive:127.0.0.1:60198
else
	echo "Netcat not found: skipping etsilive test"
fi

echo \* Read testing hasher function
do_test ./test-format-parallel-hasher -r erf

echo \* Read testing single-threaded datapath
do_test ./test-format-parallel-singlethreaded -r erf

echo \* Read testing single-threaded hasher datapath
do_test ./test-format-parallel-singlethreaded-hasher -r erf

echo \* Read stress testing with 100 threads
do_test ./test-format-parallel-stressthreads -r erf

echo \* Read testing reporter thread
do_test ./test-format-parallel-reporter -r erf

echo \* Testing Trace-Time Playback
do_test ./test-tracetime-parallel

echo
echo "Tests passed: $OK"
echo "Tests failed: $FAIL"

if [ -z "$FAIL" ]
then
        exit 0
else
        exit 1
fi
