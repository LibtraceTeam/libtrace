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
export LD_LIBRARY_PATH="$libdir"
export DYLD_LIBRARY_PATH="${libdir}"

rm -f traces/*.out.*
echo \* Read erf
do_test ./test-format-parallel erf
do_test ./test-decode erf

echo \* Read pcap
do_test ./test-format-parallel pcap
do_test ./test-decode pcap

echo \* Read pcapfile
do_test ./test-format-parallel pcapfile
do_test ./test-decode pcapfile

echo \* Read pcapfilens
do_test ./test-format-parallel pcapfilens
do_test ./test-decode pcapfilens

echo \* Read legacyatm
do_test ./test-format-parallel legacyatm
do_test ./test-decode legacyatm

echo \* Read legacyeth
do_test ./test-format-parallel legacyeth
do_test ./test-decode legacyeth

echo \* Read legacypos
do_test ./test-format-parallel legacypos
do_test ./test-decode legacypos

echo \* Read tsh
do_test ./test-format-parallel tsh
do_test ./test-decode tsh

echo \* Read rawerf
do_test ./test-format-parallel rawerf 
do_test ./test-decode rawerf


echo
echo "Tests passed: $OK"
echo "Tests failed: $FAIL"