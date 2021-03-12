#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
libdir=../lib/.libs:../libpacketdump/.libs
export LD_LIBRARY_PATH="$libdir:/usr/local/lib/"
export DYLD_LIBRARY_PATH="${libdir}"

PASSED=()
FAILED=()

do_test() {
	# start read
	echo "$1 $2 $3"
	"$1" "$2" "$3" &
	read_pid=$!
	sleep 1

	# start write
	echo "$4 $5 $6"
	"$4" "$5" "$6" &
	write_pid=$!

	wait $read_pid
	rc=$?
	wait $write_pid

	if [[ rc -eq 0 ]]
        then
                PASSED="$PASSED
$1 $2 $3 -> $4 $5 $6"
        else
                FAILED="$FAILED
$1 $2 $3 -> $4 $5 $6"
        fi

}

do_test_parallel() {
	# start read app
	echo "$3 $4"
	timeout 30 "$3" "$4" &
	read_pid=$!
	sleep 1

	# start write app
	echo "$1 $2"
	timeout 30 "$1" "$2" &
	write_pid=$!
	sleep 15

	kill -SIGINT $read_pid
        wait $read_pid
        rc=$?

	if [[ rc -eq 0 ]]
	then
		PASSED="$PASSED
$1 $2 -> $3 $4"
	else
		FAILED="$FAILED
$1 $2 -> $3 $4"
	fi
}

do_test ./test-live-dag "-r" "dag:/dev/dag16,0" ./test-live-dag "-w" "dag:/dev/dag16,0"

#do_test_parallel ./test-live "dag:/dev/dag16,0" ./test-format-parallel "dag:/dev/dag16,0"
#do_test_parallel ./test-live "dag:/dev/dag16,0" ./test-format-parallel-hasher "dag:/dev/dag16,0"
#do_test_parallel ./test-live "dag:/dev/dag16,0" ./test-format-parallel-singlethreaded "dag:/dev/dag16,0"
#do_test_parallel ./test-live "dag:/dev/dag16,0" ./test-format-parallel-singlethreaded-hasher "dag:/dev/dag16,0"

echo
echo "Passed tests: $PASSED"
echo "Failed tests: $FAILED"
echo
