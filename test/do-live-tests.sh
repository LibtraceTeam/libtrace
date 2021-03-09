#!/bin/bash

OK=0
UNSUPPORTED=""
FAIL=""

PARALLEL_OK=0
PARALLEL_UNSUPPORTED=""
PARALLEL_FAIL=""

do_test() {
	$@
	rc=$?
        if [[ rc -eq 0 ]]; then
		OK=$(( OK + 1 ))
        elif [[ rc -eq 1 ]]; then
		UNSUPPORTED="$UNSUPPORTED
$*"
        else
		FAIL="$FAIL
$*"
	fi
}

if [[ -z "$GOT_NETNS" ]]; then
	./netns-env.sh "$0" "$@"
	exit $?
fi

# If we already have LD_LIBRARY_PATH set assume it correctly
# points to libtrace we want to test.
if [[ -z "$LD_LIBRARY_PATH" ]]; then
	libdir=../lib/.libs:../libpacketdump/.libs
	export LD_LIBRARY_PATH="$libdir:/usr/local/lib/"
	export DYLD_LIBRARY_PATH="${libdir}"
fi

declare -a write_formats=()
declare -a read_formats=()
if [[ $# -eq 0 ]]; then
	declare -a write_formats=("pcapint:veth0" "int:veth0" "ring:veth0" "dpdkvdev:net_pcap0,iface=veth0" "xdp:veth0")
	declare -a read_formats=("pcapint:veth1" "int:veth1" "ring:veth1" "dpdkvdev:net_pcap1,iface=veth1" "xdp:veth1")
fi

while [[ $# -gt 0 ]]; do
	key="$1"
	case $key in
	pcap)
		write_formats+=("pcapint:veth0")
		read_formats+=("pcapint:veth1")
		;;
	dpdk)
		write_formats+=("dpdkvdev:net_pcap0,iface=veth0")
		read_formats+=("dpdkvdev:net_pcap1,iface=veth1")
		;;
	int|ring|xdp|pcapint)
		write_formats+=("$key:veth0")
		read_formats+=("$key:veth1")
		;;
	*)
		echo "Unknown argument $key"
	esac
	shift
done
echo "Testing formats: ${write_formats[*]}"

echo "Running single threaded API tests"
for w in "${write_formats[@]}"
do
	for r in "${read_formats[@]}"
	do
		echo
		echo ./test-live "$w" "$r"
		do_test ./test-live "$w" "$r"
		echo
		echo ./test-live-snaplen "$w" "$r"
		do_test ./test-live-snaplen "$w" "$r"
	done
done

echo
echo "Single threaded API tests passed: $OK"
echo "Single threaded API tests unsupported: $UNSUPPORTED"
echo "Single threaded API tests failed: $FAIL"
echo

echo
echo "Running parallel API tests"
echo
do_parallel_test() {
	echo
	echo "$@"
	timeout 5 "$@" &
	my_pid=$!
	sleep 2  # Ensure we've had time to setup, particularly dpdk
	if ! ./test-live "int:veth0"; then
		echo "TEST ERROR: ./test-live int:veth0 (couldn't generate packets)"
		exit -1
	fi
	sleep 1  # Wait for all packets to be received
	kill -SIGINT $my_pid
	wait $my_pid
	rc=$?
	if [[ rc -eq 0 ]]; then
		PARALLEL_OK=$(( PARALLEL_OK + 1 ))
	elif [[ rc -eq 1 ]]; then
		PARALLEL_UNSUPPORTED="$PARALLEL_UNSUPPORTED
$*"
	else

		PARALLEL_FAIL="$PARALLEL_FAIL
$*"
	fi
}

for r in "${read_formats[@]}"
do
	# Don't test pcapint as it only has a 30 packet buffer and
	# it always drops packets and fails to capture all 100
	if [[ $r == "pcapint:veth1" ]]; then
		continue
	fi
	do_parallel_test ./test-format-parallel "$r"
	do_parallel_test ./test-format-parallel-hasher "$r"
	# TODO fix test-format-parallel-reporter for live input
	# do_parallel_test ./test-format-parallel-reporter "$r"
	do_parallel_test ./test-format-parallel-singlethreaded "$r"
	do_parallel_test ./test-format-parallel-singlethreaded-hasher "$r"

done

echo
echo "Single threaded API tests passed: $OK"
echo "Single threaded API tests unsupported: $UNSUPPORTED"
echo "Single threaded API tests failed: $FAIL"
echo
echo "Parallel API tests passed: $PARALLEL_OK"
echo "Parallel API tests unsupported: $PARALLEL_UNSUPPORTED"
echo "Parallel API tests failed: $PARALLEL_FAIL"


if [ -z "$FAIL" ] && [ -z "$PARALLEL_FAIL" ]
then
        exit 0
else
        exit 1
fi
