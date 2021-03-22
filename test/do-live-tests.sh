#!/bin/bash

OK=0
FAIL=""

PARALLEL_OK=0
PARALLEL_FAIL=""

do_test() {
	echo $@
	$@
	rc=$?
        if [[ rc -eq 0 ]]; then
		OK=$(( OK + 1 ))
        else
		FAIL="$FAIL
$*"
	fi

	echo
}

do_test_dag() {
	# $1 = application, $2 = read_uri, $3 = write_uri
        echo "$1" -r "$2"
        timeout 30 "$1" "-r" "$2" &
        read_pid=$!

        sleep 2

        echo "$1" -w "$3"
        timeout 30 "$1" -w "$3" &
	write_pid=$!

	wait $write_pid
	wc=$?

        wait $read_pid
	rc=$?

	if [[ rc -eq 0 && wc -eq 0 ]]
	then
                OK=$(( OK + 1 ))
        else
                FAIL="$FAIL
$*"
        fi

	echo
        sleep 2
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
declare -a dag_formats=()
if [[ $# -eq 0 ]]; then
	declare -a write_formats=("pcapint:veth0" "int:veth0" "ring:veth0" "dpdkvdev:net_pcap0,iface=veth0" "xdp:veth0")
	declare -a read_formats=("pcapint:veth1" "int:veth1" "ring:veth1" "dpdkvdev:net_pcap1,iface=veth1" "xdp:veth1")
	declare -a dag_formats=("dag:/dev/dag16,0")
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
	int|ring|xdp|pfringzc|pcapint)
		write_formats+=("$key:veth0")
		read_formats+=("$key:veth1")
		;;
	pfring)
		read_formats+=("$key:veth1")
		;;
	dag)
		dag_formats+=("$key:/dev/dag16,0")
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
		do_test ./test-live "$w" "$r"
		do_test ./test-live-snaplen "$w" "$r"
	done
done
for w in "${dag_formats[@]}"
do
	do_test_dag ./test-live-dag "$w" "$w"
done

echo
echo "Single threaded API tests passed: $OK"
echo "Single threaded API tests failed: $FAIL"
echo

echo
echo "Running parallel API tests"
echo
do_parallel_test() {
	#params $1 = application, $2 = read_uri, $3 = write_uri, $4 = additional args
	echo
	echo "$1" "$4" "-r" "$2"
	timeout 30 "$1" "$4" "-r" "$2" &
	my_pid=$!
	sleep 2  # Ensure we've had time to setup, particularly dpdk
	if ! ./test-live "$3"; then
		echo "TEST ERROR: ./test-live $3 (couldn't generate packets)"
		exit -1
	fi
	sleep 10  # Wait for all packets to be received
	kill -SIGINT $my_pid
	wait $my_pid
	rc=$?
	if [[ rc -eq 0 ]]; then
		PARALLEL_OK=$(( PARALLEL_OK + 1 ))
	else
		PARALLEL_FAIL="$PARALLEL_FAIL
$*"
	fi
	sleep 2
}

for r in "${read_formats[@]}"
do
	# Don't test pcapint as it only has a 30 packet buffer and
	# it always drops packets and fails to capture all 100
	if [[ $r == "pcapint:veth1" ]]; then
		continue
	fi
	do_parallel_test ./test-format-parallel "$r" "int:veth1"
	do_parallel_test ./test-format-parallel-hasher "$r" "int:veth1"
	# TODO fix test-format-parallel-reporter for live input
	# do_parallel_test ./test-format-parallel-reporter "$r" "int:veth1"
	do_parallel_test ./test-format-parallel-singlethreaded "$r" "int:veth1"
	do_parallel_test ./test-format-parallel-singlethreaded-hasher "$r" "int:veth1"

done

for r in "${dag_formats[@]}"
do
	do_parallel_test ./test-format-parallel "$r" "dag:/dev/dag16,0" "-p"
	do_parallel_test ./test-format-parallel-hasher "$r" "dag:/dev/dag16,0" "-p"
	# TODO fix test-format-parallel-reporter for live input
        #do_parallel_test ./test-format-parallel-reporter "$r" "dag:/dev/dag16,0" "-p"
	do_parallel_test ./test-format-parallel-singlethreaded "$r" "dag:/dev/dag16,0" "-p"
	do_parallel_test ./test-format-parallel-singlethreaded-hasher "$r" "dag:/dev/dag16,0" "-p"
done
echo
echo "Single threaded API tests passed: $OK"
echo "Single threaded API tests failed: $FAIL"
echo
echo "Parallel API tests passed: $PARALLEL_OK"
echo "Parallel API tests failed: $PARALLEL_FAIL"


if [[ -z "$FAIL" ]]
then
        exit 0
else
        exit 1
fi
