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

if [[ -z "$GOT_NETNS" ]]; then
	./netns-env.sh "./$0"
	exit 0
fi

libdir=../lib/.libs:../libpacketdump/.libs
export LD_LIBRARY_PATH="$libdir"
export DYLD_LIBRARY_PATH="${libdir}"

declare -a formats=("pcapint" "int" "ring")

for a in "${formats[@]}"
do
	for b in "${formats[@]}"
	do
		echo
		echo ./test-live "$a" "$b"
		do_test ./test-live "$a" "$b"
		echo
		echo ./test-live-snaplen "$a" "$b"
		do_test ./test-live-snaplen "$a" "$b"
	done
done

echo
echo "Tests passed: $OK"
echo "Tests failed: $FAIL"