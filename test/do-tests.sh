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
echo SLL Decoder 
do_test ./test-decode2 pcap:traces/100_sll.pcap

echo 802.1x decoder
do_test ./test-decode2 pcap:traces/8021x.pcap

echo MPLS Decoder
do_test ./test-decode2 pcap:traces/10_mpls_ip.pcap

echo Radius Decoder
do_test ./test-decode2 pcap:traces/radius.pcap

rm -f traces/*.out.*
echo \* Read erf
do_test ./test-format erf
do_test ./test-decode erf

echo \* Read pcap
do_test ./test-format pcap
do_test ./test-decode pcap

echo \* Read pcapfile
do_test ./test-format pcapfile
do_test ./test-decode pcapfile

echo \* Read legacyatm
do_test ./test-format legacyatm
do_test ./test-decode legacyatm

echo \* Read legacyeth
do_test ./test-format legacyeth
do_test ./test-decode legacyeth

echo \* Read legacypos
do_test ./test-format legacypos
do_test ./test-decode legacypos

echo \* Read tsh
do_test ./test-format tsh
do_test ./test-decode tsh

echo \* Testing pcap-bpf
do_test ./test-pcap-bpf

echo \* Testing payload length
do_test ./test-plen

echo \* Testing event framework
do_test ./test-event

echo \* Testing time conversions
do_test ./test-time

echo \* Testing directions
do_test ./test-dir

echo \* Testing wireless
do_test ./test-wireless

echo \* Testing error handling
do_test ./test-errors

echo \* Testing drop counters for erf
do_test ./test-drops erf

echo \* Testing drop counters for pcapfile
do_test ./test-drops pcapfile

echo \* Testing drop counters for duck
do_test ./test-drops duck

echo \* Testing drop counters for legacyatm
do_test ./test-drops legacyatm

echo \* Testing drop counters for legacypos
do_test ./test-drops legacypos

echo \* Testing drop counters for legacyeth
do_test ./test-drops legacyeth

echo \* Testing drop counters for tsh
do_test ./test-drops tsh

echo \* Testing writing erf
do_test ./test-write erf 

echo \* Testing write pcap
do_test ./test-write pcap 

echo \* Testing write pcapfile
do_test ./test-write pcapfile 

# Not all types are convertable, for instance libtrace doesn't
# do rtclient output, and erf doesn't support 802.11
echo \* Conversions
echo " * erf -> erf"
rm -f traces/*.out.*
do_test ./test-convert erf erf

echo " * erf -> pcap"
do_test ./test-convert erf pcap

echo " * pcap -> erf"
rm -f traces/*.out.*
do_test ./test-convert pcap erf

echo " * pcapfile -> erf"
rm -f traces/*.out.*
do_test ./test-convert pcapfile erf

echo " * pcapfile -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert pcapfile pcapfile

echo " * pcap -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert pcap pcapfile

echo " * erf -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert erf pcapfile
#./test-convert rtclient erf
#./test-convert rtclient pcap

# This doesn't work because pcap doesn't support legacyatm's linktype
# so the packet is converted to a raw IP packet, which when read
# back in again doesn't match legacyatm's original packet.
#echo " * legacyatm -> pcapfile"
#rm -f traces/*.out.*
#./test-convert legacyatm pcapfile

echo " * legacyeth -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert legacyeth pcapfile

echo " * legacypos -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert legacypos pcapfile

echo " * duck -> duck"
rm -f traces/*.out.*
do_test ./test-convert duck duck

echo " * tsh -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert tsh pcapfile

echo " * tsh -> pcap"
rm -f traces/*.out.*
do_test ./test-convert tsh pcap

echo
echo "Tests passed: $OK"
echo "Tests failed: $FAIL"
