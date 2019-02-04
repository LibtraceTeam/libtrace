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
echo SLL Decoder 
do_test ./test-decode2 pcap:traces/100_sll.pcap
do_test ./test-decode2 pcapfile:traces/sll.pcap.gz

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

echo \* Read erf provenance
do_test ./test-format erfprov

echo \* Read pcap
do_test ./test-format pcap
do_test ./test-decode pcap

echo \* Read pcapfile
do_test ./test-format pcapfile
do_test ./test-decode pcapfile

echo \* Read pcapfilens
do_test ./test-format pcapfilens
do_test ./test-decode pcapfilens

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

echo \* Read rawerf
do_test ./test-format rawerf 
do_test ./test-decode rawerf

echo \* Read pcapng
do_test ./test-format pcapng
do_test ./test-decode pcapng


echo \* Testing pcap-bpf
do_test ./test-pcap-bpf

echo \* Testing payload length
do_test ./test-plen

echo \* Testing wire length
echo \* ERF
do_test ./test-wlen erf
echo \* pcapfile
do_test ./test-wlen pcapfile
echo \* pcapfilens
do_test ./test-wlen pcapfilens
echo \* legacyatm
do_test ./test-wlen legacyatm
echo \* legacypos
do_test ./test-wlen legacypos
echo \* legacyeth
do_test ./test-wlen legacyeth
echo \* rawerf
do_test ./test-wlen rawerf
echo \* pcap
do_test ./test-wlen pcap
echo \* tsh
do_test ./test-wlen tsh
echo \* pcapng
do_test ./test-wlen pcapng

echo \* Testing port numbers
do_test ./test-ports

echo \* Testing fragment parsing
do_test ./test-fragment

echo \* Testing event framework
do_test ./test-event

echo \* Testing time conversions
echo \* ERF
do_test ./test-time erf
echo \* pcapfile
do_test ./test-time pcapfile
echo \* pcapfilens
do_test ./test-time pcapfilens
echo \* legacyatm
do_test ./test-time legacyatm
echo \* legacypos
do_test ./test-time legacypos
echo \* legacyeth
do_test ./test-time legacyeth
echo \* pcap
do_test ./test-time pcap
echo \* rawerf
do_test ./test-time rawerf
echo \* tsh
do_test ./test-time tsh
echo \* pcapng
do_test ./test-time pcapng

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

echo \* Testing larger trace file
do_test ./test-drops legacylarge

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
rm -f traces/*.out.*
do_test ./test-convert erf pcap

echo " * erf -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert erf pcapfile

echo " * erf -> pcapng"
rm -f traces/*.out.*
do_test ./test-convert erf pcapng


echo " * pcap -> pcap"
rm -f traces/*.out.*
do_test ./test-convert pcap pcap

echo " * pcap -> erf"
rm -f traces/*.out.*
do_test ./test-convert pcap erf

echo " * pcap -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert pcap pcapfile

echo " * pcap -> pcapng"
rm -f traces/*.out.*
do_test ./test-convert pcap pcapng


echo " * pcapfile -> erf"
rm -f traces/*.out.*
do_test ./test-convert pcapfile erf

echo " * pcapfile -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert pcapfile pcapfile

echo " * pcapfile -> pcap"
rm -f traces/*.out.*
do_test ./test-convert pcapfile pcap

echo " * pcapfile -> pcapng"
rm -f traces/*.out.*
do_test ./test-convert pcapfile pcapng


echo " * pcapfilens -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert pcapfilens pcapfile

echo " * pcapfilens -> erf"
rm -f traces/*.out.*
do_test ./test-convert pcapfilens erf


echo " * pcapng -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert pcapng pcapfile

echo " * pcapng -> erf"
rm -f traces/*.out.*
do_test ./test-convert pcapng erf

echo " * pcapng -> pcap"
rm -f traces/*.out.*
do_test ./test-convert pcapng pcap

echo " * pcapng -> pcapng"
rm -f traces/*.out.*
do_test ./test-convert pcapng pcapng


echo " * pcap (sll) -> erf    raw IP"
rm -f traces/*.out.*
do_test ./test-convert sll1 erf

echo " * pcap (sll) -> erf    loopback"
rm -f traces/*.out.*
do_test ./test-convert sll2 erf


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

# Don't bother with this anymore -- DUCK qualifies as 'meta' so
# doesn't get written at the moment.
#echo " * duck -> duck"
#rm -f traces/*.out.*
#do_test ./test-convert duck duck

echo " * tsh -> pcapfile"
rm -f traces/*.out.*
do_test ./test-convert tsh pcapfile

echo " * tsh -> pcap"
rm -f traces/*.out.*
do_test ./test-convert tsh pcap

echo \* Testing packet truncation
echo " * pcap "
rm -f traces/*.out.*
do_test ./test-setcaplen pcap pcapfile

echo " * pcapfile "
rm -f traces/*.out.*
do_test ./test-setcaplen pcapfile pcapfile

echo " * erf "
rm -f traces/*.out.*
do_test ./test-setcaplen erf erf

echo " * pcapng "
rm -f traces/*.out.*
do_test ./test-setcaplen pcapng pcapfile

echo " * pcapfilens "
rm -f traces/*.out.*
do_test ./test-setcaplen pcapfilens pcapfile



echo " * format autodetection - uncompressed"
do_test ./test-autodetect traces/5_packets.erf
echo " * format autodetection - gzip"
do_test ./test-autodetect traces/5_packets.erf.gz
echo " * format autodetection - bzip2"
do_test ./test-autodetect traces/5_packets.erf.bz2
echo " * format autodetection - lzma"
do_test ./test-autodetect traces/5_packets.erf.xz

echo " * VXLan decode"
do_test ./test-vxlan

echo
echo "Tests passed: $OK"
echo "Tests failed: $FAIL"
