#!/bin/sh

./tracemerge erf:trace1.erf \
	erf:../../test/traces/100_packets.erf \
	pcap:../../test/traces/100_packets.pcap
