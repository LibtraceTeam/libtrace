#!/usr/bin/python
import libtrace
import sys

trace = libtrace.Trace(sys.argv[1])

print "trace=",trace



while 1:
	packet = libtrace.Packet()
	trace.trace_read_packet(packet)
	if not packet:
		break
	ippacket = packet.trace_get_ip()
	if not ippacket:
		continue

	print ippacket.ip_src,'->',ippacket.ip_dst

