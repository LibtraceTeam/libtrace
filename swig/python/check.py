#!/usr/bin/python
import libtrace
import sys

trace = libtrace.Trace(sys.argv[1])

print "trace=",trace


packet = libtrace.Packet()

count = 0

filter = libtrace.Filter("tcp and port 80")

while 1:
	trace.trace_read_packet(packet)
	if not packet:
		break

	ippacket = packet.trace_get_ip()
	if not ippacket:
		continue

	tcppacket = packet.trace_get_tcp()
	if not tcppacket:
		continue

	if not packet.trace_bpf_filter(filter):
		continue

	print ippacket.ip_src,':',tcppacket.source,'->',ippacket.ip_dst,':',tcppacket.dest

