#!/usr/bin/python
import libtrace
import sys

trace = libtrace.Trace(sys.argv[1])

print "trace=",trace

packet = trace.read_packet()

print "packet=",packet

while 1:
	packet = trace.read_packet()
	if not packet:
		break
	print packet.get_ip().ip_src,'->',packet.get_ip().ip_dst

