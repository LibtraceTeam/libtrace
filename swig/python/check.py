#!/usr/bin/python
import sys
sys.path.append('/usr/local/lib/python2.4/site-packages/libtrace')
import libtrace

trace = libtrace.Trace(sys.argv[1])

if trace.is_err():
	print "Trace failed: %s" % trace.trace_get_err()
	sys.exit()
print "trace=",trace


packet = libtrace.Packet()

print "packet=",packet
count = 0

filter = libtrace.Filter("tcp")
print "filter=",filter

ret=trace.start()

if ret < 0:
	print "Trace failed to start with error %s " % ret
	sys.exit()

while 1:
	trace.read_packet(packet)
	if not packet:
		break

	ippacket = packet.get_ip()
	if not ippacket:
		continue

	count += 1
	if count % 10000 == 0:
		print count

	tcppacket = packet.get_tcp()
	if not tcppacket:
		continue

	if not packet.apply_filter(filter):
		continue
	
	src = packet.get_source_port()
	dst = packet.get_destination_port()
	if packet.get_server_port(4,src,dst) == 0:
		print ippacket.ip_src,':',src,'->',ippacket.ip_dst,':',dst
	else:	
		print ippacket.ip_dst,':',dst,'<-',ippacket.ip_src,':',src

