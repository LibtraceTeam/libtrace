#include "libtrace.h"
#include "protocols.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h> // fprintf

DLLEXPORT void *trace_get_transport(const libtrace_packet_t *packet, 
		uint8_t *proto,
		uint32_t *remaining
		) 
{
	uint8_t dummy_proto;
	uint16_t ethertype;
	uint32_t dummy_remaining;
	void *transport;

	if (!proto) proto=&dummy_proto;

	if (!remaining) remaining=&dummy_remaining;

	transport = trace_get_layer3(packet,&ethertype,remaining);

	if (!transport || *remaining == 0)
		return NULL;

	switch (ethertype) {
		case TRACE_ETHERTYPE_IP: /* IPv4 */
			transport=trace_get_payload_from_ip(
				(libtrace_ip_t*)transport, proto, remaining);
			/* IPv6 */
			if (transport && *proto == TRACE_IPPROTO_IPV6) {
				transport=trace_get_payload_from_ip6(
				 (libtrace_ip6_t*)transport, proto,remaining);
			}
			return transport;
		case TRACE_ETHERTYPE_IPV6: /* IPv6 */
			return trace_get_payload_from_ip6(
				(libtrace_ip6_t*)transport, proto, remaining);
			
		default:
			fprintf(stderr,"unknown ethertype=%04x\n",ethertype);
			*proto=0;
			return NULL;
	}

}

DLLEXPORT libtrace_tcp_t *trace_get_tcp(libtrace_packet_t *packet) {
	uint8_t proto;
	libtrace_tcp_t *tcp;

	tcp=(libtrace_tcp_t*)trace_get_transport(packet,&proto,NULL);

	if (!tcp || proto != TRACE_IPPROTO_TCP)
		return NULL;

	return (libtrace_tcp_t*)tcp;
}

DLLEXPORT libtrace_tcp_t *trace_get_tcp_from_ip(libtrace_ip_t *ip, uint32_t *remaining)
{
	libtrace_tcp_t *tcpptr = 0;

	if (ip->ip_p == 6)  {
		tcpptr = (libtrace_tcp_t *)
			trace_get_payload_from_ip(ip, NULL, remaining);
	}

	return tcpptr;
}

DLLEXPORT libtrace_udp_t *trace_get_udp(libtrace_packet_t *packet) {
	uint8_t proto;
	libtrace_udp_t *udp;

	udp=(libtrace_udp_t*)trace_get_transport(packet,&proto,NULL);

	if (!udp || proto != 17)
		return NULL;

	return udp;
}

DLLEXPORT libtrace_udp_t *trace_get_udp_from_ip(libtrace_ip_t *ip, uint32_t *remaining)
{
	libtrace_udp_t *udpptr = 0;

	if (ip->ip_p == TRACE_IPPROTO_UDP) {
		udpptr = (libtrace_udp_t *)
			trace_get_payload_from_ip(ip, NULL, remaining);
	}

	return udpptr;
}

DLLEXPORT libtrace_icmp_t *trace_get_icmp(libtrace_packet_t *packet) {
	uint8_t proto;
	libtrace_icmp_t *icmp;

	icmp=(libtrace_icmp_t*)trace_get_transport(packet,&proto,NULL);

	if (!icmp || proto != TRACE_IPPROTO_ICMP)
		return NULL;

	return icmp;
}

DLLEXPORT libtrace_icmp_t *trace_get_icmp_from_ip(libtrace_ip_t *ip, uint32_t *remaining)
{
	libtrace_icmp_t *icmpptr = 0;

	if (ip->ip_p == TRACE_IPPROTO_ICMP)  {
		icmpptr = (libtrace_icmp_t *)trace_get_payload_from_ip(ip, 
				NULL, remaining);
	}

	return icmpptr;
}

DLLEXPORT void *trace_get_payload_from_udp(libtrace_udp_t *udp, uint32_t *remaining)
{
	if (remaining) {
		if (*remaining < sizeof(libtrace_udp_t)) {
			*remaining = 0;
			return NULL;
		}
		*remaining-=sizeof(libtrace_udp_t);
	}
	return (void*)((char*)udp+sizeof(libtrace_udp_t));
}

DLLEXPORT void *trace_get_payload_from_tcp(libtrace_tcp_t *tcp, uint32_t *remaining)
{
	unsigned int dlen = tcp->doff*4;
	if (remaining) {
		if (*remaining < dlen) {
			*remaining = 0;
			return NULL;
		}
		*remaining-=dlen;
	}
	return (void *)((char *)tcp+dlen);
}

DLLEXPORT void *trace_get_payload_from_icmp(libtrace_icmp_t *icmp, uint32_t *remaining)
{
	if (remaining) {
		if (*remaining < sizeof(libtrace_icmp_t)) {
			*remaining = 0;
			return NULL;
		}
		*remaining-=sizeof(libtrace_icmp_t);
	}
	return (char*)icmp+sizeof(libtrace_icmp_t);
}

/* Return the client port
 */
DLLEXPORT uint16_t trace_get_source_port(const libtrace_packet_t *packet)
{
	uint32_t remaining;
	const struct ports_t *port = 
		(const struct ports_t*)trace_get_transport((libtrace_packet_t*)packet,
			NULL, &remaining);

	/* snapped too early */
	if (remaining<2)
		return 0;

	if (port)
		return ntohs(port->src);
	else
		return 0;
}

/* Same as get_source_port except use the destination port */
DLLEXPORT uint16_t trace_get_destination_port(const libtrace_packet_t *packet)
{
	uint32_t remaining;
	struct ports_t *port = 
		(struct ports_t*)trace_get_transport((libtrace_packet_t*)packet,
			NULL, &remaining);
	/* snapped to early */
	if (remaining<4)
		return 0;

	if (port)
		return ntohs(port->dst);
	else
		return 0;
}


