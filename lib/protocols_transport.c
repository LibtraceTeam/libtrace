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
			
	}

	*proto=0;
	return NULL;
}

DLLEXPORT libtrace_tcp_t *trace_get_tcp(libtrace_packet_t *packet) {
	uint8_t proto;
	uint32_t rem = 0;
	libtrace_tcp_t *tcp;

	tcp=(libtrace_tcp_t*)trace_get_transport(packet,&proto,&rem);

	if (!tcp || proto != TRACE_IPPROTO_TCP)
		return NULL;

	/* We should return NULL if there isn't a full TCP header, because the
	 * caller has no way of telling how much of a TCP header we have
	 * returned - use trace_get_transport() if you want to deal with
	 * partial headers 
	 *
	 * NOTE: We're not going to insist that all the TCP options are present
	 * as well, because lots of traces are snapped after 20 bytes of TCP
	 * header and I don't really want to break libtrace programs that
	 * use this function to process those traces */

	if (rem < sizeof(libtrace_tcp_t))
		return NULL;

	return (libtrace_tcp_t*)tcp;
}

DLLEXPORT libtrace_tcp_t *trace_get_tcp_from_ip(libtrace_ip_t *ip, uint32_t *remaining)
{
	libtrace_tcp_t *tcpptr = 0;

	if (ip->ip_p == TRACE_IPPROTO_TCP)  {
		tcpptr = (libtrace_tcp_t *)
			trace_get_payload_from_ip(ip, NULL, remaining);
	}

	return tcpptr;
}

DLLEXPORT libtrace_udp_t *trace_get_udp(libtrace_packet_t *packet) {
	uint8_t proto;
	uint32_t rem = 0;
	libtrace_udp_t *udp;

	udp=(libtrace_udp_t*)trace_get_transport(packet,&proto,&rem);

	if (!udp || proto != TRACE_IPPROTO_UDP)
		return NULL;

	/* Make sure we return a full UDP header as the caller has no way of
	 * telling how much of the packet is remaining */
	if (rem < sizeof(libtrace_udp_t))
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
	uint32_t rem = 0;
	libtrace_icmp_t *icmp;

	icmp=(libtrace_icmp_t*)trace_get_transport(packet,&proto,&rem);

	if (!icmp || proto != TRACE_IPPROTO_ICMP)
		return NULL;

	/* Make sure we return a full ICMP header as the caller has no way of
	 * telling how much of the packet is remaining */
	if (rem < sizeof(libtrace_icmp_t))
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
	uint8_t proto;
	const struct ports_t *port = 
		(const struct ports_t*)trace_get_transport((libtrace_packet_t*)packet,
			&proto, &remaining);

	/* snapped too early */
	if (remaining<2)
		return 0;

	/* ICMP *technically* doesn't have ports */
	if (proto == TRACE_IPPROTO_ICMP)
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
	uint8_t proto;
	struct ports_t *port = 
		(struct ports_t*)trace_get_transport((libtrace_packet_t*)packet,
			&proto, &remaining);
	/* snapped to early */
	if (remaining<4)
		return 0;
	
	/* ICMP *technically* doesn't have ports */
	if (proto == TRACE_IPPROTO_ICMP)
		return 0;

	if (port)
		return ntohs(port->dst);
	else
		return 0;
}


