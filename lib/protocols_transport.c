/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock 
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */


#include "libtrace.h"
#include "protocols.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h> // fprintf

/* This file contains all the protocol decoding functions for transport layer
 * protocols. This includes functions for access port numbers.
 *
 * Supported protocols include (but are not limited to):
 * 	TCP
 * 	UDP
 * 	ICMP
 */

/* Get the size of the payload as it was in the original packet, i.e. prior
 * to any truncation.
 *
 * Basically, wire length minus the packet headers.
 *
 * Currently only supports IP (v4 and v6) and TCP, UDP and ICMP. Will return
 * 0 if an unsupported protocol header is encountered, or if one of the 
 * headers is truncated.
 */
DLLEXPORT size_t trace_get_payload_length(const libtrace_packet_t *packet) {

	void *layer;
	uint16_t ethertype;
	uint8_t proto;
	uint32_t rem;
	libtrace_ip_t *ip;
	libtrace_ip6_t *ip6;
	libtrace_tcp_t *tcp;
	size_t len = 0;

	/* Just use the cached length if we can */
	if (packet->payload_length != -1)
		return packet->payload_length;	

	/* Set to zero so that we can return early without having to 
	 * worry about forgetting to update the cached value */
	((libtrace_packet_t *)packet)->payload_length = 0;
	layer = trace_get_layer3(packet, &ethertype, &rem);
	if (!layer)
		return 0;
	switch (ethertype) {
		case TRACE_ETHERTYPE_IP:
			ip = (libtrace_ip_t *)layer;
			if (rem < sizeof(libtrace_ip_t))
				return 0;
			len = ntohs(ip->ip_len) - (4 * ip->ip_hl);
		
			/* Deal with v6 within v4 */
			if (ip->ip_p == TRACE_IPPROTO_IPV6)
				len -= sizeof(libtrace_ip6_t);
			
			break;
		case TRACE_ETHERTYPE_IPV6:
			ip6 = (libtrace_ip6_t *)layer;
			if (rem < sizeof(libtrace_ip6_t))
				return 0;
			len = ntohs(ip6->plen);
			break;
		default:
			return 0;
	}

	layer = trace_get_transport(packet, &proto, &rem);
	if (!layer)
		return 0;
	
	switch(proto) {
		case TRACE_IPPROTO_TCP:
			if (rem < sizeof(libtrace_tcp_t))
				return 0;
			tcp = (libtrace_tcp_t *)layer;
			
			if (len < (size_t)(4 * tcp->doff))
				return 0;
			
			len -= (4 * tcp->doff);
			break;
		case TRACE_IPPROTO_UDP:
			len -= sizeof(libtrace_udp_t);
			break;
		case TRACE_IPPROTO_ICMP:
			len -= sizeof(libtrace_icmp_t);
			break;
		
		default:
			return 0;
	}


	((libtrace_packet_t *)packet)->payload_length = len;
	return len;

}

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

	if (packet->l4_header) {
		/*
		void *link;
		libtrace_linktype_t linktype;
		link = trace_get_packet_buffer(packet, &linktype, remaining);
		if (!link)
			return NULL;
		*/
		*proto = packet->transport_proto;
		/* *remaining -= (packet->l4_header - link); */
		*remaining = packet->l4_remaining;
		return packet->l4_header;
	}

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
			break;
		case TRACE_ETHERTYPE_IPV6: /* IPv6 */
			transport = trace_get_payload_from_ip6(
				(libtrace_ip6_t*)transport, proto, remaining);
			break;
		default:
			*proto = 0;
			transport = NULL;
			break;
			
	}

	((libtrace_packet_t *)packet)->transport_proto = *proto;
	((libtrace_packet_t *)packet)->l4_header = transport;
	((libtrace_packet_t *)packet)->l4_remaining = *remaining;


	return transport;
}

DLLEXPORT void *trace_get_ospf_header(libtrace_packet_t *packet,
		uint8_t *version, uint32_t *remaining) {
	uint8_t proto;
	void *ospf;
	uint32_t dummy_rem = 0;


	if (!remaining)
		remaining = &dummy_rem;

	assert(version != NULL && "version may not be NULL when calling trace_get_ospf_header!");

	ospf = trace_get_transport(packet, &proto, remaining);

	if (!ospf || proto != TRACE_IPPROTO_OSPF || *remaining == 0)
		return NULL;

	*version = *((uint8_t *)ospf);
	
	if (*version == 2 && *remaining < sizeof(libtrace_ospf_v2_t))
		return NULL;

	return ospf;
}

DLLEXPORT void *trace_get_ospf_contents_v2(libtrace_ospf_v2_t *header,
		uint8_t *ospf_type, uint32_t *remaining) {

	uint8_t dummy_type;
	char *ptr;
	
	assert(remaining != NULL && "remaining may not be NULL when calling trace_get_ospf_contents!");

	if (!ospf_type)
		ospf_type = &dummy_type;

	if (!header || *remaining < sizeof(libtrace_ospf_v2_t)) {
		*ospf_type = 0;
		*remaining = 0;
		return NULL;
	}
	
	*ospf_type = header->type;

	ptr = ((char *)header) + sizeof(libtrace_ospf_v2_t);
	*remaining -= sizeof(libtrace_ospf_v2_t);

	return (void *)ptr;

}

DLLEXPORT unsigned char *trace_get_first_ospf_link_from_router_lsa_v2(
		libtrace_ospf_router_lsa_v2_t *lsa,
		uint32_t *remaining) {

	unsigned char *link_ptr = NULL;
	assert(remaining != NULL && "remaining may not be NULL when calling trace_get_first_link_from_router_lsa_v2!");

	if (!lsa || *remaining < sizeof(libtrace_ospf_router_lsa_v2_t)) {
		*remaining = 0;
		return NULL;
	}

	link_ptr = ((unsigned char *)lsa) + sizeof(libtrace_ospf_router_lsa_v2_t);
	*remaining -= sizeof(libtrace_ospf_router_lsa_v2_t);
	return link_ptr;

}

DLLEXPORT unsigned char *trace_get_first_ospf_lsa_from_db_desc_v2(
		libtrace_ospf_db_desc_v2_t *db_desc,
		uint32_t *remaining) {

	unsigned char *lsa_ptr = NULL;

	assert(remaining != NULL && "remaining may not be NULL when calling trace_get_first_ospf_v2_lsa!");

	if (!db_desc || *remaining < sizeof(libtrace_ospf_db_desc_v2_t)) {
		*remaining = 0;
		return NULL;
	}
	
	lsa_ptr = ((unsigned char *)db_desc) + sizeof(libtrace_ospf_db_desc_v2_t);
	*remaining -= sizeof(libtrace_ospf_db_desc_v2_t);

	return lsa_ptr;
}

DLLEXPORT unsigned char *trace_get_first_ospf_lsa_from_update_v2(
		libtrace_ospf_ls_update_t *ls_update,
		uint32_t *remaining) {

	unsigned char *lsa_ptr = NULL;

	assert(remaining != NULL && "remaining may not be NULL when calling trace_get_first_ospf_v2_lsa!");

	if (!ls_update || *remaining < sizeof(libtrace_ospf_ls_update_t)) {
		*remaining = 0;
		return NULL;
	}
	
	lsa_ptr = ((unsigned char *)ls_update) + sizeof(libtrace_ospf_ls_update_t);
	*remaining -= sizeof(libtrace_ospf_ls_update_t);

	return lsa_ptr;
}

DLLEXPORT uint32_t trace_get_ospf_metric_from_as_external_lsa_v2(
		libtrace_ospf_as_external_lsa_v2_t *as_lsa) {

	uint32_t metric = 0;

	assert(as_lsa);

	metric = as_lsa->metric_a << 16;
	metric |= (as_lsa->metric_b << 8);
	metric |= as_lsa->metric_c;

	return metric;
}

DLLEXPORT uint32_t trace_get_ospf_metric_from_summary_lsa_v2(
		libtrace_ospf_summary_lsa_v2_t *sum_lsa) {

	uint32_t metric = 0;

	assert(sum_lsa);

	metric = sum_lsa->metric_a << 16;
	metric |= (sum_lsa->metric_b << 8);
	metric |= sum_lsa->metric_c;

	return metric;
}

DLLEXPORT int trace_get_next_ospf_link_v2(unsigned char **current,
		libtrace_ospf_link_v2_t **link,
		uint32_t *remaining,
		uint32_t *link_len) {

	if (*current == NULL || *remaining < sizeof(libtrace_ospf_link_v2_t)) {
		*remaining = 0;
		*link = NULL;
		return 0;
	}

	*link = (libtrace_ospf_link_v2_t *)*current;

	/* XXX The spec allows for multiple metrics for a single link. This
	 * approach won't support this, so we may need to be more intelligent
	 * about this in future */
	*remaining -= sizeof(libtrace_ospf_link_v2_t);
	*link_len = sizeof(libtrace_ospf_link_v2_t);
	*current += sizeof(libtrace_ospf_link_v2_t);
	
	return 1; 

}

DLLEXPORT int trace_get_next_ospf_lsa_v2(unsigned char **current,
		libtrace_ospf_lsa_v2_t **lsa_hdr,
		unsigned char **lsa_body,
                uint32_t *remaining,
                uint8_t *lsa_type,
                uint16_t *lsa_length) {

	int valid_lsa = 0;

	if (*current == NULL || *remaining < sizeof(libtrace_ospf_lsa_v2_t)) {
		*lsa_hdr = NULL;
		*lsa_body = NULL;
		*remaining = 0;

		return 0;

	}

	*lsa_hdr = (libtrace_ospf_lsa_v2_t *)(*current);
	*lsa_type = (*lsa_hdr)->lsa_type;
	*lsa_length = ntohs((*lsa_hdr)->length);

	/* Check that the LSA type is valid */
	switch (*lsa_type) {
		case TRACE_OSPF_LS_ROUTER:
		case TRACE_OSPF_LS_NETWORK:
		case TRACE_OSPF_LS_SUMMARY:
		case TRACE_OSPF_LS_ASBR_SUMMARY:
		case TRACE_OSPF_LS_EXTERNAL:
			valid_lsa = 1;
			break;
	}
		
	if (*lsa_length > *remaining || !valid_lsa) {
		/* LSA is incomplete or an invalid type.
		 *
		 * If this occurs, you've probably managed to read something
		 * that is NOT a legit LSA */
		*remaining = 0;
		return -1;
	}
	
	/* Some OSPF packets, e.g. LS ACKs, only contain LSA headers. If this
	 * is the case, we'll set the body pointer to NULL so the caller 
	 * can't read invalid data */
	if (*lsa_length == sizeof(libtrace_ospf_lsa_v2_t))
		*lsa_body = NULL;
	else
		*lsa_body = (*current + sizeof(libtrace_ospf_lsa_v2_t));

	*remaining -= *lsa_length;
	*current += *lsa_length;

	if (remaining == 0) {
		/* No more LSAs */
		return 0;
	}

	return 1;

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

/* Return the source port
 */
DLLEXPORT uint16_t trace_get_source_port(const libtrace_packet_t *packet)
{
	uint32_t remaining;
	uint8_t proto;
	const struct ports_t *port = 
		(const struct ports_t*)trace_get_transport((libtrace_packet_t*)packet,
			&proto, &remaining);

	/* Snapped too early */
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
	/* Snapped too early */
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


