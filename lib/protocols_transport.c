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


#include "libtrace_int.h"
#include "libtrace.h"
#include "protocols.h"
#include "checksum.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h> // fprintf
#include <string.h>

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
			if (rem < sizeof(libtrace_udp_t))
				return 0;
			if (len < sizeof(libtrace_udp_t))
				return 0;
			len -= sizeof(libtrace_udp_t);
			break;
		case TRACE_IPPROTO_ICMP:
			if (rem < sizeof(libtrace_icmp_t))
				return 0;
			if (len < sizeof(libtrace_icmp_t))
				return 0;
			len -= sizeof(libtrace_icmp_t);
			break;
		case TRACE_IPPROTO_ICMPV6:
			if (rem < sizeof(libtrace_icmp6_t))
				return 0;
			if (len < sizeof(libtrace_icmp6_t))
				return 0;
			len -= sizeof(libtrace_icmp6_t);
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

DLLEXPORT libtrace_icmp6_t *trace_get_icmp6(libtrace_packet_t *packet) {
	uint8_t proto;
	uint32_t rem = 0;
	libtrace_icmp6_t *icmp;

	icmp=(libtrace_icmp6_t*)trace_get_transport(packet,&proto,&rem);

	if (!icmp || proto != TRACE_IPPROTO_ICMPV6)
		return NULL;

	/* Make sure we return a full ICMP header as the caller has no way of
	 * telling how much of the packet is remaining */
	if (rem < sizeof(libtrace_icmp6_t))
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

DLLEXPORT void *trace_get_payload_from_icmp6(libtrace_icmp6_t *icmp, uint32_t *remaining)
{
	if (remaining) {
		if (*remaining < sizeof(libtrace_icmp6_t)) {
			*remaining = 0;
			return NULL;
		}
		*remaining-=sizeof(libtrace_icmp6_t);
	}
	return (char*)icmp+sizeof(libtrace_icmp6_t);
}

/* Return the source port
 */
DLLEXPORT uint16_t trace_get_source_port(const libtrace_packet_t *packet)
{
	uint32_t remaining;
	uint8_t proto;
	struct ports_t *port;
        uint16_t fragoff;
        uint8_t more;

        fragoff = trace_get_fragment_offset(packet, &more);

        /* If we're not the first fragment, we're unlikely to be able
         * to get any useful port numbers from this packet.
         */
        if (fragoff != 0)
                return 0;
        
        
        port = (struct ports_t*)trace_get_transport(
                        (libtrace_packet_t*)packet,
			&proto, &remaining);

	/* Snapped too early */
	if (remaining<2)
		return 0;

	/* ICMP *technically* doesn't have ports */
	if (proto == TRACE_IPPROTO_ICMP || proto == TRACE_IPPROTO_ICMPV6)
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
	struct ports_t *port;
        uint16_t fragoff;
        uint8_t more;

        fragoff = trace_get_fragment_offset(packet, &more);

        /* If we're not the first fragment, we're unlikely to be able
         * to get any useful port numbers from this packet.
         */
        if (fragoff != 0)
                return 0;
        
        
        port = (struct ports_t*)trace_get_transport(
                        (libtrace_packet_t*)packet,
			&proto, &remaining);
	/* Snapped too early */
	if (remaining<4)
		return 0;
	
	/* ICMP *technically* doesn't have ports */
	if (proto == TRACE_IPPROTO_ICMP || proto == TRACE_IPPROTO_ICMPV6)
		return 0;

	if (port)
		return ntohs(port->dst);
	else
		return 0;
}

DLLEXPORT uint16_t *trace_checksum_transport(libtrace_packet_t *packet, 
		uint16_t *csum) {

	void *header = NULL;
	uint16_t ethertype;
	uint32_t remaining;
	uint32_t sum = 0;
	uint8_t proto = 0;
	uint16_t *csum_ptr = NULL;
	int plen = 0;

	uint8_t safety[65536];
	uint8_t *ptr = safety;

	header = trace_get_layer3(packet, &ethertype, &remaining);

	if (header == NULL)
		return NULL;
	
	if (ethertype == TRACE_ETHERTYPE_IP) {
		libtrace_ip_t *ip = (libtrace_ip_t *)header;

		if (remaining < sizeof(libtrace_ip_t))
			return NULL;

		sum = ipv4_pseudo_checksum(ip);

	} else if (ethertype == TRACE_ETHERTYPE_IPV6) {
		libtrace_ip6_t *ip = (libtrace_ip6_t *)header;
		
		if (remaining < sizeof(libtrace_ip6_t))
			return 0;

		sum = ipv6_pseudo_checksum(ip);
	
	}

	header = trace_get_transport(packet, &proto, &remaining);

	if (proto == TRACE_IPPROTO_TCP) {
		libtrace_tcp_t *tcp = (libtrace_tcp_t *)header;
		header = trace_get_payload_from_tcp(tcp, &remaining);
		
		csum_ptr = &tcp->check;

		memcpy(ptr, tcp, tcp->doff * 4);

		tcp = (libtrace_tcp_t *)ptr;
		tcp->check = 0;

		ptr += (tcp->doff * 4);
	} 
	
	else if (proto == TRACE_IPPROTO_UDP) {

		libtrace_udp_t *udp = (libtrace_udp_t *)header;
		header = trace_get_payload_from_udp(udp, &remaining);
		
		csum_ptr = &udp->check;
		memcpy(ptr, udp, sizeof(libtrace_udp_t));

		udp = (libtrace_udp_t *)ptr;
		udp->check = 0;

		ptr += sizeof(libtrace_udp_t);
	} 
	
	else if (proto == TRACE_IPPROTO_ICMP) {
		/* ICMP doesn't use the pseudo header */
		sum = 0;

		libtrace_icmp_t *icmp = (libtrace_icmp_t *)header;
		header = trace_get_payload_from_icmp(icmp, &remaining);
		
		csum_ptr = &icmp->checksum;
		memcpy(ptr, icmp, sizeof(libtrace_icmp_t));

		icmp = (libtrace_icmp_t *)ptr;
		icmp->checksum = 0;
		
		ptr += sizeof(libtrace_icmp_t);

	} 
	else {
		return NULL;
	}

	sum += add_checksum(safety, (uint16_t)(ptr - safety));

	plen = trace_get_payload_length(packet);
	if (plen < 0)
		return NULL;

	if (remaining < (uint32_t)plen)
		return NULL;

	if (header == NULL)
		return NULL;

	sum += add_checksum(header, (uint16_t)plen);
	*csum = ntohs(finish_checksum(sum));
	//assert(0);
	
	return csum_ptr;
}

DLLEXPORT void *trace_get_payload_from_gre(libtrace_gre_t *gre,
        uint32_t *remaining)
{
    uint32_t size = 4; /* GRE is 4 bytes long by default */
    if (remaining && *remaining < size) {
        *remaining = 0;
        return NULL;
    }

    if ((ntohs(gre->flags) & LIBTRACE_GRE_FLAG_CHECKSUM) != 0) {
        size += 4;  /* An extra 4 bytes. */
    }

    if ((ntohs(gre->flags) & LIBTRACE_GRE_FLAG_KEY) != 0) {
        size += 4;  /* An extra 4 bytes. */
    }

    if ((ntohs(gre->flags) & LIBTRACE_GRE_FLAG_SEQ) != 0) {
        size += 4;  /* An extra 4 bytes. */
    }

    if (remaining) {
        if (*remaining < size) {
            *remaining = 0;
            return NULL;
        }
        *remaining -= size;
    }
    return (char*)gre+size;
}
