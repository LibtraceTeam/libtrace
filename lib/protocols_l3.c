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
#include <arpa/inet.h>

#ifdef HAVE_NETPACKET_PACKET_H
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <string.h>
#else
#include <net/if_dl.h>
#include <string.h>
#endif

/* This file contains all the protocol decoding functions for layer 3
 * (the IP layer) protocols. This includes functions for accessing IP
 * addresses. 
 *
 * Supported protocols include:
 * 	IPv4
 * 	IPv6
 */

/* Gets an IPv4 header */
libtrace_ip_t *trace_get_ip(libtrace_packet_t *packet) 
{
	uint16_t ethertype;
	void *ret;

	uint32_t remaining = trace_get_capture_length(packet);

	ret = trace_get_layer3(packet,&ethertype,&remaining);

	if (!ret || ethertype!=TRACE_ETHERTYPE_IP)
		return NULL;

	/* Make sure we have at least a base IPv4 header */
	if (remaining < sizeof(libtrace_ip_t)) 
		return NULL;
	
	/* Not an IPv4 packet */
	if (((libtrace_ip_t*)ret)->ip_v != 4)
		return NULL;

	return (libtrace_ip_t*)ret;
}

libtrace_ip6_t *trace_get_ip6(libtrace_packet_t *packet) 
{
	uint16_t ethertype;
	void *ret;

	uint32_t remaining = trace_get_capture_length(packet);

	ret = trace_get_layer3(packet,&ethertype,&remaining);

	if (!ret || ethertype!=TRACE_ETHERTYPE_IPV6)
		return NULL;

	/* Make sure we have at least the base IPv6 header */
	if (remaining < sizeof(libtrace_ip6_t))
		return NULL;

	return (libtrace_ip6_t*)ret;
}

#define SW_IP_OFFMASK 0x1fff

DLLEXPORT void *trace_get_payload_from_ip(libtrace_ip_t *ipptr, uint8_t *prot,
		uint32_t *remaining) 
{
        void *trans_ptr = 0;

        assert(ipptr != NULL);
	
	/* Er? IPv5? */
	if (ipptr->ip_v != 4)
		return NULL;

	if ((ntohs(ipptr->ip_off) & SW_IP_OFFMASK) != 0) {
		if (remaining)
			*remaining = 0;		
		return NULL;
	}

	if (remaining) {
		if (*remaining<(ipptr->ip_hl*4U)) {
			*remaining = 0;
			return NULL;
		}
		/* If the packet features extra "padding", we probably
		 * don't want that counting as possible payload, e.g. for
		 * payload length calculations */
		//if (*remaining > ntohs(ipptr->ip_len))
		//	*remaining = ntohs(ipptr->ip_len);

		*remaining-=(ipptr->ip_hl * 4);
	}

        trans_ptr = (void *)((char *)ipptr + (ipptr->ip_hl * 4));

	if (prot) *prot = ipptr->ip_p;

        return trans_ptr;
}

void *trace_get_payload_from_ip6(libtrace_ip6_t *ipptr, uint8_t *prot,
		uint32_t *remaining) 
{
	void *payload = (char*)ipptr+sizeof(libtrace_ip6_t);
	uint8_t nxt;
	uint16_t len;

	assert (ipptr != NULL);
 	nxt = ipptr->nxt;	
	if (remaining) {
		if (*remaining<sizeof(libtrace_ip6_t)) {
			*remaining = 0;
			return NULL;
		}
		*remaining-=sizeof(libtrace_ip6_t);
	}

	while(1) {
		switch (nxt) {
			case 0: /* hop by hop options */
			case TRACE_IPPROTO_ROUTING:
			case TRACE_IPPROTO_AH: 
			case TRACE_IPPROTO_DSTOPTS: 
			{
				/* Length does not include the first 8 bytes */
				len=((libtrace_ip6_ext_t*)payload)->len * 8;
				len += 8;


				if (remaining) {
					if (*remaining < len) {
						/* Snap too short */
						*remaining = 0;
						return NULL;
					}
					*remaining-=len;
				}

				nxt=((libtrace_ip6_ext_t*)payload)->nxt;
				payload=(char*)payload+len;
				continue;
			}
			case TRACE_IPPROTO_ESP: 
			{
				if (prot) *prot=TRACE_IPPROTO_ESP;
				return payload;
			}
			case TRACE_IPPROTO_FRAGMENT:
				{
					len = sizeof(libtrace_ip6_frag_t);
					if (remaining) {
						if (*remaining < len) {
							/* Snap too short */
							*remaining = 0;
							return NULL;
						}
						*remaining-=len;
					}
					nxt=((libtrace_ip6_frag_t*)payload)->nxt;
					payload=(char*)payload+len;
					continue;
				}

			default:
				if (prot) *prot=nxt;
				return payload;
		}
	}
}

DLLEXPORT void *trace_get_layer3(const libtrace_packet_t *packet,
		uint16_t *ethertype,
		uint32_t *remaining)
{
	void *iphdr;
	uint16_t dummy_ethertype;
	void *link;
	uint32_t dummy_remaining;
	libtrace_linktype_t linktype;

	if (!ethertype) ethertype=&dummy_ethertype;

	if (!remaining) remaining=&dummy_remaining;

	/* use l3 cache */
	if (packet->l3_header)
	{
		/*
		link = trace_get_packet_buffer(packet,&linktype,remaining);

		if (!link)
			return NULL;
		*/

		*ethertype = packet->l3_ethertype;
		/* *remaining -= (packet->l3_header - link); */
		*remaining = packet->l3_remaining;

		return packet->l3_header;
	}

	link = trace_get_layer2(packet,&linktype,remaining);
	iphdr = trace_get_payload_from_layer2(
			link,
			linktype,
			ethertype,
			remaining);

	for(;;) {
		if (!iphdr || *remaining == 0)
			break;
		switch(*ethertype) {
		case TRACE_ETHERTYPE_8021Q: /* VLAN */
			iphdr=trace_get_payload_from_vlan(
					  iphdr,ethertype,remaining);
			continue;
		case TRACE_ETHERTYPE_MPLS: /* MPLS */
			iphdr=trace_get_payload_from_mpls(
					  iphdr,ethertype,remaining);

			if (iphdr && ethertype == 0x0) {
				iphdr=trace_get_payload_from_ethernet(
						iphdr,ethertype,remaining);
			}
			continue;
		case TRACE_ETHERTYPE_PPP_SES: /* PPPoE */
			iphdr = trace_get_payload_from_pppoe(iphdr, ethertype,
					remaining);
			continue;
		default:
			break;
		}

		break;
	}

	if (!iphdr || *remaining == 0)
		return NULL;

	/* Store values in the cache for later */
	/* Cast away constness, nasty, but this is just a cache */
	((libtrace_packet_t*)packet)->l3_ethertype = *ethertype;
	((libtrace_packet_t*)packet)->l3_header = iphdr;
	((libtrace_packet_t*)packet)->l3_remaining = *remaining;

	return iphdr;
}

/* Parse an ip or tcp option
 * @param[in,out] ptr	the pointer to the current option
 * @param[in,out] len	the length of the remaining buffer
 * @param[out] type	the type of the option
 * @param[out] optlen 	the length of the option
 * @param[out] data	the data of the option
 *
 * @returns bool true if there is another option (and the fields are filled in)
 *               or false if this was the last option.
 *
 * This updates ptr to point to the next option after this one, and updates
 * len to be the number of bytes remaining in the options area.  Type is updated
 * to be the code of this option, and data points to the data of this option,
 * with optlen saying how many bytes there are.
 *
 * @note Beware of fragmented packets.
 * @author Perry Lorier
 */
DLLEXPORT int trace_get_next_option(unsigned char **ptr,int *len,
			unsigned char *type,
			unsigned char *optlen,
			unsigned char **data)
{
	if (*len<=0)
		return 0;
	*type=**ptr;
	switch(*type) {
		case 0: /* End of options */
			return 0;
		case 1: /* Pad */
			(*ptr)++;
			(*len)--;
			return 1;
		default:
			*optlen = *(*ptr+1);
			if (*optlen<2)
				return 0; /* I have no idea wtf is going on
					   * with these packets
					   */

			/* Ensure that optlen is not greater than the
			 * amount of buffer remaining */
			if (*optlen > *len) 
				return 0;
			
			(*len)-=*optlen;
			(*data)=(*ptr+2);
			(*ptr)+=*optlen;
			if (*len<0)
				return 0;
			return 1;
	}
	assert(0);
}

static char *sockaddr_to_string(struct sockaddr *addrptr, char *space,
		int spacelen) {

	assert(addrptr && space);
	assert(spacelen > 0);
	
	if (addrptr->sa_family == AF_INET) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)addrptr;
		inet_ntop(AF_INET, &(v4->sin_addr), space, spacelen);
	}

	else if (addrptr->sa_family == AF_INET6) {
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)addrptr;
		inet_ntop(AF_INET6, &(v6->sin6_addr), space, spacelen);
	}
#ifdef HAVE_NETPACKET_PACKET_H
	else if (addrptr->sa_family == AF_PACKET) {
		struct sockaddr_ll *l2addr = (struct sockaddr_ll *)addrptr;
		uint8_t *macbytes = (uint8_t *)l2addr->sll_addr;

		snprintf(space, spacelen, "%02x:%02x:%02x:%02x:%02x:%02x",
				macbytes[0], macbytes[1], macbytes[2],
				macbytes[3], macbytes[4], macbytes[5]);

	}
#else
	else if (addrptr->sa_family == AF_LINK) {
		struct sockaddr_dl *l2addr = (struct sockaddr_dl *)addrptr;
		uint8_t *macbytes = (uint8_t *)l2addr->sdl_data;

		snprintf(space, spacelen, "%02x:%02x:%02x:%02x:%02x:%02x",
				macbytes[0], macbytes[1], macbytes[2],
				macbytes[3], macbytes[4], macbytes[5]);
	
	}
#endif
	else {
		space[0] = '\0';
		return NULL;
	}

	return space;

}

/* Extract the source mac address from a frame and bundle it up into a sockaddr */
static struct sockaddr *get_source_ethernet_address(
	libtrace_ether_t *ethernet, struct sockaddr *addr)
{
	static struct sockaddr_storage dummy;
#ifdef HAVE_NETPACKET_PACKET_H
/* Use linux's sockaddr_ll structure */
	struct sockaddr_ll *l2addr;

	if (addr)
		l2addr = (struct sockaddr_ll*)addr;
	else
		l2addr = (struct sockaddr_ll*)&dummy;
	
	l2addr->sll_family = AF_PACKET;
	l2addr->sll_protocol = ethernet->ether_type;
	l2addr->sll_ifindex = 0; /* Irrelevant */
	l2addr->sll_hatype = ARPHRD_ETHER; 
	l2addr->sll_pkttype = PACKET_OTHERHOST;
	l2addr->sll_halen = 6;
	memcpy(l2addr->sll_addr,ethernet->ether_shost, 6);

	return (struct sockaddr*)l2addr;
#else
/* Use BSD's sockaddr_dl structure */
	struct sockaddr_dl *l2addr;

	if (addr)
		l2addr = (struct sockaddr_dl *)addr;
	else
		l2addr = (struct sockaddr_dl *)&dummy;
	
	l2addr->sdl_family = AF_LINK;
#if HAVE_SDL_LEN == 1
	l2addr->sdl_len = sizeof(struct sockaddr_dl);
#endif
	l2addr->sdl_index = 0; /* Unused */
	l2addr->sdl_alen = 6; /* Address length  */
	l2addr->sdl_nlen = 0; /* No name in here - this *should* work, right? */
	l2addr->sdl_slen = 0;	
	l2addr->sdl_type = 0; /* Hopefully zero is OK for this value too */
	memcpy(l2addr->sdl_data, ethernet->ether_shost, 6);

	return (struct sockaddr *)l2addr;
#endif
}

static struct sockaddr *get_source_l2_address(
	const libtrace_packet_t *packet, struct sockaddr *addr)
{
	static struct sockaddr_storage dummy;
	void *l2;
	libtrace_linktype_t linktype;
	uint32_t remaining;

	if (!addr)
		addr =(struct sockaddr*)&dummy;

	l2=trace_get_layer2(packet, &linktype, &remaining);
	if (!l2) {
		return NULL;
	}

	switch (linktype) {
		case TRACE_TYPE_ETH:
			return get_source_ethernet_address((libtrace_ether_t*)l2, addr);
		default:
			return NULL;
	}
}

DLLEXPORT struct sockaddr *trace_get_source_address(
		const libtrace_packet_t *packet, struct sockaddr *addr)
{
	uint16_t ethertype;
	uint32_t remaining;
	void *l3;
	struct ports_t *ports;
	static struct sockaddr_storage dummy;

	if (!addr)
		addr=(struct sockaddr*)&dummy;

	l3 = trace_get_layer3(packet,&ethertype,&remaining);

	if (!l3)
		return get_source_l2_address(packet,addr);

	switch (ethertype) {
		case TRACE_ETHERTYPE_IP: /* IPv4 */
		{
			struct sockaddr_in *addr4=(struct sockaddr_in*)addr;
			libtrace_ip_t *ip = (libtrace_ip_t*)l3;
			ports = (struct ports_t*)
				trace_get_payload_from_ip(ip,NULL,&remaining);
			addr4->sin_family=AF_INET;
			if (ports && remaining>=sizeof(*ports))
				addr4->sin_port=ports->src;
			else
				addr4->sin_port=0;
			addr4->sin_addr=ip->ip_src;
			return addr;
		}
		case TRACE_ETHERTYPE_IPV6: /* IPv6 */
		{
			struct sockaddr_in6 *addr6=(struct sockaddr_in6*)addr;
			libtrace_ip6_t *ip6 = (libtrace_ip6_t*)l3;
			ports = (struct ports_t*)
				trace_get_payload_from_ip6(ip6,NULL,&remaining);
			addr6->sin6_family=AF_INET6;
			if (ports && remaining>=sizeof(*ports))
				addr6->sin6_port=ports->src;
			else
				addr6->sin6_port=0;
			addr6->sin6_flowinfo=0;
			addr6->sin6_addr=ip6->ip_src;
			addr6->sin6_scope_id = 0;
			return addr;
		}
		default:
			return get_source_l2_address(packet, addr);
	}
}


DLLEXPORT char *trace_get_source_address_string(
		const libtrace_packet_t *packet, char *space, int spacelen) {

	static char staticspace[INET6_ADDRSTRLEN];
	struct sockaddr_storage addr;
	struct sockaddr *addrptr;
	

	if (space == NULL || spacelen == 0) {
		space = staticspace;
		spacelen = INET6_ADDRSTRLEN;
	}

	addrptr = trace_get_source_address(packet, (struct sockaddr *)&addr);

	if (addrptr == NULL)
		return NULL;
	
	return sockaddr_to_string(addrptr, space, spacelen);
}

static struct sockaddr *get_destination_ethernet_address(
	libtrace_ether_t *ethernet, struct sockaddr *addr)
{
	static struct sockaddr_storage dummy;
#ifdef HAVE_NETPACKET_PACKET_H
/* Use linux's sockaddr_ll structure */
	struct sockaddr_ll *l2addr;
	if (addr)
		l2addr = (struct sockaddr_ll*)addr;
	else
		l2addr = (struct sockaddr_ll*)&dummy;
	
	l2addr->sll_family = AF_PACKET;
	l2addr->sll_protocol = ethernet->ether_type;
	l2addr->sll_ifindex = 0; /* Irrelevant */
	l2addr->sll_hatype = ARPHRD_ETHER; 
	l2addr->sll_pkttype = PACKET_OTHERHOST;
	l2addr->sll_halen = 6;
	memcpy(l2addr->sll_addr,ethernet->ether_dhost, 6);

	return (struct sockaddr*)l2addr;
#else
/* Use BSD's sockaddr_dl structure */
	struct sockaddr_dl *l2addr;

	if (addr)
		l2addr = (struct sockaddr_dl *)addr;
	else
		l2addr = (struct sockaddr_dl *)&dummy;
	
	l2addr->sdl_family = AF_LINK;
#if HAVE_SDL_LEN == 1
	l2addr->sdl_len = sizeof(struct sockaddr_dl);
#endif
	l2addr->sdl_index = 0; /* Unused */
	l2addr->sdl_alen = 6; /* Address length  */
	l2addr->sdl_nlen = 0; /* No name in here - this *should* work, right? */
	l2addr->sdl_slen = 0;	
	l2addr->sdl_type = 0; /* Hopefully zero is OK for this value too */
	memcpy(l2addr->sdl_data, ethernet->ether_dhost, 6);

	return (struct sockaddr *)l2addr;
#endif
}

static struct sockaddr *get_destination_l2_address(
	const libtrace_packet_t *packet, struct sockaddr *addr)
{
	static struct sockaddr_storage dummy;
	void *l2;
	libtrace_linktype_t linktype;
	uint32_t remaining;
	if (!addr)
		addr =(struct sockaddr*)&dummy;
	l2=trace_get_layer2(packet, &linktype, &remaining);
	if (!l2)
		return NULL;

	switch (linktype) {
		case TRACE_TYPE_ETH:
			return get_destination_ethernet_address((libtrace_ether_t*)l2, addr);
		default:
			return NULL;
	}
}

DLLEXPORT struct sockaddr *trace_get_destination_address(
		const libtrace_packet_t *packet, struct sockaddr *addr)
{
	uint16_t ethertype;
	uint32_t remaining;
	void *l3;
	struct ports_t *ports;
	static struct sockaddr_storage dummy;

	if (!addr)
		addr=(struct sockaddr*)&dummy;

	l3 = trace_get_layer3(packet,&ethertype,&remaining);

	if (!l3)
		return get_destination_l2_address(packet,addr);

	switch (ethertype) {
		case TRACE_ETHERTYPE_IP: /* IPv4 */
		{
			struct sockaddr_in *addr4=(struct sockaddr_in*)addr;
			libtrace_ip_t *ip = (libtrace_ip_t*)l3;
			ports = (struct ports_t*)
				trace_get_payload_from_ip(ip,NULL,&remaining);
			addr4->sin_family=AF_INET;
			if (ports && remaining>=sizeof(*ports))
				addr4->sin_port=ports->dst;
			else
				addr4->sin_port=0;
			addr4->sin_addr=ip->ip_dst;
			return addr;
		}
		case TRACE_ETHERTYPE_IPV6: /* IPv6 */
		{
			struct sockaddr_in6 *addr6=(struct sockaddr_in6*)addr;
			libtrace_ip6_t *ip6 = (libtrace_ip6_t*)l3;
			ports = (struct ports_t*)
				trace_get_payload_from_ip6(ip6,NULL,&remaining);
			addr6->sin6_family=AF_INET6;
			if (ports && remaining>=sizeof(*ports))
				addr6->sin6_port=ports->dst;
			else
				addr6->sin6_port=0;
			addr6->sin6_flowinfo=0;
			addr6->sin6_addr=ip6->ip_dst;
			return addr;
		}
		default:
			return get_destination_l2_address(packet, addr);
	}
}

DLLEXPORT char *trace_get_destination_address_string(
		const libtrace_packet_t *packet, char *space, int spacelen) {

	struct sockaddr_storage addr;
	struct sockaddr *addrptr;
	
	static char staticspace[INET6_ADDRSTRLEN];

	if (space == NULL || spacelen == 0) {
		space = staticspace;
		spacelen = INET6_ADDRSTRLEN;
	}

	addrptr = trace_get_destination_address(packet, 
			(struct sockaddr *)&addr);

	if (addrptr == NULL)
		return NULL;
	
	return sockaddr_to_string(addrptr, space, spacelen);
}

DLLEXPORT uint16_t *trace_checksum_layer3(libtrace_packet_t *packet, 
		uint16_t *csum) {

	void *l3;
	uint16_t ethertype;
	uint32_t remaining;
	uint16_t *csum_ptr;

	uint8_t safety[65536];

	if (csum == NULL)
		return NULL;
	
	l3 = trace_get_layer3(packet, &ethertype, &remaining);
		
	if (l3 == NULL)
		return NULL;
	
	if (ethertype == TRACE_ETHERTYPE_IP) {
		libtrace_ip_t *ip = (libtrace_ip_t *)l3;
		if (remaining < sizeof(libtrace_ip_t))
			return NULL;

		csum_ptr = &ip->ip_sum;

		/* I hate memcpys, but this is the only truly safe way to
		 * do this without modifying the packet. I'm trying to be
		 * careful about not creating any more thread-safety issues
		 * than there already are :) */
		memcpy(safety, ip, ip->ip_hl * sizeof(uint32_t));
		
		/* Set the checksum to zero, so we can do the calculation */
		ip = (libtrace_ip_t *)safety;
		ip->ip_sum = 0;

		*csum = checksum_buffer(safety, ip->ip_hl * sizeof(uint32_t));
		
		/* Remember to byteswap appropriately */
		*csum = ntohs(*csum);
		
		return csum_ptr;
	}

	return NULL;
}

DLLEXPORT uint16_t trace_get_fragment_offset(const libtrace_packet_t *packet, 
                uint8_t *more) {

        void *l3;
        uint16_t ethertype;
        uint32_t remaining;

        *more = 0;

        l3 = trace_get_layer3(packet, &ethertype, &remaining);
        if (l3 == NULL)
                return 0;

        if (ethertype == TRACE_ETHERTYPE_IP) {
                libtrace_ip_t *ip = (libtrace_ip_t *)l3;
                uint16_t offset = 0;

                /* Fragment offset appears in 7th and 8th bytes */
                if (remaining < 8)
                        return 0;
                 
                offset = ntohs(ip->ip_off);

                if ((offset & 0x2000) != 0)
                        *more = 1;
                return (offset & 0x1FFF) * 8;
        }

        if (ethertype == TRACE_ETHERTYPE_IPV6) {
                libtrace_ip6_t *ip6 = (libtrace_ip6_t *)l3;
                void *payload = ip6++;
                uint8_t nxt = ip6->nxt;
                uint16_t len;
                
                /* First task, find a Fragment header if present */
                if (remaining < sizeof(libtrace_ip6_t))
                        return 0;
                remaining -= sizeof(libtrace_ip6_t);

                /* Adapted from trace_get_payload_from_ip6 */
                while (1) {
                        switch (nxt) {
                        case 0:
                        case TRACE_IPPROTO_ROUTING:
			case TRACE_IPPROTO_AH: 
			case TRACE_IPPROTO_DSTOPTS: 
                        {

				/* Length does not include the first 8 bytes */
				len=((libtrace_ip6_ext_t*)payload)->len * 8;
				len += 8;

			        if (remaining < len) {
                                        /* Snap too short */
                                        return 0;
                                }
                                remaining-=len;

				nxt=((libtrace_ip6_ext_t*)payload)->nxt;
				continue;
			}
			case TRACE_IPPROTO_FRAGMENT:
                        {
                                libtrace_ip6_frag_t *frag = (libtrace_ip6_frag_t *)payload;
                                uint16_t offset;
                                len = sizeof(libtrace_ip6_frag_t);
                                if (remaining < len) {
                                        /* Snap too short */
                                        return 0;
                                }
                                remaining-=len;

                                offset = ntohs(frag->frag_off);
                                if ((offset & 0x0001) != 0) 
                                        *more = 1;

                                return ((offset & 0xFFF8) >> 3) * 8;
                         }
                         default:
                                return 0;
                         }
                }

        }
        return 0;
}
