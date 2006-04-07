/* This file has the various helper functions used to decode various protocols 
 *
 * $Id$
 */ 
#include "libtrace.h"
#include "libtrace_int.h"
#include "wag.h"
#include <assert.h>
#include <stdio.h>


/* Returns the payload from 802.3 ethernet.  Type optionally returned in
 * "type" in host byte order.  This will return a vlan header.
 */
static void *trace_get_payload_from_ethernet(void *ethernet, 
		uint16_t *type,
		uint32_t *remaining)
{
	libtrace_ether_t *eth = ethernet;

	if (remaining) {
		if (*remaining < sizeof(*eth))
			return NULL;
		*remaining-=sizeof(*eth);
	}

	if (type)
		*type = ntohs(eth->ether_type);

	return (void*)((char *)eth + sizeof(*eth));
}

/* skip any 802.1q headers if necessary 
 * type is input/output
 */
static void *trace_get_vlan_payload_from_ethernet_payload(void *ethernet, uint16_t *type,
		uint32_t *remaining)
{
	assert(type && "You must pass a type in!");

	if (*type == 0x8100) {
		libtrace_8021q_t *vlanhdr = (libtrace_8021q_t *)ethernet;

		if (remaining) {
			if (*remaining < sizeof(libtrace_8021q_t))
				return NULL;

			*remaining=*remaining-sizeof(libtrace_8021q_t);
		}

		*type = ntohs(vlanhdr->vlan_ether_type);

		return (void*)((char *)ethernet + sizeof(*vlanhdr));
	}

	return NULL;
}

static void *trace_get_payload_from_80211(void *link, uint16_t *type, uint32_t *remaining)
{
	libtrace_80211_t *wifi = link;
	struct ieee_802_11_payload *eth;

	if (remaining && *remaining < sizeof(libtrace_80211_t))
		return NULL;

	/* Data packet? */
	if (wifi->type != 2) {
		return NULL;
	}

	if (remaining && *remaining < sizeof(*eth))
		return NULL;

	eth=(void*)((char*)wifi+sizeof(*eth));

	if (*type) *type=eth->type;

	return eth;
}

static void *trace_get_payload_from_linux_sll(void *link,
		uint16_t *type, uint32_t *remaining) 
{
	struct trace_sll_header_t *sll;

	sll = link;

	if (remaining) {
		if (*remaining < sizeof(*sll))
			return NULL;
		*remaining-=sizeof(*sll);
	}

	if (*type) *type = sll->protocol;

	return (void*)((char*)sll+sizeof(*sll));
}

static void *trace_get_payload_from_atm(void *link,
		uint16_t *type, uint32_t *remaining)
{
	/* 64 byte capture. */
	struct libtrace_llcsnap *llc = link;

	if (remaining) {
		if (*remaining < sizeof(struct libtrace_llcsnap)+4)
			return NULL;
		*remaining-=(sizeof(struct libtrace_llcsnap)+4);
	}

	/* advance the llc ptr +4 into the link layer.
	 * TODO: need to check what is in these 4 bytes.
	 * don't have time!
	 */
	llc = (void*)((char *)llc + 4);

	if (*type) *type = ntohs(llc->type);

	return (void*)((char*)llc+sizeof(*llc));
}

static void *trace_get_payload_from_legacy_pos(void *link, 
		uint16_t *type, uint32_t *remaining)
{
	/* 64 byte capture. */
	struct libtrace_pos *pos = link;

	if (remaining) {
		if (*remaining < sizeof(struct libtrace_pos))
			return NULL;
		*remaining-=sizeof(struct libtrace_pos);
	}

	if (type) *type = ntohs(pos->ether_type);

	return (void*)((char *)pos+sizeof(*pos));
}

static void *trace_get_payload_from_pflog(void *link,
		uint16_t *type, uint32_t *remaining)
{
	struct trace_pflog_header_t *pflog = link;
	if (remaining) {
		if (*remaining<sizeof(*pflog)) 
			return NULL;
		*remaining-=sizeof(*pflog);
	}
	if (type) {
		switch(pflog->af) {
			case AF_INET6: *type=0x86DD; break;
			case AF_INET: *type=0x0800; break;
			default:
				      /* Unknown */
				      return NULL;
		}
	}
	return (void*)((char*)pflog+ sizeof(*pflog));
}

void *trace_get_payload_from_link(void *link, libtrace_linktype_t linktype, 
		uint16_t *type, uint32_t *remaining)
{
	switch(linktype) {
		case TRACE_TYPE_80211_PRISM:
			return trace_get_payload_from_80211((char*)link+144,
					type,remaining);
		case TRACE_TYPE_80211:
			return trace_get_payload_from_80211(link,type,remaining);
		case TRACE_TYPE_ETH:
		case TRACE_TYPE_LEGACY_ETH:
			return trace_get_payload_from_ethernet(link,type,remaining);
		case TRACE_TYPE_NONE:
			return link; /* I love the simplicity */
		case TRACE_TYPE_LINUX_SLL:
			return trace_get_payload_from_linux_sll(link,type,remaining);
		case TRACE_TYPE_PFLOG:
			return trace_get_payload_from_pflog(link,type,remaining);
		case TRACE_TYPE_LEGACY_POS:
			return trace_get_payload_from_legacy_pos(link,type,remaining);
		case TRACE_TYPE_LEGACY_ATM:
		case TRACE_TYPE_ATM:
			return trace_get_payload_from_atm(link,type,remaining);
	}
	fprintf(stderr,"Don't understand link layer type %i in trace_get_ip6()\n",
		linktype);
	return NULL;
}

libtrace_ip_t *trace_get_ip(libtrace_packet_t *packet) 
{
	uint16_t type;
	void *ret=trace_get_payload_from_link(
			trace_get_link(packet),
			trace_get_link_type(packet),
			&type, NULL);

	if (!ret)
		return NULL;

	ret=trace_get_vlan_payload_from_ethernet_payload(ret,&type,NULL);

	if (!ret || type!=0x0800)
		return NULL;

	return ret;
}

libtrace_ip6_t *trace_get_ip6(libtrace_packet_t *packet) 
{
	uint16_t type;
	void *ret=trace_get_payload_from_link(
			trace_get_link(packet),
			trace_get_link_type(packet),
			&type,NULL);

	if (!ret)
		return NULL;

	ret=trace_get_vlan_payload_from_ethernet_payload(ret,&type,NULL);

	if (!ret || type!=0x86DD)
		return NULL;

	return ret;
}

#define SW_IP_OFFMASK 0xff1f

void *trace_get_payload_from_ip(libtrace_ip_t *ipptr, uint8_t *prot,
		uint32_t *remaining) 
{
        void *trans_ptr = 0;

        if ((ipptr->ip_off & SW_IP_OFFMASK) != 0)
		return NULL;

	if (remaining) {
		if (*remaining<(ipptr->ip_hl*4U)) {
			return NULL;
		}
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
	uint8_t nxt = ipptr->nxt;

	if (remaining) {
		if (*remaining<sizeof(libtrace_ip6_t))
			return NULL;
		*remaining-=sizeof(libtrace_ip6_t);
	}

	while(1) {
		switch (nxt) {
			case 0: /* hop by hop options */
			case 43: /* routing */
			case 44: /* fragment */
			case 50: /* ESP */
			case 51: /* AH */
			case 60: /* Destination options */
				{
					uint16_t len=((libtrace_ip6_ext_t*)payload)->len
					+sizeof(libtrace_ip6_ext_t);

					if (remaining) {
						if (*remaining < len) {
							/* Snap too short */
							return NULL;
						}
						*remaining-=len;
					}

					payload=(char*)payload+len;
					nxt=((libtrace_ip6_ext_t*)payload)->nxt;
					continue;
				}
			default:
				if (prot) *prot=nxt;
				return payload;
		}
	}
}

void *trace_get_transport(libtrace_packet_t *packet, 
		uint8_t *proto,
		uint32_t *remaining
		) 
{
	void *transport;
	uint8_t dummy;
	uint16_t ethertype;

	if (!proto) proto=&dummy;

	if (remaining)
		*remaining = trace_get_capture_length(packet);

	transport = trace_get_payload_from_link(
			trace_get_link(packet),
			trace_get_link_type(packet),
			&ethertype,
			remaining);

	if (!transport)
		return NULL;

	transport = trace_get_vlan_payload_from_ethernet_payload(transport,
			&ethertype,
			remaining);

	if (!transport)
		return NULL;

	switch (*proto) {
		case 0x0800: /* IPv4 */
			transport=trace_get_payload_from_ip(transport, proto, remaining);
			/* IPv6 */
			if (transport && *proto == 41) {
				transport=trace_get_payload_from_ip6(transport,
						proto,remaining);
			}
			return transport;
		case 0x86DD: /* IPv6 */
			return trace_get_payload_from_ip6(transport, proto, remaining);
			
		default:
			return NULL;
	}

}

libtrace_tcp_t *trace_get_tcp(libtrace_packet_t *packet) {
	uint8_t proto;
	libtrace_tcp_t *tcp;

	tcp=trace_get_transport(packet,&proto,NULL);

	if (proto != 6)
		return NULL;

	return tcp;
}

libtrace_tcp_t *trace_get_tcp_from_ip(libtrace_ip_t *ip, uint32_t *remaining)
{
	struct libtrace_tcp *tcpptr = 0;

	if (ip->ip_p == 6)  {
		tcpptr = (struct libtrace_tcp *)
			trace_get_payload_from_ip(ip, NULL, remaining);
	}

	return tcpptr;
}

libtrace_udp_t *trace_get_udp(libtrace_packet_t *packet) {
	uint8_t proto;
	libtrace_udp_t *udp;

	udp=trace_get_transport(packet,&proto,NULL);

	if (proto != 17)
		return NULL;

	return udp;
}

libtrace_udp_t *trace_get_udp_from_ip(libtrace_ip_t *ip, uint32_t *remaining)
{
	struct libtrace_udp *udpptr = 0;

	if (ip->ip_p == 17) {
		udpptr = (libtrace_udp_t *)
			trace_get_payload_from_ip(ip, NULL, remaining);
	}

	return udpptr;
}

libtrace_icmp_t *trace_get_icmp(libtrace_packet_t *packet) {
	uint8_t proto;
	libtrace_icmp_t *icmp;

	icmp=trace_get_transport(packet,&proto,NULL);

	if (proto != 1)
		return NULL;

	return icmp;
}

libtrace_icmp_t *trace_get_icmp_from_ip(libtrace_ip_t *ip, uint32_t *remaining)
{
	libtrace_icmp_t *icmpptr = 0;

	if (ip->ip_p == 1)  {
		icmpptr = (libtrace_icmp_t *)trace_get_payload_from_ip(ip, 
				NULL, remaining);
	}

	return icmpptr;
}

void *trace_get_payload_from_udp(libtrace_udp_t *udp, uint32_t *remaining)
{
	if (remaining) {
		if (*remaining < sizeof(libtrace_udp_t))
			return NULL;
		*remaining-=sizeof(libtrace_udp_t);
	}
	return (void*)((char*)udp+sizeof(libtrace_udp_t));
}

void *trace_get_payload_from_tcp(libtrace_tcp_t *tcp, uint32_t *remaining)
{
	unsigned int dlen = tcp->doff*4;
	if (remaining) {
		if (*remaining < dlen)
			return NULL;
		*remaining-=dlen;
	}
	return tcp+dlen;
}

void *trace_get_payload_from_icmp(libtrace_icmp_t *icmp, uint32_t *remaining)
{
	if (remaining) {
		if (*remaining < sizeof(libtrace_icmp_t))
			return NULL;
		*remaining-=sizeof(libtrace_icmp_t);
	}
	return (char*)icmp+sizeof(libtrace_icmp_t);
}

struct ports_t {
	uint16_t src;
	uint16_t dst;
};

/* Return the client port
 */
uint16_t trace_get_source_port(const libtrace_packet_t *packet)
{
	struct ports_t *port = trace_get_transport((libtrace_packet_t*)packet,
			NULL, NULL);

	return ntohs(port->src);
}

/* Same as get_source_port except use the destination port */
uint16_t trace_get_destination_port(const libtrace_packet_t *packet)
{
	struct ports_t *port = trace_get_transport((libtrace_packet_t*)packet,
			NULL, NULL);

	return ntohs(port->dst);
}


uint8_t *trace_get_source_mac(libtrace_packet_t *packet) {
	void *link = trace_get_link(packet);
	libtrace_80211_t *wifi = link;
        libtrace_ether_t *ethptr = link;
	if (!link)
		return NULL;
	switch (trace_get_link_type(packet)) {
		case TRACE_TYPE_80211:
			return (uint8_t*)&wifi->mac2;
		case TRACE_TYPE_ETH:
			return (uint8_t*)&ethptr->ether_shost;
		default:
			fprintf(stderr,"Not implemented\n");
			assert(0);
	}
}

uint8_t *trace_get_destination_mac(libtrace_packet_t *packet) {
	void *link = trace_get_link(packet);
	libtrace_80211_t *wifi = link;
        libtrace_ether_t *ethptr = link;
	if (!link)
		return NULL;
	switch (trace_get_link_type(packet)) {
		case TRACE_TYPE_80211:
			return (uint8_t*)&wifi->mac1;
		case TRACE_TYPE_ETH:
			return (uint8_t*)&ethptr->ether_dhost;
		default:
			fprintf(stderr,"Not implemented\n");
			assert(0);
	}
}

struct sockaddr *trace_get_source_address(const libtrace_packet_t *packet, 
		struct sockaddr *addr)
{
	uint16_t proto;
	uint32_t remaining;
	void *transport;
	static struct sockaddr_storage dummy;

	if (!addr)
		addr=(struct sockaddr*)&dummy;

	remaining = trace_get_capture_length(packet);

	transport = trace_get_payload_from_link(
			trace_get_link(packet),
			trace_get_link_type(packet),
			&proto,
			&remaining);

	if (!transport)
		return false;

	transport = trace_get_vlan_payload_from_ethernet_payload(transport,
			&proto,
			&remaining);

	if (!transport)
		return false;

	switch (proto) {
		case 0x0800: /* IPv4 */
		{
			struct sockaddr_in *addr4=(struct sockaddr_in*)addr;
			libtrace_ip_t *ip = transport;
			addr4->sin_family=AF_INET;
			addr4->sin_port=0;
			addr4->sin_addr=ip->ip_src;
			return addr;
		}
		case 0x86DD: /* IPv6 */
		{
			struct sockaddr_in6 *addr6=(struct sockaddr_in6*)addr;
			libtrace_ip6_t *ip6 = transport;
			addr6->sin6_family=AF_INET6;
			addr6->sin6_port=0;
			addr6->sin6_flowinfo=0;
			addr6->sin6_addr=ip6->ip_src;
			return addr;
		}
		default:
			return NULL;
	}
}

struct sockaddr *trace_get_destination_address(const libtrace_packet_t *packet, 
		struct sockaddr *addr)
{
	uint16_t proto;
	uint32_t remaining;
	void *transport;
	static struct sockaddr_storage dummy;

	if (!addr)
		addr=(struct sockaddr*)&dummy;

	remaining = trace_get_capture_length(packet);

	transport = trace_get_payload_from_link(
			trace_get_link(packet),
			trace_get_link_type(packet),
			&proto,
			&remaining);

	if (!transport)
		return false;

	transport = trace_get_vlan_payload_from_ethernet_payload(transport,
			&proto,
			&remaining);

	if (!transport)
		return false;

	switch (proto) {
		case 0x0800: /* IPv4 */
		{
			struct sockaddr_in *addr4=(struct sockaddr_in*)addr;
			libtrace_ip_t *ip = transport;
			addr4->sin_family=AF_INET;
			addr4->sin_port=0;
			addr4->sin_addr=ip->ip_dst;
			return addr;
		}
		case 0x86DD: /* IPv6 */
		{
			struct sockaddr_in6 *addr6=(struct sockaddr_in6*)addr;
			libtrace_ip6_t *ip6 = transport;
			addr6->sin6_family=AF_INET6;
			addr6->sin6_port=0;
			addr6->sin6_flowinfo=0;
			addr6->sin6_addr=ip6->ip_dst;
			return addr;
		}
		default:
			return NULL;
	}
}

