/* This file has the various helper functions used to decode various protocols 
 *
 * $Id$
 */ 
#include "libtrace.h"
#include "libtrace_int.h"
#include "wag.h"
#include <assert.h>
#include <stdio.h>

#ifndef WIN32
#include <net/if_arp.h>
#endif

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER    1               /* Ethernet 10/100Mbps.  */
#endif

#ifndef ARPHRD_PPP
#define ARPHRD_PPP      512
#endif


/* Returns the payload from 802.3 ethernet.  Type optionally returned in
 * "type" in host byte order.  This will return a vlan header.
 */
static void *trace_get_payload_from_ethernet(void *ethernet, 
		uint16_t *type,
		uint32_t *remaining)
{
	libtrace_ether_t *eth = (libtrace_ether_t*)ethernet;

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

	return ethernet;
}

static void *trace_get_payload_from_80211(void *link, uint16_t *type, uint32_t *remaining)
{
	libtrace_80211_t *wifi;
	libtrace_802_11_payload_t *eth;

	if (remaining && *remaining < sizeof(libtrace_80211_t))
		return NULL;

	wifi=(libtrace_80211_t*)link;

	/* Data packet? */
	if (wifi->type != 2) {
		return NULL;
	}

	if (remaining && *remaining < sizeof(*eth))
		return NULL;

	eth=(libtrace_802_11_payload_t *)((char*)wifi+sizeof(*wifi));

	if (type) *type=ntohs(eth->type);

	return (void*)((char*)eth+sizeof(*eth));
}

static void *trace_get_payload_from_linux_sll(void *link,
		uint16_t *type, uint32_t *remaining) 
{
	libtrace_sll_header_t *sll;
	void *ret;

	sll = (libtrace_sll_header_t*) link;

	if (remaining) {
		if (*remaining < sizeof(*sll))
			return NULL;
		*remaining-=sizeof(*sll);
	}

	/* What kind of wacked out header, has this in host order?! */
	if (type) *type = htons(sll->protocol); 

	ret=(void*)((char*)sll+sizeof(*sll));

	switch(sll->hatype) {
		case ARPHRD_PPP:
			break;
		case ARPHRD_ETHER:
			ret=trace_get_payload_from_ethernet(ret,type,remaining);
			break;
		default:
			/* Unknown hardware type */
			return NULL;
	}

	return ret;
}

static void *trace_get_payload_from_atm(void *link,
		uint16_t *type, uint32_t *remaining)
{
	/* 64 byte capture. */
	libtrace_llcsnap_t *llc = (libtrace_llcsnap_t*)link;

	if (remaining) {
		if (*remaining < sizeof(libtrace_llcsnap_t)+4)
			return NULL;
		*remaining-=(sizeof(libtrace_llcsnap_t)+4);
	}

	/* advance the llc ptr +4 into the link layer.
	 * TODO: need to check what is in these 4 bytes.
	 * don't have time!
	 */
	llc = (libtrace_llcsnap_t*)((char *)llc + 4);

	if (type) *type = ntohs(llc->type);

	return (void*)((char*)llc+sizeof(*llc));
}

static void *trace_get_payload_from_pos(void *link, 
		uint16_t *type, uint32_t *remaining)
{
	/* 64 byte capture. */
	libtrace_pos_t *pos = (libtrace_pos_t*)link;

	if (remaining) {
		if (*remaining < sizeof(libtrace_pos_t))
			return NULL;
		*remaining-=sizeof(libtrace_pos_t);
	}

	if (type) *type = ntohs(pos->ether_type);

	return (void*)((char *)pos+sizeof(*pos));
}

static void *trace_get_payload_from_pflog(void *link,
		uint16_t *type, uint32_t *remaining)
{
	libtrace_pflog_header_t *pflog = (libtrace_pflog_header_t*)link;
    if (remaining) {
		if (*remaining<sizeof(*pflog)) 
			return NULL;
		*remaining-=sizeof(*pflog);
	}
	if (type) {
		switch(pflog->af) {
			case AF_INET6: *type=0x86DD; break;
			case AF_INET:  *type=0x0800; break;
			default:
				      /* Unknown */
				      return NULL;
		}
	}
	return (void*)((char*)pflog+ sizeof(*pflog));
}

/* Returns the 'payload' of the prism header, which is the 802.11 frame */
static void *trace_get_payload_from_prism (void *link,
		uint16_t *type, uint32_t *remaining)
{
	if (remaining) {
		if (*remaining<144) 
			return NULL;
		*remaining-=144;
	}

	if (type) *type = 0;

	return (void *) ((char*)link+144);
}

/* Returns the 'payload' of the radiotap header, which is the 802.11 frame */
static void *trace_get_payload_from_radiotap (void *link, 
		uint16_t *type, uint32_t *remaining)
{
	struct libtrace_radiotap_t *rtap = (struct libtrace_radiotap_t*)link;
	uint16_t rtaplen = bswap_le_to_host16(rtap->it_len);
	if (remaining) {
		if (*remaining < rtaplen)
			return NULL;
		*remaining -= rtaplen;
	}

	if (type) *type = 0;

	return (void*) ((char*)link + rtaplen);
}

void *trace_get_payload_from_link(void *link, libtrace_linktype_t linktype, 
		uint16_t *type, uint32_t *remaining)
{
	void *l = NULL;

	switch(linktype) {
		case TRACE_TYPE_80211_PRISM:
			l = trace_get_payload_from_prism(link,type,remaining);
			return(l ? trace_get_payload_from_80211(l,type,remaining) : NULL);
		case TRACE_TYPE_80211_RADIO:
			l = trace_get_payload_from_radiotap(link,type,remaining);
			return(l ? trace_get_payload_from_80211(l,type,remaining) : NULL);
		case TRACE_TYPE_80211:
			return trace_get_payload_from_80211(link,type,remaining);
		case TRACE_TYPE_ETH:
			return trace_get_payload_from_ethernet(link,type,remaining);
		case TRACE_TYPE_NONE:
			if ((*(char*)link&0xF0) == 0x40)
				*type=0x0800;
			else if ((*(char*)link&0xF0) == 0x60)
				*type=0x86DD;
			return link; /* I love the simplicity */
		case TRACE_TYPE_LINUX_SLL:
			return trace_get_payload_from_linux_sll(link,type,remaining);
		case TRACE_TYPE_PFLOG:
			return trace_get_payload_from_pflog(link,type,remaining);
		case TRACE_TYPE_POS:
			return trace_get_payload_from_pos(link,type,remaining);
		case TRACE_TYPE_ATM:
			return trace_get_payload_from_atm(link,type,remaining);
		case TRACE_TYPE_DUCK:
			return NULL; /* duck packets have no payload! */
	}
	fprintf(stderr,"Don't understand link layer type %i in trace_get_payload_from_link()\n",
		linktype);
	return NULL;
}

libtrace_ip_t *trace_get_ip(libtrace_packet_t *packet) 
{
	uint16_t type;
	void *link = trace_get_link(packet);
	void *ret;

	if (!link)
		return NULL;
	
	ret=trace_get_payload_from_link(
			link,
			trace_get_link_type(packet),
			&type, NULL);

	if (!ret)
		return NULL;

	ret=trace_get_vlan_payload_from_ethernet_payload(ret,&type,NULL);

	if (!ret || type!=0x0800)
		return NULL;

	/* Not an IPv4 packet */
	if (((libtrace_ip_t*)ret)->ip_v != 4)
		return NULL;

	return (libtrace_ip_t*)ret;
}

libtrace_ip6_t *trace_get_ip6(libtrace_packet_t *packet) 
{
	uint16_t type;
	void *link=trace_get_link(packet);
	void *ret;
	
	if (!link)
		return NULL;

	ret=trace_get_payload_from_link(
			link,
			trace_get_link_type(packet),
			&type,NULL);

	if (!ret)
		return NULL;

	ret=trace_get_vlan_payload_from_ethernet_payload(ret,&type,NULL);

	if (!ret || type!=0x86DD)
		return NULL;

	return (libtrace_ip6_t*)ret;
}

#define SW_IP_OFFMASK 0xff1f

DLLEXPORT void *trace_get_payload_from_ip(libtrace_ip_t *ipptr, uint8_t *prot,
		uint32_t *remaining) 
{
        void *trans_ptr = 0;

        if ((ipptr->ip_off & SW_IP_OFFMASK) != 0) {
		return NULL;
	}

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

DLLEXPORT void *trace_get_transport(libtrace_packet_t *packet, 
		uint8_t *proto,
		uint32_t *remaining
		) 
{
	void *transport;
	uint8_t dummy_proto;
	uint16_t ethertype;
	void *link;
	uint32_t dummy_remaining;

	if (!proto) proto=&dummy_proto;

	if (!remaining) remaining=&dummy_remaining;

	*remaining = trace_get_capture_length(packet);

	link=trace_get_link(packet);

	if (!link)
		return NULL;

	transport = trace_get_payload_from_link(
			link,
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

	switch (ethertype) {
		case 0x0800: /* IPv4 */
			transport=trace_get_payload_from_ip(
				(libtrace_ip_t*)transport, proto, remaining);
			/* IPv6 */
			if (transport && *proto == 41) {
				transport=trace_get_payload_from_ip6(
				 (libtrace_ip6_t*)transport, proto,remaining);
			}
			return transport;
		case 0x86DD: /* IPv6 */
			return trace_get_payload_from_ip6(
				(libtrace_ip6_t*)transport, proto, remaining);
			
		default:
			*proto=0;
			return NULL;
	}

}

DLLEXPORT libtrace_tcp_t *trace_get_tcp(libtrace_packet_t *packet) {
	uint8_t proto;
	libtrace_tcp_t *tcp;

	tcp=(libtrace_tcp_t*)trace_get_transport(packet,&proto,NULL);

	if (!tcp || proto != 6)
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

	if (ip->ip_p == 17) {
		udpptr = (libtrace_udp_t *)
			trace_get_payload_from_ip(ip, NULL, remaining);
	}

	return udpptr;
}

DLLEXPORT libtrace_icmp_t *trace_get_icmp(libtrace_packet_t *packet) {
	uint8_t proto;
	libtrace_icmp_t *icmp;

	icmp=(libtrace_icmp_t*)trace_get_transport(packet,&proto,NULL);

	if (!icmp || proto != 1)
		return NULL;

	return icmp;
}

DLLEXPORT libtrace_icmp_t *trace_get_icmp_from_ip(libtrace_ip_t *ip, uint32_t *remaining)
{
	libtrace_icmp_t *icmpptr = 0;

	if (ip->ip_p == 1)  {
		icmpptr = (libtrace_icmp_t *)trace_get_payload_from_ip(ip, 
				NULL, remaining);
	}

	return icmpptr;
}

DLLEXPORT void *trace_get_payload_from_udp(libtrace_udp_t *udp, uint32_t *remaining)
{
	if (remaining) {
		if (*remaining < sizeof(libtrace_udp_t))
			return NULL;
		*remaining-=sizeof(libtrace_udp_t);
	}
	return (void*)((char*)udp+sizeof(libtrace_udp_t));
}

DLLEXPORT void *trace_get_payload_from_tcp(libtrace_tcp_t *tcp, uint32_t *remaining)
{
	unsigned int dlen = tcp->doff*4;
	if (remaining) {
		if (*remaining < dlen)
			return NULL;
		*remaining-=dlen;
	}
	return (void *)((char *)tcp+dlen);
}

DLLEXPORT void *trace_get_payload_from_icmp(libtrace_icmp_t *icmp, uint32_t *remaining)
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
DLLEXPORT uint16_t trace_get_source_port(const libtrace_packet_t *packet)
{
	uint32_t remaining;
	struct ports_t *port = 
		(struct ports_t*)trace_get_transport((libtrace_packet_t*)packet,
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


uint8_t *trace_get_source_mac(libtrace_packet_t *packet) {
	void *link = trace_get_link(packet);
	libtrace_80211_t *wifi;
        libtrace_ether_t *ethptr = (libtrace_ether_t*)link;
	if (!link)
		return NULL;
	switch (trace_get_link_type(packet)) {
		case TRACE_TYPE_80211:
			wifi=(libtrace_80211_t*)link;
			return (uint8_t*)&wifi->mac2;
		case TRACE_TYPE_80211_PRISM:
			wifi=(libtrace_80211_t*)((char*)link+144);
			return (uint8_t*)&wifi->mac2;
		case TRACE_TYPE_ETH:
			return (uint8_t*)&ethptr->ether_shost;
		case TRACE_TYPE_POS:
		case TRACE_TYPE_NONE:
		case TRACE_TYPE_HDLC_POS:
		case TRACE_TYPE_LINUX_SLL:
		case TRACE_TYPE_PFLOG:
		case TRACE_TYPE_ATM:
		case TRACE_TYPE_DUCK:
			return NULL;
	}
	fprintf(stderr,"Not implemented\n");
	assert(0);
	return NULL;
}

DLLEXPORT uint8_t *trace_get_destination_mac(libtrace_packet_t *packet) {
	void *link = trace_get_link(packet);
	libtrace_80211_t *wifi;
        libtrace_ether_t *ethptr = (libtrace_ether_t*)link;
	if (!link)
		return NULL;
	switch (trace_get_link_type(packet)) {
		case TRACE_TYPE_80211:
			wifi=(libtrace_80211_t*)link;
			return (uint8_t*)&wifi->mac1;
		case TRACE_TYPE_80211_PRISM:
			wifi=(libtrace_80211_t*)((char*)link+144);
			return (uint8_t*)&wifi->mac1;
		case TRACE_TYPE_ETH:
			return (uint8_t*)&ethptr->ether_dhost;
		case TRACE_TYPE_POS:
		case TRACE_TYPE_NONE:
		case TRACE_TYPE_ATM:
		case TRACE_TYPE_HDLC_POS:
		case TRACE_TYPE_LINUX_SLL:
		case TRACE_TYPE_PFLOG:
		case TRACE_TYPE_DUCK:
			/* No MAC address */
			return NULL;
	}
	fprintf(stderr,"Not implemented\n");
	assert(0);
	return NULL;
}

DLLEXPORT struct sockaddr *trace_get_source_address(const libtrace_packet_t *packet, 
		struct sockaddr *addr)
{
	uint16_t proto;
	uint32_t remaining;
	void *l3;
	struct ports_t *ports;
	static struct sockaddr_storage dummy;

	if (!addr)
		addr=(struct sockaddr*)&dummy;

	remaining = trace_get_capture_length(packet);

	l3 = trace_get_payload_from_link(
			trace_get_link(packet),
			trace_get_link_type(packet),
			&proto,
			&remaining);

	if (!l3)
		return false;

	l3 = trace_get_vlan_payload_from_ethernet_payload(l3,
			&proto,
			&remaining);

	if (!l3)
		return NULL;

	switch (proto) {
		case 0x0800: /* IPv4 */
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
		case 0x86DD: /* IPv6 */
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
			addr6->sin6_addr=ip6->ip_src;
			return addr;
		}
		default:
			return NULL;
	}
}

DLLEXPORT struct sockaddr *trace_get_destination_address(const libtrace_packet_t *packet, 
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
			libtrace_ip_t *ip = (libtrace_ip_t*)transport;
			addr4->sin_family=AF_INET;
			addr4->sin_port=0;
			addr4->sin_addr=ip->ip_dst;
			return addr;
		}
		case 0x86DD: /* IPv6 */
		{
			struct sockaddr_in6 *addr6=(struct sockaddr_in6*)addr;
			libtrace_ip6_t *ip6 = (libtrace_ip6_t*)transport;
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

/* parse an ip or tcp option
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
			(*len)-=*optlen;
			(*data)=(*ptr+2);
			(*ptr)+=*optlen;
			if (*len<0)
				return 0;
			return 1;
	}
	assert(0);
}


