/* This file has the various helper functions used to decode various protocols 
 *
 * $Id$
 */ 
#include "libtrace.h"
#include "libtrace_int.h"
#include "wag.h"


static void *trace_get_ip_from_ethernet(void *ethernet, int *skipped)
{
	libtrace_ether_t *eth = ethernet;
	
	if (ntohs(eth->ether_type)==0x0800) {
		if (skipped)
			*skipped=sizeof(libtrace_ether_t);
		return (void*)((char *)eth + sizeof(*eth));
	} else if (ntohs(eth->ether_type) == 0x8100) {
		libtrace_8021q_t *vlanhdr = (libtrace_8021q_t *)eth;
		if (skipped)
			*skipped=sizeof(libtrace_ether_t);
		if (ntohs(vlanhdr->vlan_ether_type) == 0x0800) {
			return (void*)((char *)eth + sizeof(*vlanhdr));
		}
	}
	
	return NULL;
}

static void *trace_get_ip6_from_ethernet(void *ethernet, int *skipped)
{
	libtrace_ether_t *eth = ethernet;
	
	if (ntohs(eth->ether_type)==0x86DD) {
		if (skipped)
			*skipped=sizeof(libtrace_ether_t);
		return (void*)((char *)eth + sizeof(*eth));
	} else if (ntohs(eth->ether_type) == 0x8100) {
		libtrace_8021q_t *vlanhdr = (libtrace_8021q_t *)eth;
		if (skipped)
			*skipped=sizeof(libtrace_ether_t);
		if (ntohs(vlanhdr->vlan_ether_type) == 0x86DD) {
			return (void*)((char *)eth + sizeof(*vlanhdr));
		}
	}
	
	return NULL;
}

static void *trace_get_ip_from_80211(void *link, int *skipped)
{
	libtrace_80211_t *wifi = link;
	struct ieee_802_11_payload *eth;

	if (*skipped) skipped+=sizeof(libtrace_80211_t);

	if (!wifi) {
		return NULL;
	}

	/* Data packet? */
	if (wifi->type != 2) {
		return NULL;
	}

	if (skipped) *skipped+=sizeof(*eth);
	eth=(void*)((char*)wifi+sizeof(libtrace_80211_t));

	if (ntohs(eth->type) == 0x0800) {
		return (void*)((char*)eth + sizeof(*eth));
	} else if (ntohs(eth->type) == 0x8100) {
		struct libtrace_8021q *vlanhdr = (struct libtrace_8021q *)eth;
		if (ntohs(vlanhdr->vlan_ether_type) == 0x0800) {
			if (skipped) *skipped+=sizeof(*vlanhdr);
			return (void*)((char*)eth + sizeof(*vlanhdr));
		}
	}

	return NULL;
}

static void *trace_get_ip6_from_80211(void *link, int *skipped)
{
	libtrace_80211_t *wifi = link;
	struct ieee_802_11_payload *eth;

	if (*skipped) skipped+=sizeof(libtrace_80211_t);

	if (!wifi) {
		return NULL;
	}

	/* Data packet? */
	if (wifi->type != 2) {
		return NULL;
	}

	if (skipped) *skipped+=sizeof(*eth);
	eth=(void*)((char*)wifi+sizeof(libtrace_80211_t));

	if (ntohs(eth->type) == 0x86DD) {
		return (void*)((char*)eth + sizeof(*eth));
	} else if (ntohs(eth->type) == 0x8100) {
		struct libtrace_8021q *vlanhdr = (struct libtrace_8021q *)eth;
		if (ntohs(vlanhdr->vlan_ether_type) == 0x86DD) {
			if (skipped) *skipped+=sizeof(*vlanhdr);
			return (void*)((char*)eth + sizeof(*vlanhdr));
		}
	}

	return NULL;
}

/* TODO: split these cases into get_*_from_* functions */
struct libtrace_ip *trace_get_ip(const struct libtrace_packet_t *packet) {
        struct libtrace_ip *ipptr = 0;

	switch(trace_get_link_type(packet)) {
		case TRACE_TYPE_80211_PRISM:
			ipptr = trace_get_ip_from_80211(
					(char*)trace_get_link(packet)+144,
					NULL);
			break;
		case TRACE_TYPE_80211:
			ipptr = trace_get_ip_from_80211(
					trace_get_link(packet),
					NULL);
			break;
		case TRACE_TYPE_ETH:
		case TRACE_TYPE_LEGACY_ETH:
			ipptr = trace_get_ip_from_ethernet(
					trace_get_link(packet),
					NULL);
			break;
		case TRACE_TYPE_NONE:
			ipptr = trace_get_link(packet);
			break;
		case TRACE_TYPE_LINUX_SLL:
			{
				struct trace_sll_header_t *sll;

				sll = trace_get_link(packet);
				if (!sll) {
					ipptr = NULL;
				} else if (ntohs(sll->protocol)!=0x0800) {
					ipptr = NULL;
				}
				else {
					ipptr=(void*)((char*)sll+sizeof(*sll));
				}
			}
			break;
		case TRACE_TYPE_PFLOG:
			{
				struct trace_pflog_header_t *pflog;
				pflog = trace_get_link(packet);
				if (!pflog) {
					ipptr = NULL;
					break;
				}
				if (pflog->af != AF_INET6) {
					ipptr = NULL;
				} else {
					ipptr = (void*)((char*)pflog+
						sizeof(*pflog));
				}
			}
			break;
		case TRACE_TYPE_LEGACY_POS:
			{
				/* 64 byte capture. */
				struct libtrace_pos *pos = 
					trace_get_link(packet);
				if (ntohs(pos->ether_type) == 0x0800) {
					ipptr=(void*)((char *)pos+sizeof(*pos));
				} else {
					ipptr=NULL;
				}
				break;
				
			}
		case TRACE_TYPE_LEGACY_ATM:
		case TRACE_TYPE_ATM:
			{
				/* 64 byte capture. */
				struct libtrace_llcsnap *llc = 
					trace_get_link(packet);

				/* advance the llc ptr +4 into the link layer.
				 * need to check what is in these 4 bytes.
				 * don't have time!
				 */
				llc = (void*)((char *)llc + 4);
				if (ntohs(llc->type) == 0x0800) {
					ipptr=(void*)((char*)llc+sizeof(*llc));
				} else {
					ipptr = NULL;
				}
				break;
			}
		default:
			fprintf(stderr,"Don't understand link layer type %i in trace_get_ip6()\n",
				trace_get_link_type(packet));
			ipptr=NULL;
			break;
	}

        return ipptr;
}

/* TODO: split these cases into get_*_from_* functions */
struct libtrace_ip6 *trace_get_ip6(const struct libtrace_packet_t *packet) {
        libtrace_ip6_t *ipptr = 0;

	switch(trace_get_link_type(packet)) {
		case TRACE_TYPE_80211_PRISM:
			{
				ipptr = trace_get_ip6_from_80211(
					(char*)trace_get_link(packet)+144, NULL);
			}
			break;
		case TRACE_TYPE_80211:
			ipptr = trace_get_ip6_from_80211(
					trace_get_link(packet),
					NULL);
			break;
		case TRACE_TYPE_ETH:
		case TRACE_TYPE_LEGACY_ETH:
			{
				ipptr = trace_get_ip6_from_ethernet(
						trace_get_link(packet),
						NULL);
				break;
			}
		case TRACE_TYPE_NONE:
			ipptr = trace_get_link(packet);
			break;
		case TRACE_TYPE_LINUX_SLL:
			{
				trace_sll_header_t *sll;

				sll = trace_get_link(packet);
				if (!sll) {
					ipptr = NULL;
				} else if (ntohs(sll->protocol)!=0x86DD) {
					ipptr = NULL;
				}
				else {
					ipptr = (void*)((char*)sll+
							sizeof(*sll));
				}
			}
			break;
		case TRACE_TYPE_PFLOG:
			{
				struct trace_pflog_header_t *pflog;
				pflog = trace_get_link(packet);
				if (!pflog) {
					ipptr = NULL;
					break;
				}
				if (pflog->af != AF_INET) {
					ipptr = NULL;
				} else {
					ipptr = (void*)((char*)pflog+
						sizeof(*pflog));
				}
			}
			break;
		case TRACE_TYPE_LEGACY_POS:
			{
				/* 64 byte capture. */
				struct libtrace_pos *pos = 
					trace_get_link(packet);
				if (ntohs(pos->ether_type) == 0x86DD) {
					ipptr=(void*)((char *)pos+sizeof(*pos));
				} else {
					ipptr=NULL;
				}
				break;
				
			}
		case TRACE_TYPE_LEGACY_ATM:
		case TRACE_TYPE_ATM:
			{
				/* 64 byte capture. */
				struct libtrace_llcsnap *llc = 
					trace_get_link(packet);

				/* advance the llc ptr +4 into the link layer.
				 * need to check what is in these 4 bytes.
				 * don't have time!
				 */
				llc = (void*)((char *)llc + 4);
				if (ntohs(llc->type) == 0x86DD) {
					ipptr=(void*)((char*)llc+sizeof(*llc));
				} else {
					ipptr = NULL;
				}
				break;
			}
		default:
			fprintf(stderr,"Don't understand link layer type %i in trace_get_ip()\n",
				trace_get_link_type(packet));
			ipptr=NULL;
			break;
	}

        return ipptr;
}

#define SW_IP_OFFMASK 0xff1f

void *trace_get_payload_from_ip(libtrace_ip_t *ipptr, uint8_t *prot,
		int *skipped) 
{
        void *trans_ptr = 0;

        if ((ipptr->ip_off & SW_IP_OFFMASK) == 0) {
		if (skipped) *skipped=(ipptr->ip_hl * 4);
                trans_ptr = (void *)((char *)ipptr + (ipptr->ip_hl * 4));
		if (prot) *prot = ipptr->ip_p;
        }
        return trans_ptr;
}

void *trace_get_payload_from_ip6(libtrace_ip6_t *ipptr, uint8_t *prot,
		int *skipped) 
{
	void *payload = (char*)ipptr+sizeof(libtrace_ip6_t);
	uint8_t nxt = ipptr->nxt;

	if (skipped) skipped+=sizeof(libtrace_ip6_t);

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

					if (skipped)
						*skipped+=len;

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

static void *trace_get_ip4_transport(const libtrace_packet_t *packet,
		uint8_t *proto) 
{
        libtrace_ip_t *ipptr = 0;

        if (!(ipptr = trace_get_ip(packet))) {
                return 0;
        }

        return trace_get_payload_from_ip(ipptr,proto,NULL);
}

static void *trace_get_ip6_transport(const libtrace_packet_t *packet,
		uint8_t *proto) 
{
        libtrace_ip6_t *ipptr = 0;

        if (!(ipptr = trace_get_ip6(packet))) {
                return 0;
        }

        return trace_get_payload_from_ip6(ipptr,proto,NULL);
}

void *trace_get_transport(const struct libtrace_packet_t *packet, 
		uint8_t *proto) 
{
	void *transport;
	uint8_t dummy;

	if (!proto) proto=&dummy;

	transport=trace_get_ip4_transport(packet,proto);
	if (transport) {
		if (*proto == 41) {
			trace_get_payload_from_ip6(transport,proto,NULL);
		}
		return transport;
	}

	return trace_get_ip6_transport(packet,proto);
}

libtrace_tcp_t *trace_get_tcp(const libtrace_packet_t *packet) {
	uint8_t proto;
	libtrace_tcp_t *tcp;

	tcp=trace_get_transport(packet,&proto);

	if (proto != 6)
		return NULL;

	return tcp;
}

libtrace_tcp_t *trace_get_tcp_from_ip(libtrace_ip_t *ip, int *skipped)
{
	struct libtrace_tcp *tcpptr = 0;

	if (ip->ip_p == 6)  {
		tcpptr = (struct libtrace_tcp *)
			trace_get_payload_from_ip(ip, NULL, skipped);
	}

	return tcpptr;
}

libtrace_udp_t *trace_get_udp(libtrace_packet_t *packet) {
	uint8_t proto;
	libtrace_udp_t *udp;

	udp=trace_get_transport(packet,&proto);

	if (proto != 17)
		return NULL;

	return udp;
}

libtrace_udp_t *trace_get_udp_from_ip(libtrace_ip_t *ip, int *skipped)
{
	struct libtrace_udp *udpptr = 0;

	if (ip->ip_p == 17) {
		udpptr = (libtrace_udp_t *)
			trace_get_payload_from_ip(ip, NULL, skipped);
	}

	return udpptr;
}

libtrace_icmp_t *trace_get_icmp(const libtrace_packet_t *packet) {
	uint8_t proto;
	libtrace_icmp_t *icmp;

	icmp=trace_get_transport(packet,&proto);

	if (proto != 1)
		return NULL;

	return icmp;
}

libtrace_icmp_t *trace_get_icmp_from_ip(libtrace_ip_t *ip, int *skipped)
{
	libtrace_icmp_t *icmpptr = 0;

	if (ip->ip_p == 1)  {
		icmpptr = (libtrace_icmp_t *)trace_get_payload_from_ip(ip, NULL, skipped);
	}

	return icmpptr;
}

void *trace_get_payload_from_udp(libtrace_udp_t *udp, int *skipped)
{
	if (skipped) *skipped+=sizeof(libtrace_udp_t);
	return (void*)((char*)udp+sizeof(libtrace_udp_t));
}

void *trace_get_payload_from_tcp(libtrace_tcp_t *tcp, int *skipped)
{
	int dlen = tcp->doff*4;
	if (skipped) *skipped=dlen;
	return tcp+dlen;
}

void *trace_get_payload_from_icmp(libtrace_icmp_t *icmp, int *skipped)
{
	if (skipped) *skipped = sizeof(libtrace_icmp_t);
	return (char*)icmp+sizeof(libtrace_icmp_t);
}

