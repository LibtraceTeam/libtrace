#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "libpacketdump.h"
#ifndef WIN32
	#include <netinet/in_systm.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	libtrace_ip6_t *ip = (libtrace_ip6_t*)packet;
	
	uint32_t tmp = ntohl(*(uint32_t*)ip);

	printf(" IPv6: Version %u\n", (tmp >> 28) & 0x000000f);
	printf(" IPv6: Class %u\n", (tmp >> 20) & 0x000000ff);
	printf(" IPv6: Flow Label %u\n", tmp & 0x000fffff);
	printf(" IPv6: Payload Length %u\n", ntohs(ip->plen));
	printf(" IPv6: Next Header %u\n", ip->nxt);
	printf(" IPv6: Hop Limit %u\n", ip->hlim);


	char ipstr[INET6_ADDRSTRLEN];                             
	inet_ntop(AF_INET6, &(ip->ip_src), ipstr, INET6_ADDRSTRLEN);

	printf(" IPv6: Source IP %s\n", ipstr);
	inet_ntop(AF_INET6, &(ip->ip_dst), ipstr, INET6_ADDRSTRLEN);
	printf(" IPv6: Destination IP %s\n", ipstr);

	decode_next(packet+sizeof(libtrace_ip6_t),len-sizeof(libtrace_ip6_t),"ip",ip->nxt);
	return;
}
