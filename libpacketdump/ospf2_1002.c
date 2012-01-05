#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "libpacketdump.h"

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len) {
	libtrace_ospf_network_lsa_v2_t *net;
	struct in_addr *router = NULL;

	net = (libtrace_ospf_network_lsa_v2_t *)packet;

	if (len < 4)
		return;
	printf(" OSPF Network LSA: Netmask %s\n", inet_ntoa(net->netmask));

	router = (struct in_addr *)(packet + sizeof(libtrace_ospf_network_lsa_v2_t));
	len -= sizeof(libtrace_ospf_network_lsa_v2_t);

	while (len >= sizeof(struct in_addr)) {

		printf("OSPF Network LSA: Attached Router %s\n", 
				inet_ntoa(*router));
		router ++;
		len -= sizeof(struct in_addr);
	}
}
