#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "libpacketdump.h"

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len) {

	libtrace_ospf_as_external_lsa_v2_t *as = (libtrace_ospf_as_external_lsa_v2_t *)packet;

	if (len < 4)
		return;
	
	printf (" OSPF AS External LSA: Netmask %s ", inet_ntoa(as->netmask));

	if (len < 8) {
		printf("\n");
		return;
	}
	
	printf( "Metric %u\n", trace_get_ospf_metric_from_as_external_lsa_v2(as));

	if (len < 12)
		return;
	
	printf(" OSPF AS External LSA: Forwarding %s ", inet_ntoa(as->forwarding));

	if (len < 16) {
		printf("\n");
		return;
	}
	
	printf("External Tag %u\n", ntohl(as->external_tag));

}

