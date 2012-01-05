#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "libpacketdump.h"


DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len) {
	
	libtrace_ospf_summary_lsa_v2_t *sum = (libtrace_ospf_summary_lsa_v2_t *)packet;

	if (len >= 4) {
		printf(" OSPF Summary LSA: Netmask %s ", inet_ntoa(sum->netmask));
	}

	if (len < 8) 
		return;
	
	printf("Metric %u\n", trace_get_ospf_metric_from_summary_lsa_v2(sum));
}
