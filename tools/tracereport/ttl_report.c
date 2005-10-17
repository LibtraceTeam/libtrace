#include <netdb.h>
#include <inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"

static stat_t ttl_stat[256] = { {0,0} } ;

void ttl_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	if (!ip)
		return;

	ttl_stat[ip->ip_ttl].count++;
	ttl_stat[ip->ip_ttl].bytes+=trace_get_wire_length(packet);
}

void ttl_report(void)
{
	int i;
	printf("# TTL breakdown:\n");
	printf("%-20s \t%12s\t%12s\n","TTL","bytes","packets");
	for(i=0;i<256;++i) {
		if (ttl_stat[i].count==0)
			continue;
		printf("%20i:\t%12" PRIu64 ":\t%12" PRIu64 "\n",
				i,
				ttl_stat[i].bytes,
				ttl_stat[i].count);
	}
}
