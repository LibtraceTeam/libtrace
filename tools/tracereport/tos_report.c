#include <netdb.h>
#include <inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"

static stat_t tos_stat[256] = { {0,0} } ;

void tos_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	if (!ip)
		return;

	tos_stat[ip->ip_tos].count++;
	tos_stat[ip->ip_tos].bytes+=trace_get_wire_length(packet);
}

void tos_report(void)
{
	int i;
	printf("# TOS breakdown:\n");
	printf("%-20s \t%12s\t%12s\n","ToS","bytes","packets");
	for(i=0;i<256;++i) {
		if (tos_stat[i].count==0)
			continue;
		printf("%16s0x%02x:\t%12" PRIu64 ":\t%12" PRIu64 "\n",
				" ",
				i,
				tos_stat[i].bytes,
				tos_stat[i].count);
	}
}
