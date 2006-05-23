#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

static stat_t prot_stat[256] = { {0,0} } ;

void protocol_per_packet(struct libtrace_packet_t *packet)
{
	uint8_t proto;
	if (trace_get_transport(packet,&proto,NULL)==NULL)
		return;
		
	prot_stat[proto].count++;
	prot_stat[proto].bytes+=trace_get_wire_length(packet);
}

void protocol_report(void)
{
	int i;
	printf("# Protocol breakdown:\n");
	printf("%-20s \t%12s\t%12s\n","Protocol","bytes","packets");
	setprotoent(1);
	for(i=0;i<256;++i) {
		struct protoent *prot;
		if (prot_stat[i].count==0)
			continue;
		prot = getprotobynumber(i);
		if (prot) {
		printf("%20s:\t%12" PRIu64 "\t%12" PRIu64 "\n",
				prot->p_name,
				prot_stat[i].bytes,
				prot_stat[i].count);
		}
		else {
		printf("%20i:\t%12" PRIu64 "\t%12" PRIu64 "\n",
				i,
				prot_stat[i].bytes,
				prot_stat[i].count);

		}
	}
	setprotoent(0);
}
