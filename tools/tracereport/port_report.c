#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libtrace.h"
#include "tracereport.h"
#include "contain.h"

stat_t ports[256][65536]={{{0,0}}};
char protn[256]={0};

void port_per_packet(struct libtrace_packet_t *packet)
{
	uint8_t proto;
	int port;

	if(trace_get_transport(packet,&proto,NULL)==NULL) 
		return;

	port = trace_get_server_port(proto,
			trace_get_source_port(packet),
			trace_get_destination_port(packet))==USE_SOURCE
		? trace_get_source_port(packet)
		: trace_get_destination_port(packet);

	ports[proto][port].bytes+=trace_get_wire_length(packet);
	ports[proto][port].count++;
	protn[proto]=1;
}

void port_port(int i,char *prot, int j)
{
	struct servent *ent = getservbyport(htons(j),prot);
	if(ent)
		printf("%20s:\t%12" PRIu64 "\t%12" PRIu64 "\n",
				ent->s_name,
				ports[i][j].bytes,
				ports[i][j].count
		      );
	else
		printf("%20i:\t%12" PRIu64 "\t%12" PRIu64 "\n",
				j,
				ports[i][j].bytes,
				ports[i][j].count
		      );
}

void port_protocol(int i)
{
	int j;
	struct protoent *ent = getprotobynumber(i);
	printf("Protocol: %i %s%s%s\n",i,
			ent?"(":"",ent?ent->p_name:"",ent?")":"");
	for(j=0;j<65536;++j) {
		if (ports[i][j].count) {
			port_port(i,ent?ent->p_name:"",j);
		}
	}
}

void port_report(void)
{
	int i;
	printf("# Port breakdown:\n");
	printf("%-20s \t%12s\t%12s\n","Port","Bytes","Packets");
	setservent(1);
	setprotoent(1);
	for(i=0;i<256;++i) {
		if (protn[i]) {
			port_protocol(i);
		}
	}
	endprotoent();
	endservent();
}
