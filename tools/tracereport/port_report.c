#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libtrace.h"
#include "tracereport.h"
#include "contain.h"

stat_t ports[4][256][65536]={{{{0,0}}}};
char protn[256]={0};
static bool suppress[4] = {true,true,true,true};

void port_per_packet(struct libtrace_packet_t *packet)
{
	uint8_t proto;
	int port;
	int dir = trace_get_direction(packet);
	if(dir < 0 || dir > 1)
		dir = 2;
	if(trace_get_transport(packet,&proto,NULL)==NULL) 
		return;

	port = trace_get_server_port(proto,
			trace_get_source_port(packet),
			trace_get_destination_port(packet))==USE_SOURCE
		? trace_get_source_port(packet)
		: trace_get_destination_port(packet);

	ports[dir][proto][port].bytes+=trace_get_wire_length(packet);
	ports[dir][proto][port].count++;
	protn[proto]=1;
	suppress[dir] = false;
}

void port_suppress()
{
	int i;
	printf("%-20s","Direction:");
	for(i=0;i<4;i++){
		if(!suppress[i]){
			switch(i){
				case 0:
					printf("\t%24s", "Outbound   ");
					break;
				case 1:
					printf("\t%24s", "Inbound   ");
					break;
				case 2:
					printf("\t%24s", "Undefined   ");
					break;
				default:
					break;
			}
		}
	}
	printf("\n");
	printf("%-20s","Port");
	for(i=0;i<4;i++){
		if(!suppress[i]){
			printf("\t%12s\t%12s", "bytes","packets");
		}
	}
	printf("\n");
}

void port_port(int i,char *prot, int j)
{
	struct servent *ent = getservbyport(htons(j),prot);
	int k;
	
	if(ent){
		printf("%20s:",ent->s_name);
		for(k=0;k<4;k++){
			if (ports[k][i][j].count==0){
				if(!suppress[k])
					printf("\t%24s"," ");
				continue;
			}
			printf("\t%12" PRIu64 "\t%12" PRIu64,
				ports[k][i][j].bytes,
				ports[k][i][j].count
		      );
		}
	}
	else{
		printf("%20i:",j);
		for(k=0;k<4;k++){
			if (ports[k][i][j].count==0){
				if(!suppress[k])
					printf("\t%24s"," ");
				continue;
			}
			printf("\t%12" PRIu64 "\t%12" PRIu64,
				ports[k][i][j].bytes,
				ports[k][i][j].count
		      );
		}
	}
	printf("\n");
}

void port_protocol(int i)
{
	int j,k;
	struct protoent *ent = getprotobynumber(i);
	printf("Protocol: %i %s%s%s\n",i,
			ent?"(":"",ent?ent->p_name:"",ent?")":"");
	for(j=0;j<65536;++j) {
		for(k=0;k<4;k++){
			if (ports[k][i][j].count) {
				port_port(i,ent?ent->p_name:"",j);
				break;
			}
		}
	}
}

void port_report(void)
{
	int i;
	printf("# Port breakdown:\n");
	port_suppress();
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
