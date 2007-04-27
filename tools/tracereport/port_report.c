#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libtrace.h"
#include "tracereport.h"
#include "contain.h"
#include "report.h"

stat_t *ports[3][256] = {{NULL}};
char protn[256]={0};
static bool suppress[3] = {true,true,true};

void port_per_packet(struct libtrace_packet_t *packet)
{
	uint8_t proto;
	int port;
	libtrace_direction_t dir = trace_get_direction(packet);

	if(trace_get_transport(packet,&proto,NULL)==NULL) 
		return;

	if (dir != TRACE_DIR_INCOMING && dir != TRACE_DIR_OUTGOING)
		dir = TRACE_DIR_OTHER;
	
	port = trace_get_server_port(proto,
			trace_get_source_port(packet),
			trace_get_destination_port(packet))==USE_SOURCE
		? trace_get_source_port(packet)
		: trace_get_destination_port(packet);

	if (!ports[dir][proto])
		ports[dir][proto]=calloc(65536,sizeof(stat_t));
	ports[dir][proto][port].bytes+=trace_get_wire_length(packet);
	ports[dir][proto][port].count++;
	protn[proto]=1;
	suppress[dir] = false;
}


static void port_port(int i,char *prot, int j, FILE *out)
{
	struct servent *ent = getservbyport(htons(j),prot);
	int k;
	
	if(ent){
		fprintf(out,"%16s:",ent->s_name);
	}
	else{
		fprintf(out,"%16i:",j);
	}

	for (k = 0; k < 3; k++) {
		if (!ports[k][i])
			continue;
		if (k != 0) {
			fprintf(out, "%16s", " ");
		}
		switch (k) {
			case 0:
	                        fprintf(out, "\t%10s", "Outbound");
                                break;
			case 1:
				fprintf(out, "\t%10s", "Inbound");
				break;
			case 2:
				fprintf(out, "\t%10s", "Unknown");
				break;
		}
		fprintf(out, "\t%16" PRIu64 " %16" PRIu64 "\n",
			ports[k][i][j].bytes,
			ports[k][i][j].count);
	}
}

static void port_protocol(int i, FILE *out)
{
	int j,k;
	struct protoent *ent = getprotobynumber(i);
	fprintf(out, "Protocol: %i %s%s%s\n",i,
			ent?"(":"",ent?ent->p_name:"",ent?")":"");
	for(j=0;j<65536;++j) {
		for(k=0;k<3;k++){
			if (ports[k][i] && ports[k][i][j].count) {
				port_port(i,ent?ent->p_name:"",j, out);
				break;
			}
		}
	}
}

void port_report(void)
{
	int i;
	FILE *out = fopen("ports.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	fprintf(out, "%-16s\t%10s\t%16s %16s\n",
                        "PORT",
                        "DIRECTION",
                        "BYTES",
                        "PACKETS");	

	setservent(1);
	setprotoent(1);
	for(i=0;i<256;++i) {
		if (protn[i]) {
			port_protocol(i, out);
			free(ports[0][i]);
			free(ports[1][i]);
			free(ports[2][i]);
		}
	}
	endprotoent();
	endservent();
	fclose(out);
}
