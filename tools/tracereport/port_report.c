#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libtrace.h"
#include "tracereport.h"
#include "contain.h"

CMP(cmp_int,int,a-b)
MAP(int,MAP(int,stat_t)) protocol_tree = MAP_INIT(cmp_int);


void port_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	if (!ip)
		return;

	int port = trace_get_server_port(ip->ip_p,
			trace_get_source_port(packet),
			trace_get_destination_port(packet))==USE_SOURCE
		? trace_get_source_port(packet)
		: trace_get_destination_port(packet);


	if (!MAP_FIND(protocol_tree,ip->ip_p)) {
		MAP_INSERT(protocol_tree,ip->ip_p,MAP_INIT(cmp_int));
	}

	if (!MAP_FIND(MAP_FIND(protocol_tree,ip->ip_p)->value,port)) {
		MAP_INSERT(MAP_FIND(protocol_tree,ip->ip_p)->value,port,{0});
	}

	++MAP_FIND(MAP_FIND(protocol_tree,ip->ip_p)->value,port)->value.count;
	MAP_FIND(MAP_FIND(protocol_tree,ip->ip_p)->value,port)->value.bytes+=trace_get_wire_length(packet);
}

static MAP_VISITOR(port_visitor,int,stat_t)
{
	struct servent *ent = getservbyport(htons(node->key),(char *)userdata);
	if(ent)
		printf("%20s:\t%12" PRIu64 "\t%12" PRIu64 "\n",
				ent->s_name,
				node->value.bytes,
				node->value.count
		      );
	else
		printf("%20i:\t%12" PRIu64 "\t%12" PRIu64 "\n",
				node->key,
				node->value.bytes,
				node->value.count
		      );
}

static MAP_VISITOR(protocol_visitor,int,MAP(int,stat_t))
{
	struct protoent *ent = getprotobynumber(node->key);
	printf("Protocol: %i %s%s%s\n",node->key,
			ent?"(":"",ent?ent->p_name:"",ent?")":"");
	MAP_VISIT(node->value,NULL,port_visitor,NULL,(void*)(ent?ent->p_name:""));
}

void port_report(void)
{
	printf("# Port breakdown:\n");
	printf("%-20s \t%12s\t%12s\n","Port","Bytes","Packets");
	setservent(1);
	setprotoent(1);
	MAP_VISIT(protocol_tree,NULL,protocol_visitor,NULL,NULL);
	endprotoent();
	endservent();
}
