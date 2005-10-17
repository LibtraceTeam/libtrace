#include <netdb.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libtrace.h"
#include "tracereport.h"
#include "tree.h"

#define MEMDUP(x) memcpy(malloc(sizeof(x)),&x,sizeof(x))

static tree_t *protocol_tree = NULL;

int protocolcmp(const void *a,const void *b) { 
	return *(uint8_t*)a-*(uint8_t*)b;
}
int portcmp(const void *a, const void *b) {
	return *(uint16_t*)a-*(uint16_t*)b;
}

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

	uint8_t *protocol = MEMDUP(ip->ip_p);
	uint16_t *portmem = MEMDUP(port);


	tree_t *ports=tree_find(&protocol_tree,protocol,protocolcmp);

	stat_t *stat =tree_find(&ports,portmem,portcmp);
	if (!stat) {
		stat=calloc(1,sizeof(stat_t));
	}
	++stat->count;
	stat->bytes+=trace_get_wire_length(packet);
	if (tree_replace(&ports,portmem,portcmp,stat)) {
		free(portmem);
	}
	if (tree_replace(&protocol_tree,protocol,protocolcmp,ports)) {
		free(protocol);
	}
}

static void port_visitor(const void *key, void *value, void *data)
{
	struct servent *ent = getservbyport(htons(*(uint16_t*)key),(char *)data);
	if(ent)
		printf("%20s:\t%12" PRIu64 "\t%12" PRIu64 "\n",
				ent->s_name,
				((stat_t *)value)->bytes,
				((stat_t *)value)->count
		      );
	else
		printf("%20i:\t%12" PRIu64 "\t%12" PRIu64 "\n",
				*(uint16_t*)key,
				((stat_t *)value)->bytes,
				((stat_t *)value)->count
		      );
}

static void protocol_visitor(const void *key, void *value, void *data)
{
	struct protoent *ent = getprotobynumber(*(uint8_t*)key);
	printf("Protocol: %i %s%s%s\n",*(uint8_t*)key,
			ent?"(":"",ent?ent->p_name:"",ent?")":"");
	tree_inorder((tree_t**)&value,
			port_visitor,
			(void*)(ent?ent->p_name:""));
}

void port_report(void)
{
	int i;
	printf("# Port breakdown:\n");
	printf("%-20s \t%12s\t%12s\n","Port","Bytes","Packets");
	setservent(1);
	setprotoent(1);
	tree_inorder(&protocol_tree,protocol_visitor,NULL);
	endprotoent();
	endservent();
}
