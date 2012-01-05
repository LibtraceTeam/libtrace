#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "libpacketdump.h"

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len) {
	unsigned char *link_ptr = NULL;
        libtrace_ospf_link_v2_t *link;
        uint32_t link_len;
        libtrace_ospf_router_lsa_v2_t *hdr;

        int i = 0;

	hdr = (libtrace_ospf_router_lsa_v2_t *)packet;

	if (len < 4)
		return;
	
	printf(" OSPF Router LSA: Links %u ", ntohs(hdr->num_links));
	if (hdr->v)
		printf("V ");
	if (hdr->e) 
		printf("E ");
	if (hdr->b)
		printf("B ");
	printf("\n");

	link_ptr = trace_get_first_ospf_link_from_router_lsa_v2(hdr, &len);

	if (!link_ptr || len == 0)
		return;
	while (trace_get_next_ospf_link_v2(&link_ptr, &link, &len, &link_len) > 0) {
		printf(" OSPF Router Link: Id %s ", inet_ntoa(link->link_id));
		printf("Data %s\n", inet_ntoa(link->link_data));
		printf(" OSPF Router Link: Type %u TOS %u Metric %u\n",
				link->type, link->num_tos,
				ntohs(link->tos_metric));
		i++;
		if (i == ntohs(hdr->num_links))
			break;
	}
}

	
