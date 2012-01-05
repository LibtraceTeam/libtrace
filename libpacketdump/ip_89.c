#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libpacketdump.h"

static void dump_ospf_v2_header(libtrace_ospf_v2_t *hdr, unsigned len) {

	printf(" OSPF Header: Version %u Type %u ",
			hdr->ospf_v, hdr->type);
	switch(hdr->type) {
		case TRACE_OSPF_HELLO:
			printf("(Hello)");
			break;
		case TRACE_OSPF_DATADESC:
			printf("(Database Desc)");
			break;
		case TRACE_OSPF_LSREQ:
			printf("(Link State Request)");
			break;
		case TRACE_OSPF_LSUPDATE:
			printf("(Link State Update)");
			break;
		case TRACE_OSPF_LSACK:
			printf("(Link State Ack.)");
			break;
	}

	printf("\n OSPF Header: Length %u \n", ntohs(hdr->len));
	printf(" OSPF Header: Router Id %s ", inet_ntoa(hdr->router));
	printf("Area Id %s\n", inet_ntoa(hdr->area));
	printf(" OSPF Header: Checksum %u Auth Type %u\n", ntohs(hdr->sum),
			ntohs(hdr->au_type));

	printf(" OSPF Header: Auth Key ID %u Auth Data Len %u\n", 
			hdr->au_key_id, hdr->au_data_len);
	printf(" OSPF Header: Auth Crypto Seq %u\n", ntohl(hdr->au_seq_num));


}

DLLEXPORT void decode(int link_type UNUSED, const char *packet, unsigned len) {

	libtrace_ospf_v2_t *hdr = (libtrace_ospf_v2_t *)packet;

	if (hdr->ospf_v == 2) {
		dump_ospf_v2_header(hdr, len);
		decode_next(packet + sizeof(libtrace_ospf_v2_t), 
			len - sizeof(libtrace_ospf_v2_t), "ospf2", 
			hdr->type);
	}

	return;

}
