#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "libpacketdump.h"

/* Decoder for an LSA header */

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len) {

	libtrace_ospf_lsa_v2_t *lsa = (libtrace_ospf_lsa_v2_t *)packet;

	if (len < 2)
		return;
	printf(" OSPF LSA: Age %u ", ntohs(lsa->age));	

	if (len < 3)
		return;
	printf("Options ");

	if (lsa->lsa_options.e_bit)
		printf("E ");
	if (lsa->lsa_options.mc_bit)
		printf("MC ");
	if (lsa->lsa_options.np_bit)
		printf("N/P ");
	if (lsa->lsa_options.ea_bit)
		printf("EA ");
	if (lsa->lsa_options.dc_bit)
		printf("DC ");
	printf("\n");

	if (len < 4)
		return;
	printf(" OSPF LSA: LS Type %u ", lsa->lsa_type);
	switch(lsa->lsa_type) {
		case 1:
			printf("(Router LSA)\n");
			break;
		case 2:
			printf("(Network LSA)\n");
			break;
		case 3:
			printf("(Summary LSA - IP)\n");
			break;
		case 4:
			printf("(Summary LSA - ASBR)\n");
			break;
		case 5:
			printf("(AS External LSA)\n");
			break;
		default:
			printf("(Unknown)\n");
	}
	
	if (len < 8)
		return;
	
	printf(" OSPF LSA: Link State ID %s ", inet_ntoa(lsa->ls_id));

	if (len < 12) {
		printf("\n");
		return;
	}

	printf("Advertising Router %s\n", inet_ntoa(lsa->adv_router));

	if (len < 16)
		return;

	printf(" OSPF LSA: Seq %u ", ntohl(lsa->seq));

	if (len < 18) {
		printf("\n");
		return;
	}

	printf("Checksum %u ", ntohs(lsa->checksum));

	if (len < 20) {
		printf("\n");
		return;
	}

	printf("Length %u \n", ntohs(lsa->length));
}
