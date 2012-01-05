#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "libpacketdump.h"


DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len) {
	libtrace_ospf_ls_update_t *update = (libtrace_ospf_ls_update_t *)packet;
	unsigned char *lsa_ptr;
	uint8_t lsa_type;
	libtrace_ospf_lsa_v2_t *lsa_hdr;
	unsigned char *lsa_body;
	int i = 0;
	int max_lsas = 0;
	uint32_t rem = len;
	uint16_t lsa_length;


	if (len < 4)
		return;
	max_lsas = ntohl(update->ls_num_adv);
	printf(" OSPF LS Update: LSAs %u\n", max_lsas);
	

	lsa_ptr = trace_get_first_ospf_lsa_from_update_v2(update, &rem);

	if (lsa_ptr == NULL || rem == 0)
		return;

	while (trace_get_next_ospf_lsa_v2(&lsa_ptr, &lsa_hdr, &lsa_body,
			&rem, &lsa_type, &lsa_length) > 0) {

		i ++;
		if (lsa_hdr) {

			decode_next((char *)lsa_hdr, lsa_length, "ospf2", 1000);
		}	

		if (lsa_body) {
			decode_next((char *)lsa_body, lsa_length - 
					sizeof(libtrace_ospf_lsa_v2_t),
					"ospf2",
					1000 + lsa_type);
		}

		if (i == max_lsas)
			break;


	}
}
