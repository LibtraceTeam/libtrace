#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "libpacketdump.h"

#include <assert.h>

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len) {

	unsigned char *lsa_ptr = (unsigned char *)packet;
	uint32_t rem = len;
	uint16_t lsa_length = 0;
	uint8_t lsa_type;
	libtrace_ospf_lsa_v2_t *lsa_hdr;

	while (trace_get_next_ospf_lsa_header_v2(&lsa_ptr, &lsa_hdr, 
                       	&rem, &lsa_type, &lsa_length) > 0) {

		if (lsa_hdr) {
			decode_next((char *)lsa_hdr, lsa_length, "ospf2", 1000);
		}

		/* These packets contain LSA headers only so don't try to
		 * decode the body */
	}
}
