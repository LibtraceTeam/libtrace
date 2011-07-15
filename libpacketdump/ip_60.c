#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"

DLLEXPORT void decode(int link_type UNUSED, const char *packet, unsigned len) {

	uint16_t hbh_len = 0;
	libtrace_ip6_ext_t* hdr = (libtrace_ip6_ext_t*)packet;

	hbh_len = (hdr->len + 1) * 8;

	printf(" IPv6 Destination Options: Next Header %u Header Ext Len %u",
			hdr->nxt, hdr->len);

	printf("\n");

	decode_next(packet + hbh_len, len - hbh_len, "ip", hdr->nxt);


}
