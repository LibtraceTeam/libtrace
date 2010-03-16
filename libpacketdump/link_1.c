/* Decoder for CHDLC frames */

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libtrace.h"
#include "libpacketdump.h"

typedef struct libtrace_chdlc_t {
        uint8_t address;        /** 0xF0 for unicast, 0xF8 for multicast */
        uint8_t control;        /** Always 0x00 */
        uint16_t ethertype;
} libtrace_chdlc_t;


DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	libtrace_chdlc_t *frame = (libtrace_chdlc_t *)packet;

	printf(" CHDLC:");
	if (len >= 1)
		printf(" Address: 0x%02x", frame->address);
	else {
		printf("[|Truncated]\n");
		return;
	}
	
	if (len >= 2)
		printf(" Control: 0x%02x", frame->control);
	else {
		printf("[|Truncated]\n");
		return;
	}
	
	if (len >= 4) {
		printf(" Ethertype: 0x%04x\n", ntohs(frame->ethertype));
		decode_next(packet + 4, len - 4, "eth", 
				ntohs(frame->ethertype));
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	

	return;
}
