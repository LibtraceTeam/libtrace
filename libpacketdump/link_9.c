/* Decoder for PPP with HDLC frames */

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libtrace.h"
#include "libpacketdump.h"

typedef struct libtrace_hdlc_t {
        uint8_t address;        /** Always 0xff */
        uint8_t control;        /** Always 0x03 */
        uint16_t protocol;
} libtrace_hdlc_t;


DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	libtrace_hdlc_t *frame = (libtrace_hdlc_t *)packet;

	printf(" PPP:");
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
		printf(" Protocol: 0x%04x\n", ntohs(frame->protocol));
		
		/* PPP protocols do not match ethertypes, so we have to
		 * convert
		 *
		 * XXX develop decoders for PPP protocols so this can be
		 * done generically 
		 */
		if (ntohs(frame->protocol) == 0x0021) {
			decode_next(packet + 4, len - 4, "eth", 0x0800);
		} 
	}
	else {
		printf("[|Truncated]\n");
		return;
	}
	

	return;
}
