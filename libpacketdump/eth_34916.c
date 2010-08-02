
#include "libtrace_int.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include "libpacketdump.h"
#include "libtrace.h"

typedef struct pppoe_t {
	LT_BITFIELD8	ver:4;
	LT_BITFIELD8	type:4;
	uint8_t		code;
	uint16_t	session;
	uint16_t	length;
} pppoe_t;

DLLEXPORT void decode(int link_type UNUSED,const char *pkt,unsigned len) 
{
	pppoe_t *pppoe = (pppoe_t *) pkt;
	
	if (len < sizeof(*pppoe)) {
		printf(" PPPoE: Truncated (len = %u)\n", len);
		return;
	}

	printf(" PPPoE: Version: %d\n",pppoe->ver);
	printf(" PPPoE: Type: %d\n",pppoe->type);
	printf(" PPPoE: Code: %d\n",pppoe->code);
	printf(" PPPoE: Session: %d\n",ntohs(pppoe->session));
	printf(" PPPoE: Length: %d\n",ntohs(pppoe->length));

	/* Meh.. pass it off to eth decoder */
	decode_next(pkt + sizeof(*pppoe), len - sizeof(*pppoe), "link", 5);

}


