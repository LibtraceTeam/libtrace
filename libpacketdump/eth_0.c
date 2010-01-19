#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <ctype.h>
#include "libpacketdump.h"

#define WIDTH 16

/* This is an example of a decoder for a protocol that we know exists, but is undocumented.
 * We dump the protocol as hex, and then skip onto the next header which we do know exists.
 */

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	unsigned int i=0;
	printf(" Ubiquity:");
	for(i=0;i<132; /* Nothing */ ) {
		unsigned int j;
		printf("\n ");
		for(j=0;j<WIDTH;j++) {
			if (i+j<len)
				printf(" %02x",(unsigned char)packet[i+j]);
			else
				printf("   ");
		}
		printf("    ");
		for(j=0;j<WIDTH;j++) {
			if (i+j<len)
				if (isprint((unsigned char)packet[i+j]))
					printf("%c",(unsigned char)packet[i+j]);
				else
					printf(".");
			else
				printf("   ");
		}
		if (i+WIDTH>len)
			break;
		else
			i+=WIDTH;
	}
	printf("\n");
	if (len>132)
		decode_next(packet+132,len-132,"link",4);
	return;
}
