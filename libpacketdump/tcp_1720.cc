// h323
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <map>
#include "libpacketdump.h"
#include <netinet/tcp.h>
#include <netinet/in.h>
#include "asn1.h"

#define SAFE(x) \
	((unsigned int)len>=((char*)&tcp->x-(char*)tcp+sizeof(tcp->x))) 
#define DISPLAY_EXP(x,fmt,exp) \
	if (SAFE(x)) \
		printf(fmt,exp); \
	else \
		return; 

#define DISPLAY(x,fmt) DISPLAY_EXP(x,fmt,tcp->x)

#define DISPLAYS(x,fmt) DISPLAY_EXP(x,fmt,htons(tcp->x))
#define DISPLAYL(x,fmt) DISPLAY_EXP(x,fmt,htonl(tcp->x))
#define DISPLAYIP(x,fmt) DISPLAY_EXP(x,fmt,inet_ntoa(*(struct in_addr*)&tcp->x))

extern "C"
void decode(int link_type,char *packet,int len)
{
	ASN asn;
	if (len<=0)
		return;
	asn.feed(packet,len);
	while (!asn.eof())
		asn.getEncoding()->display();
	return;
}
