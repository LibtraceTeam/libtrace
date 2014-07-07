#ifndef __LIBPACKETDUMP_H__
#define __LIBPACKETDUMP_H__
#include "libtrace.h"

#ifdef __cplusplus 
extern "C" {
#endif

#define SAFE(hdr,x) \
        ((unsigned int)len>=((char*)&hdr->x-(char*)hdr+sizeof(hdr->x))) 

#define DISPLAY_EXP(hdr,x,fmt,exp) \
        if (SAFE(hdr, x)) \
                printf(fmt,exp); \
        else {\
                printf("(Truncated)\n"); \
                return; \
        }

#define DISPLAY(hdr,x,fmt) DISPLAY_EXP(hdr,x,fmt,hdr->x)

#define DISPLAYS(hdr,x,fmt) DISPLAY_EXP(hdr,x,fmt,htons(hdr->x))
#define DISPLAYL(hdr,x,fmt) DISPLAY_EXP(hdr,x,fmt,htonl(hdr->x))
#define DISPLAYIP(hdr,x,fmt) DISPLAY_EXP(hdr,x,fmt,inet_ntoa(*(struct in_addr*)&hdr->x))


void trace_hexdump_packet(libtrace_packet_t *packet);
void trace_dump_packet(libtrace_packet_t *packet);
void decode_next(const char *packet,int len,const char *proto_name,int type);

void decode(int link_type, const char *pkt, unsigned len);

#ifdef __cplusplus 
}
#endif

#endif
