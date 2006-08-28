#ifndef __LIBPACKETDUMP_H__
#define __LIBPACKETDUMP_H__
#include "libtrace.h"

#ifdef __cplusplus 
extern "C" {
#endif

void trace_dump_packet(libtrace_packet_t *packet);
void decode_next(char *packet,int len,char *proto_name,int type);

#ifdef __cplusplus 
}
#endif

#endif
