#ifndef __TRACEDUMP_H__
#define __TRACEDUMP_H__

void per_packet(int link_type,char *buffer, int size);

void decode_next(char *packet,int len,char *proto_name,int type);

#endif
