/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */
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
#define DISPLAYIP(hdr,x,fmt) DISPLAY_EXP(hdr,x,fmt,inet_ntoa(*(struct in_addr*)(void *)(&hdr->x)))


void trace_hexdump_packet(libtrace_packet_t *packet);
void trace_dump_packet(libtrace_packet_t *packet);
void decode_next(const char *packet,int len,const char *proto_name,int type);

void decode(int link_type, const char *pkt, unsigned len);
void decode_meta(int link_type, const char *pkt, unsigned len, libtrace_packet_t *p);

#ifdef __cplusplus 
}
#endif

#endif
