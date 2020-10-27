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
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"
#include "libtrace.h"
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netdb.h>


DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	struct libtrace_udp *udp = (struct libtrace_udp*)packet;
	printf(" UDP:");
	if (SAFE(udp, source)) {
		struct servent *ent=getservbyport(udp->source,"udp");
		if(ent) {
			printf(" Source %i (%s)",htons(udp->source),ent->s_name);
		} else {
			printf(" Source %i",htons(udp->source));
		}
	}
	else {
		printf("\n");
		return;
	}
	if (SAFE(udp, dest)) {
		struct servent *ent=getservbyport(udp->dest,"udp");
		if(ent) {
			printf(" Dest %i (%s)",htons(udp->dest),ent->s_name);
		} else {
			printf(" Dest %i",htons(udp->dest));
		}
	}
	else {
		printf("\n");
		return;
	}
	printf("\n UDP:");
	DISPLAYS(udp, len," Len %u");
	DISPLAYS(udp, check," Checksum %u");
	printf("\n");
	if (htons(udp->source) < htons(udp->dest)) 
		decode_next(packet+sizeof(*udp),len-sizeof(*udp),"udp",htons(udp->source));
	else
		decode_next(packet+sizeof(*udp),len-sizeof(*udp),"udp",htons(udp->dest));
	return;
}
