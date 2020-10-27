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


