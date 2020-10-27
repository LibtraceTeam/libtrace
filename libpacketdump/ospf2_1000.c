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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "libpacketdump.h"

/* Decoder for an LSA header */

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len) {

	libtrace_ospf_lsa_v2_t *lsa = (libtrace_ospf_lsa_v2_t *)packet;

	if (len < 2)
		return;
	printf(" OSPF LSA: Age %u ", ntohs(lsa->age));	

	if (len < 3)
		return;
	printf("Options ");

	if (lsa->lsa_options.e_bit)
		printf("E ");
	if (lsa->lsa_options.mc_bit)
		printf("MC ");
	if (lsa->lsa_options.np_bit)
		printf("N/P ");
	if (lsa->lsa_options.ea_bit)
		printf("EA ");
	if (lsa->lsa_options.dc_bit)
		printf("DC ");
	printf("\n");

	if (len < 4)
		return;
	printf(" OSPF LSA: LS Type %u ", lsa->lsa_type);
	switch(lsa->lsa_type) {
		case 1:
			printf("(Router LSA)\n");
			break;
		case 2:
			printf("(Network LSA)\n");
			break;
		case 3:
			printf("(Summary LSA - IP)\n");
			break;
		case 4:
			printf("(Summary LSA - ASBR)\n");
			break;
		case 5:
			printf("(AS External LSA)\n");
			break;
		default:
			printf("(Unknown)\n");
	}
	
	if (len < 8)
		return;
	
	printf(" OSPF LSA: Link State ID %s ", inet_ntoa(lsa->ls_id));

	if (len < 12) {
		printf("\n");
		return;
	}

	printf("Advertising Router %s\n", inet_ntoa(lsa->adv_router));

	if (len < 16)
		return;

	printf(" OSPF LSA: Seq %u ", ntohl(lsa->seq));

	if (len < 18) {
		printf("\n");
		return;
	}

	printf("Checksum %u ", ntohs(lsa->checksum));

	if (len < 20) {
		printf("\n");
		return;
	}

	printf("Length %u \n", ntohs(lsa->length));
}
