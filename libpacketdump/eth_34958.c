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
#include "libpacketdump.h"

#define POPBYTE(x) 				\
		do {				\
			if (len<1) return;	\
			x=*(packet++);		\
		} while(0)			

#define POPWORD(x) 				\
		do {				\
			if (len<2) return;	\
			x=htons(*(uint16_t*)packet);	\
			packet+=2;		\
		} while(0)

static void decode_eap_request(const char *packet, unsigned len)
{
	int v;
	POPBYTE(v);
	printf(" 802.1x: EAP: Identifier: %u\n",v);
	POPWORD(v);
	printf(" 802.1x: EAP: Length: %u\n",v);
	POPBYTE(v);
	printf(" 802.1x: EAP: Type: ");
	switch(v) {
		case 1: printf(" Identity (1)\n"); break;
		case 2: printf(" Notification (2)\n"); break;
		case 3: printf(" NAK (3)\n"); break;
		case 4: printf(" MD5-Challenge (4)\n"); break;
		case 5: printf(" One-Time Password (5)\n"); break;
		case 6: printf(" Generic Token Card (6)\n"); break;
	}
}

static void decode_eap(const char *packet, unsigned len)
{
	int v;
	POPWORD(v);
	printf(" 802.1x: Length: %d\n",v);
	POPBYTE(v);
	printf(" 802.1x: EAP: ");
	switch(v) {
		case 1: 
			printf("Request (1)\n");
			decode_eap_request(packet,len);
			break;
		case 2: printf("Response (2)\n"); break;
		case 3: printf("Success (3)\n"); break;
		case 4: printf("Failure (4)\n"); break;
		default: printf("#0x%02x\n",v); break;
	}
	
}

static void decode_eapol_start(const char *packet, unsigned len)
{
	int v;
	POPWORD(v);
	printf(" 802.1x: Length: %d\n",v);
}

static void decode_eapol_logoff(const char *packet, unsigned len)
{
	int v;
	POPWORD(v);
	printf(" 802.1x: Length: %d\n",v);
}

struct key_descriptor {
		uint8_t descriptor_type;
		uint16_t key_length;
		uint64_t replay_counter;
		uint8_t key_iv[27-12];
		uint8_t kevy_index;
		uint8_t key_signature[44-29];
};

static void decode_eapol_key(const char *packet, unsigned len)
{
	int v;
	POPWORD(v);
	printf(" 802.1x: Length: %d\n",v);
}

static void decode_eapol_encapsulated_asf_alert(const char *packet, unsigned len)
{
	int v;
	POPWORD(v);
	printf(" 802.1x: Length: %d\n",v);
}

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	int v;
	int type;
	POPBYTE(v);
	printf(" 802.1x: Version: %u\n",v);
	POPBYTE(type);
	printf(" 802.1x: Type: ");
	switch (type) {
		case 0: 
			printf(" EAP-Packet (0)\n"); 
			decode_eap(packet,len);
			break;
		case 1: printf(" EAPOL-Start (1)\n"); 
			decode_eapol_start(packet,len);
			break;
		case 2: 
			printf(" EAPOL-Logoff (2)\n"); 
			decode_eapol_logoff(packet,len);
			break;
		case 3: 
			printf(" EAPOL-Key (3)\n");
			decode_eapol_key(packet,len);
			break;
		case 4: 
			printf(" EAPOL-Encasulated-ASF-Alert (4)\n");
			decode_eapol_encapsulated_asf_alert(packet,len);
			break;
		default:
			printf(" Unknown #0x%02x\n",v);
			decode_next(packet,len,"eapol",type);
			break;
	}

	return;
}
