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
/*
 * libpacketdump decoder for Radiotap 
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libtrace.h"
#include "libpacketdump.h"
#include "lt_bswap.h"

#define ALIGN_NATURAL_64(_p,_s,_c) \
	while ( (_p - _s) % sizeof(uint64_t)) {_p++; _c++;}
#define ALIGN_NATURAL_32(_p,_s,_c) \
	while ( (_p - _s) % sizeof(uint32_t)) {_p++; _c++;}
#define ALIGN_NATURAL_16(_p,_s,_c) \
	while ( (_p - _s) % sizeof(uint16_t)) {_p++; _c++;} 

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	uint32_t *ptr; 
	uint8_t *p; /* Our current field "cursor" */
	uint8_t *s; /* Start of data fields, for alignment */
	struct libtrace_radiotap_t *rtap;
	uint16_t rtap_len;
	uint32_t rtap_pres;
	uint16_t rtap_real_len; /* to make sure length in header matches fields present */
	rtap = (libtrace_radiotap_t *)packet;
	
	printf(" Radiotap:");

	if (len < 8) {
		printf(" [|Truncated (%u bytes)]\n", len);
		return;
	}
	
	rtap_real_len = sizeof(struct libtrace_radiotap_t);
	rtap_len = bswap_le_to_host16(rtap->it_len);
	rtap_pres = bswap_le_to_host32(rtap->it_present);

	printf(" version: %u, length: %u, fields: %#08x\n", rtap->it_version,
			rtap_len, rtap_pres);
	
	/* Check for extended bitmasks */
	ptr = (uint32_t *) (char *)(&(rtap->it_present));
	
	if ( (rtap_pres) & (1 << TRACE_RADIOTAP_EXT) ) 
		printf("  extended fields:");
	
	while( (bswap_le_to_host32(*ptr)) & (1 << TRACE_RADIOTAP_EXT) ) {
		rtap_real_len += sizeof (uint32_t);
		ptr++;
		printf(" %#08x", bswap_le_to_host32(*ptr));	
	}

        if ( (rtap_pres) & (1 << TRACE_RADIOTAP_EXT) )
                printf("\n");

	/* make p point to the first data field */
	s = (uint8_t *) rtap;
        p = (uint8_t *) ++ptr;

	if (rtap_pres & (1 << TRACE_RADIOTAP_TSFT)) {
		ALIGN_NATURAL_64(p,s,rtap_real_len);
		printf(" Radiotap: TSFT = %" PRIu64 " microseconds\n", bswap_le_to_host64(*((uint64_t *)p)));
		p += sizeof (uint64_t);
		rtap_real_len += sizeof (uint64_t);
	}

	if (rtap_pres & (1 << TRACE_RADIOTAP_FLAGS)) {
		printf(" Radiotap: Flags = 0x%02x\n", *p);
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	
	if (rtap_pres & (1 << TRACE_RADIOTAP_RATE)) {
		printf(" Radiotap: Rate = %u kbps\n", (*p) * 500);
		p +=  sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}
	
	if (rtap_pres & (1 << TRACE_RADIOTAP_CHANNEL)) {
		ALIGN_NATURAL_16(p,s,rtap_real_len);
		printf(" Radiotap: Freq = %u MHz, ChanFlags: 0x%04x\n", bswap_le_to_host16(*((uint16_t *)p)), 
				*(((uint16_t *)p) + 1));
		p += sizeof (uint32_t);
		rtap_real_len += sizeof(uint32_t);
	}
											
	if (rtap_pres & (1 << TRACE_RADIOTAP_FHSS)) {
		ALIGN_NATURAL_16(p,s, rtap_real_len);
		printf(" Radiotap: FHSS HopSet = %u , HopPattern: %u\n", *p, *(p+1)); 
		p += sizeof (uint16_t);
		rtap_real_len += sizeof(uint16_t);
	}


	if (rtap_pres & (1 << TRACE_RADIOTAP_DBM_ANTSIGNAL)) {
		printf(" Radiotap: Signal = %i dBm\n", (int8_t) *p) ;
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}


	if (rtap_pres & (1 << TRACE_RADIOTAP_DBM_ANTNOISE)) {
		printf(" Radiotap: Noise = %i dBm\n", (int8_t) *p); 
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}


	if (rtap_pres & (1 << TRACE_RADIOTAP_LOCK_QUALITY)) {
		ALIGN_NATURAL_16(p,s, rtap_real_len);
		printf(" Radiotap: Barker Code Lock Quality = %u\n", bswap_le_to_host16(*((uint16_t *)p))); 
		p += sizeof (uint16_t);
		rtap_real_len += sizeof(uint16_t);
	}


	if (rtap_pres & (1 << TRACE_RADIOTAP_TX_ATTENUATION)) {
		ALIGN_NATURAL_16(p,s, rtap_real_len);
		printf(" Radiotap: TX Attenuation = %u\n", bswap_le_to_host16(*((uint16_t *)p))); 
		p += sizeof (uint16_t);
		rtap_real_len += sizeof(uint16_t);
	}

	if (rtap_pres & (1 << TRACE_RADIOTAP_DB_TX_ATTENUATION)) {
		ALIGN_NATURAL_16(p,s,rtap_real_len);
		printf(" Radiotap: TX Attenuation = %u dB\n", bswap_le_to_host16(*((uint16_t *)p))); 
		p += sizeof (uint16_t);
		rtap_real_len += sizeof(uint16_t);
	}

	if (rtap_pres & (1 << TRACE_RADIOTAP_DBM_TX_POWER)) {
		printf(" Radiotap: TX Power = %i dBm\n", *p); 
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	if (rtap_pres & (1 << TRACE_RADIOTAP_ANTENNA)) {
		printf(" Radiotap: Antenna = %u\n", *p); 
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	if (rtap_pres & (1 << TRACE_RADIOTAP_DB_ANTSIGNAL)) {
		printf(" Radiotap: Signal = %u dB\n", *p); 
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	if (rtap_pres & (1 << TRACE_RADIOTAP_DB_ANTNOISE)) {
		printf(" Radiotap: Noise = %u dB\n", *p); 
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	if (rtap_pres & (1 << TRACE_RADIOTAP_RX_FLAGS)) {
		ALIGN_NATURAL_16(p,s,rtap_real_len);
		printf(" Radiotap: RX Flags = 0x%04x\n", *((uint16_t *)p));
		p += sizeof (uint16_t);
		rtap_real_len += sizeof(uint16_t);
	}

	if (rtap_pres & (1 << TRACE_RADIOTAP_TX_FLAGS)) {
		ALIGN_NATURAL_16(p,s,rtap_real_len);
		printf(" Radiotap: TX Flags = 0x%04x\n", *((uint16_t *)p));
		p += sizeof (uint16_t);
		rtap_real_len += sizeof(uint16_t);
	}

	if (rtap_pres & (1 << TRACE_RADIOTAP_RTS_RETRIES)) {
		printf(" Radiotap: RTS Retries = %u\n", *p);
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	if (rtap_pres & (1 << TRACE_RADIOTAP_DATA_RETRIES)) {
		printf(" Radiotap: Data Retries = %u\n", *p);
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	if (rtap_real_len != rtap_len) 
		printf(" Radiotap: WARNING: Header contains un-decoded fields.\n");

	if (len > rtap_len) 
		decode_next(packet + rtap_len, len - rtap_len, "link", TRACE_TYPE_80211);
		
	return;

}
