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
#include "libtrace_int.h" /* bswaps */

#define ALIGN_NATURAL_32(_p,_s,_c) \
	while ( (_p - _s) % sizeof(uint32_t)) {_p++; _c++;}
#define ALIGN_NATURAL_16(_p,_s,_c) \
	while ( (_p - _s) % sizeof(uint16_t)) {_p++; _c++;} 

void decode(int link_type,char *packet,int len)
{
	uint32_t *ptr; 
	uint8_t *p; /* Our current field "cursor" */
	uint8_t *s; /* Start of data fields, for alignment */
	struct libtrace_radiotap_t *rtap;
	uint16_t rtap_len;
	uint16_t rtap_real_len; /* to make sure length in header matches fields present */
	rtap = (libtrace_radiotap_t *)packet;
	
	printf(" Radiotap 802.11 Monitoring:");

	if (len < 8) {
		printf(" [|Truncated (%u bytes)]\n", len);
		return;
	}
	
	rtap_real_len = sizeof(struct libtrace_radiotap_t);
	rtap_len = bswap_le_to_host16(rtap->it_len);

	printf(" version: %u, length: %u, fields: %#08x\n", rtap->it_version,
			rtap_len, rtap->it_present);
	
	/* Check for extended bitmasks */
	ptr = (uint32_t *) &(rtap->it_present);
	
	if ( (*ptr) & (1 << TRACE_RADIOTAP_EXT) ) 
		printf("  extended fields:");
	
	while( (*ptr) & (1 << TRACE_RADIOTAP_EXT) ) {
		rtap_real_len += sizeof (uint32_t);
		printf(" %#08x", *(++ptr));	
	}


	/* make p point to the first data field */
	s = p = (uint8_t *) ++ptr;

	if (rtap->it_present & (1 << TRACE_RADIOTAP_TSFT)) {
		printf("  TSFT: %llu microseconds\n", bswap_le_to_host64(*((uint64_t *)p)));
		p += sizeof (uint64_t);
		rtap_real_len += sizeof (uint64_t);
	}

	if (rtap->it_present & (1 << TRACE_RADIOTAP_FLAGS)) {
		printf("  Flags: %#04x\n", *p);
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	
	if (rtap->it_present & (1 << TRACE_RADIOTAP_RATE)) {
		printf("  Rate: %u kbps\n", (*p) * 500);
		p +=  sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}
	
	if (rtap->it_present & (1 << TRACE_RADIOTAP_CHANNEL)) {
		ALIGN_NATURAL_16(p,s,rtap_real_len);
		printf("  Freq: %u MHz, ChanFlags: %#06x\n", bswap_le_to_host16(*((uint16_t *)p)), 
				*(((uint16_t *)p) + 1));
		p += sizeof (uint32_t);
		rtap_real_len += sizeof(uint32_t);
	}
											
	if (rtap->it_present & (1 << TRACE_RADIOTAP_FHSS)) {
		ALIGN_NATURAL_16(p,s, rtap_real_len);
		printf("  FHSS: HopSet: %u , HopPattern: %u\n", *p, *(p+1)); 
		p += sizeof (uint16_t);
		rtap_real_len += sizeof(uint16_t);
	}


	if (rtap->it_present & (1 << TRACE_RADIOTAP_DBM_ANTSIGNAL)) {
		printf("  Signal: %i dBm\n", (int8_t) *p) ;
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}


	if (rtap->it_present & (1 << TRACE_RADIOTAP_DBM_ANTNOISE)) {
		printf("  Noise: %i dBm\n", (int8_t) *p); 
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}


	if (rtap->it_present & (1 << TRACE_RADIOTAP_LOCK_QUALITY)) {
		ALIGN_NATURAL_16(p,s, rtap_real_len);
		printf("  Barker Code Lock Quality: %u\n", bswap_le_to_host16(*((uint16_t *)p))); 
		p += sizeof (uint16_t);
		rtap_real_len += sizeof(uint16_t);
	}


	if (rtap->it_present & (1 << TRACE_RADIOTAP_TX_ATTENUATION)) {
		ALIGN_NATURAL_16(p,s, rtap_real_len);
		printf("  TX Attenuation: %u\n", bswap_le_to_host16(*((uint16_t *)p))); 
		p += sizeof (uint16_t);
		rtap_real_len += sizeof(uint16_t);
	}

	if (rtap->it_present & (1 << TRACE_RADIOTAP_DB_TX_ATTENUATION)) {
		ALIGN_NATURAL_16(p,s,rtap_real_len);
		printf("  TX Attenuation: %u dB\n", bswap_le_to_host16(*((uint16_t *)p))); 
		p += sizeof (uint16_t);
		rtap_real_len += sizeof(uint16_t);
	}

	if (rtap->it_present & (1 << TRACE_RADIOTAP_DBM_TX_POWER)) {
		printf("  TX Power: %i dBm\n", *p); 
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	if (rtap->it_present & (1 << TRACE_RADIOTAP_ANTENNA)) {
		printf("  Antenna: %u\n", *p); 
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	if (rtap->it_present & (1 << TRACE_RADIOTAP_DB_ANTSIGNAL)) {
		printf("  Signal: %u dB\n", *p); 
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	if (rtap->it_present & (1 << TRACE_RADIOTAP_DB_ANTNOISE)) {
		printf("  Noise: %u dB\n", *p); 
		p += sizeof (uint8_t);
		rtap_real_len += sizeof(uint8_t);
	}

	if (rtap->it_present & (1 << TRACE_RADIOTAP_FCS)) {
		ALIGN_NATURAL_32(p,s,rtap_real_len);
		printf("  Frame Check Sequence: %#10x\n", bswap_le_to_host32(*((uint32_t *)p))); 
		p += sizeof (uint32_t);
		rtap_real_len += sizeof(uint32_t);
	}

	if (rtap_real_len != rtap_len) 
		printf("  WARNING: Header length does not match fields present (%u)\n", rtap_real_len);

	if (len > rtap_len) 
		decode_next(packet + rtap_len, len - rtap_len, "link", TRACE_TYPE_80211);
		
	return;

}
