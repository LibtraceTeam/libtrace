/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Scott Raynel
 *          Perry Lorier
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */

#include "libtrace_int.h" 
#include "libtrace.h"

/* The file contains all the functions necessary to access various measurement
 * values that are specific to wireless MACs ( RadioTap in particular ).
 *
 * Credit for all this code goes to Scott Raynel.
 */

/* Used for Radiotap fields which must be naturally aligned */
#define ALIGN_NATURAL_64(_p,_s) \
	while ( (_p - _s) % sizeof(uint64_t)) _p++
#define ALIGN_NATURAL_32(_p,_s) \
	while ( (_p - _s) % sizeof(uint32_t)) _p++
#define ALIGN_NATURAL_16(_p,_s) \
	while ( (_p - _s) % sizeof(uint16_t)) _p++

/** Gets a field from a Radiotap header.
 * @param link the radiotap header
 * @param field the radiotap field we want to access
 * @return a void pointer to the field. It is up to the caller to cast to the
 * appropriate type.
 * @note Radiotap fields are always little-endian
 */
static void *trace_get_radiotap_field(void *link, libtrace_radiotap_field_t field)
{
	struct libtrace_radiotap_t *rtap = (struct libtrace_radiotap_t *)link;
	uint8_t *p;
	uint8_t *s;

	/* Check if the field exists in the radiotap header before proceeding
	*/
	if ((bswap_le_to_host32(rtap->it_present) & (1 << field)) == 0) return NULL;

	/* Skip over any extended bitmasks */
	p = (uint8_t *) &(rtap->it_present);

	while ( bswap_le_to_host32(*((uint32_t*)p)) & (1U << TRACE_RADIOTAP_EXT) ) {
		p += sizeof (uint32_t);
	}

	/* Point p at the first field of radiotap data and remember it for later
	 * when we're doing field alignment 
	 */
	p += sizeof(uint32_t);
	s = p;

	if (field == TRACE_RADIOTAP_TSFT) 
		/* Always aligned */
		return (void*)p;
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_TSFT))
		p += sizeof (uint64_t);

	if (field == TRACE_RADIOTAP_FLAGS)
		/* Always aligned */
		return (void*)p;
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_FLAGS))
		p += sizeof (uint8_t);

	if (field == TRACE_RADIOTAP_RATE)
		/* Always aligned */
		return (void*)p;
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_RATE))
		p+= sizeof (uint8_t);

	if (field == TRACE_RADIOTAP_CHANNEL)
	{
		ALIGN_NATURAL_16(p,s);
		return (void *)p;
	}
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_CHANNEL))
		p+= sizeof (uint32_t);

	if (field == TRACE_RADIOTAP_FHSS)
	{
		ALIGN_NATURAL_16(p,s);
		return (void *)p;
	}
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_FHSS))
		p+= sizeof (uint16_t);

	if (field == TRACE_RADIOTAP_DBM_ANTSIGNAL)
		return (void *)p;
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_DBM_ANTSIGNAL))
		p+= sizeof (uint8_t);

	if (field == TRACE_RADIOTAP_DBM_ANTNOISE)
		return (void *)p;
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_DBM_ANTNOISE))
		p+= sizeof (uint8_t);

	if (field == TRACE_RADIOTAP_LOCK_QUALITY)
	{
		ALIGN_NATURAL_16(p,s);
		return (void *)p;
	}
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_LOCK_QUALITY))
		p+= sizeof (uint16_t);

	if (field == TRACE_RADIOTAP_TX_ATTENUATION)
	{
		ALIGN_NATURAL_16(p,s);
		return (void *)p;
	}
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_TX_ATTENUATION))
		p+= sizeof (uint16_t);

	if (field == TRACE_RADIOTAP_DB_TX_ATTENUATION)
	{
		ALIGN_NATURAL_16(p,s);
		return (void *)p;
	}
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_DB_TX_ATTENUATION))
		p+= sizeof (uint16_t);

	if (field == TRACE_RADIOTAP_DBM_TX_POWER)
		return (void *)p;
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_DBM_TX_POWER))
		p+= sizeof (uint8_t);

	if (field == TRACE_RADIOTAP_ANTENNA)
		return (void *)p;
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_ANTENNA))
		p+= sizeof (uint8_t);

	if (field == TRACE_RADIOTAP_DB_ANTSIGNAL)
		return (void *)p;
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_DB_ANTSIGNAL))
		p+= sizeof (uint8_t);

	if (field == TRACE_RADIOTAP_DB_ANTNOISE)
		return (void *) p;
	/*
	if (bswap_le_to_host32(rtap->it_present) & (1 << TRACE_RADIOTAP_DB_ANTNOISE))
		p+= sizeof (uint8_t);
	*/

	/* Unknown field */
	return NULL;
} 

DLLEXPORT bool trace_get_wireless_tsft(void *link, 
		libtrace_linktype_t linktype, uint64_t *tsft)
{
	uint64_t *p;
	void *l;
	uint16_t type;
	if (link == NULL || tsft == NULL) return false;

	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			if( (p = (uint64_t *) trace_get_radiotap_field(link, 
							TRACE_RADIOTAP_TSFT))) {
				*tsft = bswap_le_to_host64(*p);
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL );
			return trace_get_wireless_tsft(l, arphrd_type_to_libtrace(type), tsft);

		case TRACE_TYPE_80211_PRISM:
			return false;
		default:
			return false;
	}
	return false;
}

/* 
 * This function isn't portable across drivers, so has been left static
 * for now. Maybe it will be included in the API later if it becomes useful
 * and we come up with a suitable abstraction.
 * This function isn't marked static as the various format modules need to
 * access it for get_wire_length(). It's not meant to be exported though.
 */
bool trace_get_wireless_flags(void *link, 
		libtrace_linktype_t linktype, uint8_t *flags)
{
	uint8_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || flags == NULL) return false;

	switch(linktype) {
		case TRACE_TYPE_80211_RADIO:
			if (( p = (uint8_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_FLAGS))) {
				*flags = *p;
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_flags(l, arphrd_type_to_libtrace(type), flags);
		default:
			return false;
	}
	return false;
}

DLLEXPORT bool trace_get_wireless_rate(void *link, 
		libtrace_linktype_t linktype, uint8_t *rate)
{
	uint8_t * p;
	void *l;
	uint16_t type;

	if (link == NULL || rate == NULL) return false ;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			if ( (p = (uint8_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_RATE))) {
				*rate = *p;
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_rate(l, arphrd_type_to_libtrace(type), rate);
		default:
			return false;
	}
	return false;
}

DLLEXPORT bool trace_get_wireless_freq(void *link, 
		libtrace_linktype_t linktype, uint16_t *freq)
{
	uint16_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || freq == NULL) return false;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			/* NB: The channel field is actually two 16 bit fields. 
			 * The chan_freq field is the first of those two, so we
			 * just cast it to a uint16_t.
			 */
			if (( p = (uint16_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_CHANNEL))) {
				*freq = bswap_le_to_host16(*p);
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_freq(l, arphrd_type_to_libtrace(type), freq);
		default:
			return false;
	}
	return false;
}

#if 0

/* 
 * This function isn't portable across drivers, so has been left static
 * for now. Maybe it will be included in the API later if it becomes useful
 * and we come up with a suitable abstraction.
 */
static
bool trace_get_wireless_channel_flags(void *link,
		libtrace_linktype_t linktype, uint16_t *flags)
{
	uint16_t *p;
	void *l;
	uint16_t type;
	if (link == NULL || flags == NULL) return false;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			/* NB: The channel field is actually two 16 bit fields.
			 * The chan_flags field is the second of the two, so we need
			 * to take the pointer returned by getting the channel field
			 * and increment it.
			 */
			if ((p = (uint16_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_CHANNEL))) {
				*flags = bswap_le_to_host16(*(++p));
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_channel_flags(l, arphrd_type_to_libtrace(type), flags);
		default:
			return false;
	}
	return false;
}

/* Not sure that this function is useful for now - who uses FHSS?
 * This might get exported in the future if it becomes useful
 */
static
bool trace_get_wireless_fhss_hopset(void *link,
		libtrace_linktype_t linktype, uint8_t *hopset)
{
	uint8_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || hopset == NULL) return false;
	switch(linktype) {
		case TRACE_TYPE_80211_RADIO:
			/* NB: As above with the channel field, the fhss field is
			 * similar.
			 */
			if( (p = (uint8_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_FHSS))) {
				*hopset = *p;
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_fhss_hopset(l, arphrd_type_to_libtrace(type), hopset);
		default:
			return false;
	}
	return false;
}

/* Not sure that this function is useful for now - who uses FHSS?
 * This might get exported in the future if it becomes useful
 */
static
bool trace_get_wireless_fhss_hoppattern(void *link,
		libtrace_linktype_t linktype, uint8_t *hoppattern)
{
	uint8_t *p;
	void *l;
	uint16_t type;
	if (link == NULL || hoppattern == NULL) return false;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			if((p = (uint8_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_FHSS))) {
				*hoppattern = *(++p);
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_fhss_hoppattern(l, arphrd_type_to_libtrace(type), hoppattern);
		default:
			return false;
	}
	return false;
}

#endif

DLLEXPORT bool trace_get_wireless_signal_strength_dbm(void *link,
		libtrace_linktype_t linktype, int8_t *strength)
{
	int8_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || strength == NULL) return false;
	switch(linktype) {
		case TRACE_TYPE_80211_RADIO:
			if ((p =  (int8_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_DBM_ANTSIGNAL))) {
				*strength = *p;
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_signal_strength_dbm(l, arphrd_type_to_libtrace(type), strength);
		default:
			return false;
	}
	return false;
}

DLLEXPORT bool trace_get_wireless_noise_strength_dbm(void *link,
		libtrace_linktype_t linktype, int8_t *strength)
{
	uint8_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || strength == NULL) return false;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			if (( p = (uint8_t *) trace_get_radiotap_field(link,
					TRACE_RADIOTAP_DBM_ANTNOISE))) {
				*strength = *p;
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_noise_strength_dbm(l, arphrd_type_to_libtrace(type), strength);
		default:
			return false;
	}
	return false;
}

DLLEXPORT bool trace_get_wireless_signal_strength_db(void *link,
		libtrace_linktype_t linktype, uint8_t *strength)
{
	uint8_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || strength == NULL) return false;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			if ((p =  (uint8_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_DB_ANTSIGNAL))) {
				*strength = *p;
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_signal_strength_db(l, arphrd_type_to_libtrace(type), strength);
		default:
			return false;
	}
	return false ;
}

DLLEXPORT bool trace_get_wireless_noise_strength_db(void *link,
		libtrace_linktype_t linktype, uint8_t *strength)
{
	uint8_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || strength == NULL) return false;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			if ((p = (uint8_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_DB_ANTNOISE))) {
				*strength = *p;
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_noise_strength_db(l, arphrd_type_to_libtrace(type), strength);
		default:
			return false;
	}
	return false;
}

#if 0
/* Not sure if this function is useful. As the radiotap documentation says,
 * there's no set metric for defining the quality of the Barker Code Lock.
 * Maybe it will be exported later if it becomes useful.
 */
static
bool trace_get_wireless_lock_quality(void *link,
		libtrace_linktype_t linktype, uint16_t *quality)
{
	uint16_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || quality == NULL) return false;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			if((p = (uint16_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_LOCK_QUALITY))) {
				*quality = bswap_le_to_host16(*p);
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_lock_quality(l, arphrd_type_to_libtrace(type), quality);
		default:
			return false;
	}
	return false;
}

#endif

DLLEXPORT bool trace_get_wireless_tx_attenuation(void *link,
		libtrace_linktype_t linktype, uint16_t *attenuation)
{
	uint16_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || attenuation == 0) return false;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			if ((p = (uint16_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_TX_ATTENUATION))) {
				*attenuation = bswap_le_to_host16(*p);
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_tx_attenuation(l, arphrd_type_to_libtrace(type), attenuation);
		default:
			return false;
	}
	return false;
}

DLLEXPORT bool trace_get_wireless_tx_attenuation_db(void *link,
		libtrace_linktype_t linktype, uint16_t *attenuation)
{
	uint16_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || attenuation == NULL) return false;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			if ((p = (uint16_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_DB_TX_ATTENUATION))) {
				*attenuation = bswap_le_to_host16(*p);
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_tx_attenuation_db(l, arphrd_type_to_libtrace(type), attenuation);
		default:
			return false;
	}
	return false;
}

DLLEXPORT bool trace_get_wireless_tx_power_dbm(void *link,
		libtrace_linktype_t linktype, int8_t *txpower)
{
	int8_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || txpower == NULL) return false;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			if ((p=(int8_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_DBM_TX_POWER))) {
				*txpower = *p;
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_tx_power_dbm(l, arphrd_type_to_libtrace(type), txpower);
		default:
			return false;
	}
	return false;
}


DLLEXPORT bool trace_get_wireless_antenna(void *link,
		libtrace_linktype_t linktype, uint8_t *antenna)
{
	uint8_t *p;
	void *l;
	uint16_t type;

	if (link == NULL || antenna == NULL) return false;
	switch (linktype) {
		case TRACE_TYPE_80211_RADIO:
			if ((p = (uint8_t *) trace_get_radiotap_field(link,
							TRACE_RADIOTAP_ANTENNA))) {
				*antenna = *p;
				return true;
			} else break;
		case TRACE_TYPE_LINUX_SLL:
			l = trace_get_payload_from_linux_sll(link, &type, NULL, NULL);
			return trace_get_wireless_antenna(l, arphrd_type_to_libtrace(type), antenna);
		default:
			return false;
	}
	return false;
}

