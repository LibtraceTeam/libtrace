/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007-2013 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock 
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
#include "checksum.h"

uint32_t add_checksum(void *buffer, uint16_t length) {
        uint32_t sum = 0;
        uint16_t * buff = (uint16_t *) buffer;
        uint16_t count = length;
	uint16_t val;

        while(count > 1 ) {
                val = *buff;
		sum += val;
		buff ++;
                count = count -2;
        }

        if(count > 0) {
		sum += *(uint8_t *)buff;
        }

	return sum;
}

uint16_t finish_checksum(uint32_t sum) {
        while (sum>>16) {
                sum = (sum & 0xffff) + (sum >> 16);
	}
        return (uint16_t)~sum;
}

uint16_t checksum_buffer(void *buffer, uint16_t length) {

	uint32_t sum = add_checksum(buffer, length);
	return finish_checksum(sum);

}

uint32_t ipv4_pseudo_checksum(libtrace_ip_t *ip) {

	uint32_t sum = 0;
	uint16_t temp = 0;

	sum += add_checksum(&ip->ip_src.s_addr,sizeof(uint32_t));
	sum += add_checksum(&ip->ip_dst.s_addr,sizeof(uint32_t));

	temp = htons(ip->ip_p);
	sum += add_checksum(&temp, sizeof(uint16_t));

	temp = htons(ntohs(ip->ip_len) - (ip->ip_hl * 4));
	sum += add_checksum(&temp, sizeof(uint16_t));

	return sum;	

}

uint32_t ipv6_pseudo_checksum(libtrace_ip6_t *ip) {

	uint32_t sum = 0;
	uint16_t temp = 0;

	sum += add_checksum(&ip->ip_src.s6_addr,sizeof(struct in6_addr));
	sum += add_checksum(&ip->ip_dst.s6_addr,sizeof(struct in6_addr));
	
	temp = ip->plen;
	sum += add_checksum(&temp, sizeof(uint16_t));


	temp = htons(ip->nxt);
	sum += add_checksum(&temp, sizeof(uint16_t));


	return sum;	

}


