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

/**
 * toeplitz hashing - see microsoft rss code
 */
#include "config.h"
#include <stdint.h>
#include <stddef.h>
#include <libtrace.h>

#ifndef HASH_TOEPLITZ_H
#define HASH_TOEPLITZ_H

/**
 * The default expected to be used.
 */ 
typedef struct toeplitz_conf {
	unsigned int hash_ipv4 : 1;
	unsigned int hash_tcp_ipv4 : 1;
	unsigned int hash_ipv6 : 1;
	unsigned int hash_tcp_ipv6 : 1;
	unsigned int hash_ipv6_ex : 1;
	unsigned int hash_tcp_ipv6_ex : 1;
	/* These UDP ones are Intel extensions */
	unsigned int x_hash_udp_ipv4 : 1;
	unsigned int x_hash_udp_ipv6 : 1;
	unsigned int x_hash_udp_ipv6_ex : 1;
	uint8_t key[40];
	uint32_t key_cache[320];
} toeplitz_conf_t;

DLLEXPORT void toeplitz_hash_expand_key(toeplitz_conf_t *conf);
DLLEXPORT uint32_t toeplitz_hash(const toeplitz_conf_t *tc, const uint8_t *data, size_t offset, size_t n, uint32_t result);
DLLEXPORT uint32_t toeplitz_first_hash(const toeplitz_conf_t *tc, const uint8_t *data, size_t n);
DLLEXPORT void toeplitz_init_config(toeplitz_conf_t *conf, bool bidirectional);
DLLEXPORT uint64_t toeplitz_hash_packet(const libtrace_packet_t * pkt, const toeplitz_conf_t *cnf);
DLLEXPORT void toeplitz_ncreate_bikey(uint8_t *key, size_t num);
DLLEXPORT void toeplitz_create_bikey(uint8_t *key);
DLLEXPORT void toeplitz_ncreate_unikey(uint8_t *key, size_t num);
DLLEXPORT void toeplitz_create_unikey(uint8_t *key);


/* IPv4 Only (Input[8] = @12-15, @16-19) src dst */

// Using char any way in the hope this structure will auto allign
#pragma pack(push)  /* push current alignment to stack */
#pragma pack(1)     /* set alignment to 1 byte boundary */
typedef struct ipv4_toeplitz_only {
	uint8_t src[4];
	uint8_t dest[4];
} toeplitz_ipv4_only_t;
#pragma pack(pop)   /* restore original alignment from stack */

#endif
