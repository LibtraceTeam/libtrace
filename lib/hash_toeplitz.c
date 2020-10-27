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
 * A implementation of Microsofts RSS standard for hashing.
 * See http://msdn.microsoft.com/en-us/library/windows/hardware/ff570726%28v=vs.85%29.aspx
 * and the Scalable Networking: Eliminating the Receive Processing Bottleneck—Introducing RSS
 * white paper.
 * 
 */
#include "hash_toeplitz.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
 
static inline uint8_t get_bit(uint8_t byte, size_t num) {
	return byte & (0x80>>num);
}

/**
 * Takes a key of length 40 bytes == (320bits)
 * and expands it into 320 32 bit ints
 * each shifted left by 1 byte more than the last
 */
void toeplitz_hash_expand_key(toeplitz_conf_t *conf) {
	size_t i = 0, j;
	// Don't destroy the existing key
	char *key_cpy = malloc(40);
	memcpy(key_cpy, conf->key, 40);
	
	do {
		conf->key_cache[i] = *((uint32_t *) key_cpy);
		
		for (j = 0; j < 39 ; ++j) {
			key_cpy[j] <<= 1;
			key_cpy[j] |= (0x80 & key_cpy[j+1])>>7;
		}
		key_cpy[39] <<= 1;
		++i;
	} while (i < 320);
	free(key_cpy);
}


/**
 * Creates a random unidirectional RSS key - a ip or ip+port combination in
 * the opposite directions will most likely get different hashes.
 * @param key An array of bytes to retrieve the RSS key
 * @param num The number of bytes in key
 */
void toeplitz_ncreate_unikey(uint8_t *key, size_t num) {
	size_t i;
	unsigned int seed = time(NULL);
	for (i = 0; i < num; i++) {
		key[i] = (uint8_t) rand_r(&seed);
	}
}

/**
 * Creates a random 40 byte unidirectional RSS key - a ip or ip+port combination
 * in the opposite directions will most likely get different hashes.
 * @param key must have 40 bytes of space to retrieve random the key
 */
void toeplitz_create_unikey(uint8_t *key) {
	toeplitz_ncreate_unikey(key, 40);
}

/**
 * Create a bidirectional RSS key, i.e. ip and ip+port configurations
 * in opposite directions will receive the same hash
 * @param key must have 40 bytes of space to retrieve random the key
 * @param num The number of bytes in the key, must be a multiple of 2
 */
void toeplitz_ncreate_bikey(uint8_t *key, size_t num) {
	unsigned int seed = time(NULL);
	size_t i;
	if (num % 2 != 0) {
		perror("Can not create a bidirectional key for an odd length key");
	}
	// Every thing is 16bit (port=16, ipv4=32, ipv6=128 
	// aligned so this will make the hash bidirectional
	uint16_t bi_key = (uint16_t) rand_r(&seed);
	uint16_t *bi_rep = (uint16_t *) key;
	for (i = 0; i < num/2; i++) {
		bi_rep[i] = bi_key;
	}
}

/**
 * Create a 40 byte bidirectional RSS key, i.e. ip and ip+port configurations
 * in opposite directions will receive the same hash
 * @param key An array of bytes to retrieve the RSS key
 */
void toeplitz_create_bikey(uint8_t *key) {
	toeplitz_ncreate_bikey(key, 40);
}

void toeplitz_init_config(toeplitz_conf_t *conf, bool bidirectional)
{
	if (bidirectional) {
		toeplitz_create_bikey(conf->key);
	} else {
		toeplitz_create_unikey(conf->key);
	}
	toeplitz_hash_expand_key(conf);
	conf->hash_ipv4 = 1;
	conf->hash_ipv6 = 1;
	conf->hash_tcp_ipv4 = 1;
	conf->x_hash_udp_ipv4 = 1;
	conf->hash_tcp_ipv6 = 1;
	conf->x_hash_udp_ipv6 = 1;
}

/**
 * n is bits
 */
uint32_t toeplitz_hash(const toeplitz_conf_t *tc, const uint8_t *data, size_t offset, size_t n, uint32_t result)
{
	size_t byte;
	size_t bit, i = 0;
	const uint32_t * key_array = tc->key_cache + offset*8;
	for (byte = 0; byte < n; ++byte) {
		for (bit = 0; bit < 8; ++bit,++i) {
			if (get_bit(data[byte], bit))
				result ^= key_array[i];
		}
	}
	return result;
}

uint32_t toeplitz_first_hash(const toeplitz_conf_t *tc, const uint8_t *data, size_t n)
{
	return toeplitz_hash(tc, data, 0, n, 0);
}

uint64_t toeplitz_hash_packet(const libtrace_packet_t * pkt, const toeplitz_conf_t *cnf) {
	uint8_t proto;
	uint16_t eth_type;
	uint32_t remaining;
	uint32_t res = 0; // shutup warning, logic was to complex for gcc to follow
	void *layer3 = trace_get_layer3(pkt, &eth_type, &remaining);
	void *transport = NULL;
	size_t offset = 0;
	bool accept_tcp = false, accept_udp = false;

	if (cnf->hash_ipv6_ex || cnf->hash_tcp_ipv6_ex || cnf->x_hash_udp_ipv6_ex)
	{
		perror("We don't support ipv6 ex hashing yet\n");
	}

	if (layer3) {
		switch (eth_type) {
			case TRACE_ETHERTYPE_IP:
				// The packet needs to include source and dest which
				// are at the very end of the header
				if ((cnf->hash_ipv4 || cnf->hash_tcp_ipv4 || cnf->x_hash_udp_ipv4)
						&& remaining >= sizeof(libtrace_ip_t)) {	
					libtrace_ip_t * ip = (libtrace_ip_t *)layer3;
					// Order here is src dst as required by RSS
					res = toeplitz_first_hash(cnf, (uint8_t *)&ip->ip_src, 8);
					offset = 8;
					accept_tcp = cnf->hash_tcp_ipv4;
					accept_udp = cnf->x_hash_udp_ipv4;
				}
				break;
			case TRACE_ETHERTYPE_IPV6:
				// TODO IPv6 EX
				if ((cnf->hash_ipv6 || cnf->hash_tcp_ipv6 || cnf->x_hash_udp_ipv6)
						&& remaining >= sizeof(libtrace_ip6_t)) {
					libtrace_ip6_t * ip6 = (libtrace_ip6_t *)layer3;
					// Order here is src dst as required by RSS
					res = toeplitz_first_hash(cnf, (uint8_t *)&ip6->ip_src, 32);
					offset = 32;
					accept_tcp = cnf->hash_tcp_ipv6;
					accept_udp = cnf->x_hash_udp_ipv6;
				}
				break;
			default:
				return 0;
		}
	}

	transport = trace_get_transport(pkt, &proto, &remaining);

	if (transport) {
		switch(proto) {
			// Hash src & dst port
			case TRACE_IPPROTO_UDP:
				if (accept_udp && remaining >= 4) {
					res = toeplitz_hash(cnf, (uint8_t *)transport, offset, 4, res);
				}
				break;
			case TRACE_IPPROTO_TCP:
				if (accept_tcp && remaining >= 4) {
					res = toeplitz_hash(cnf, (uint8_t *)transport, offset, 4, res);
				}
				break;
		}
	}

	return res;
}
