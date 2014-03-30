/**
 * toeplitz hashing - see microsoft rss code
 */
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

void toeplitz_hash_expand_key(toeplitz_conf_t *conf);
inline uint32_t toeplitz_hash(const toeplitz_conf_t *tc, const uint8_t *data, size_t offset, size_t n, uint32_t result);
inline uint32_t toeplitz_first_hash(const toeplitz_conf_t *tc, const uint8_t *data, size_t n);
inline void toeplitz_init_config(toeplitz_conf_t *conf, bool bidirectional);
inline uint64_t toeplitz_hash_packet(const libtrace_packet_t * pkt, const toeplitz_conf_t *cnf);
void toeplitz_create_bikey(uint8_t *key);
void toeplitz_create_unikey(uint8_t *key);


/* IPv4 Only (Input[8] = @12-15, @16-19) src dst */

// Using char any way in the hope this structure will auto allign
#pragma pack(push)  /* push current alignment to stack */
#pragma pack(1)     /* set alignment to 1 byte boundary */
typedef struct ipv4_toeplitz_only {
	uint8_t src[4];
	uint8_t dest[4];
} toeplitz_ipv4_only_t;
#pragma pack(pop)   /* restore original alignment from stack */


inline toeplitz_ipv4_only_t make_toeplitz_ipv4(uint8_t *src_ip4, uint8_t *dest_ip4);

#endif
