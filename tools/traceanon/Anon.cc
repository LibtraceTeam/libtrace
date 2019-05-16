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


#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include "Anon.h"


static uint32_t masks[33] = {
                0x00000000, 0x80000000, 0xC0000000, 0xe0000000, 0xf0000000,
                0xf8000000, 0xfC000000, 0xfe000000, 0xff000000, 0xff800000,
                0xffC00000, 0xffe00000, 0xfff00000, 0xfff80000, 0xfffC0000,
                0xfffe0000, 0xffff0000, 0xffff8000, 0xffffC000, 0xffffe000,
                0xfffff000, 0xfffff800, 0xfffffC00, 0xfffffe00, 0xffffff00,
                0xffffff80, 0xffffffC0, 0xffffffe0, 0xfffffff0, 0xfffffff8,
                0xfffffffC, 0xfffffffe, 0xffffffff,
};


Anonymiser::Anonymiser (uint8_t *salt) {
#ifdef HAVE_LIBCRYPTO
    mdctx = EVP_MD_CTX_create();
    memcpy(this->salt,salt,SALT_LENGTH);
#endif
    /* empty constructor */
}

Anonymiser::~Anonymiser(){
#ifdef HAVE_LIBCRYPTO
    EVP_MD_CTX_destroy(mdctx);
    EVP_cleanup();
#endif
}

static inline void buffer_to_digits(uint8_t *buffer, uint32_t len) {

    uint32_t i;
    for (i = 0; i < len; i++) {
        buffer[i] = '0' + (buffer[i] % 10);
    }
}

static inline void buffer_to_chars(uint8_t *buffer, uint32_t len) {
    uint32_t i;

    for (i = 0; i < len; i++) {
        uint8_t mod = buffer[i] % 62;

        if (mod < 26) {
            buffer[i] = 'a' + mod;
        } else if (mod < 52) {
            buffer[i] = 'A' + (mod - 26);
        } else {
            buffer[i] = '0' + (mod - 52);
        }
    }
}

uint8_t *Anonymiser::digest_message(uint8_t *src_ptr, uint32_t src_length, uint8_t anon_mode){

#ifdef HAVE_LIBCRYPTO

    // printf("DIGEST PERSPECTIVE");
    // for (int i = 0; i < src_length; i++){
    //     printf(" %02x", *(src_ptr+i));
    // }
    // for (int i = 0; i < SALT_LENGTH; i++){
    //     printf(" %02x", *(salt+i));
    // }printf("\n");

    

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, src_ptr, src_length);
    EVP_DigestUpdate(mdctx, salt, SALT_LENGTH);
    uint32_t len = 0;

    EVP_DigestFinal_ex(mdctx, buffer, &len);

    if (anon_mode == RADIUS_ANON_MODE_NUMERIC) {
        buffer_to_digits(buffer, 32);
    } else if (anon_mode == RADIUS_ANON_MODE_TEXT) {
        buffer_to_chars(buffer, 32);
    }

    return buffer;
#else
    return NULL;
#endif
}

PrefixSub::PrefixSub(const char *ipv4_key, const char *ipv6_key, uint8_t *salt) : Anonymiser(salt) {
    this->ipv4_mask = 0;
    this->ipv4_prefix = 0;

    memset(this->ipv6_mask, 0, 16);
    memset(this->ipv6_prefix, 0, 16);

    if (ipv4_key != NULL) {
        int a,b,c,d;
        int bits;

        if (sscanf(ipv4_key, "%i.%i.%i.%i/%i", &a, &b, &c, &d, &bits) != 5) {
            fprintf(stderr, "Invalid IPv4 prefix: %s\n", ipv4_key);

        } else {
            this->ipv4_prefix = (a<<24) + (b<<16) + (c<<8) + d;
            if (bits < 0 || bits > 32) {
                fprintf(stderr, "Invalid IPv4 prefix: %s\n", ipv4_key);
            } else {
                this->ipv4_mask = masks[bits];
            }
        }
    }

    /* TODO IPv6 */


}

PrefixSub::~PrefixSub() {

}

uint32_t PrefixSub::anonIPv4(uint32_t orig) {

    return (this->ipv4_prefix & this->ipv4_mask) | (orig & ~this->ipv4_mask);

}

void PrefixSub::anonIPv6(uint8_t *orig, uint8_t *result) {

    /* TODO */
    memcpy(result, orig, 16);

}

#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>

CryptoAnon::CryptoAnon(uint8_t *key, uint8_t len, uint8_t cachebits, uint8_t *salt) :
        Anonymiser(salt) {

    assert(len >= 32);
    memcpy(this->key, key, 16);
    memcpy(this->padding, key + 16, 16);

    this->cipher = EVP_aes_128_ecb();
    this->ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(this->ctx);

    EVP_EncryptInit_ex(this->ctx, this->cipher, NULL, this->key, NULL);

    this->cachebits = cachebits;

    this->ipv4_cache = new IPv4AnonCache();
    this->ipv6_cache = new IPv6AnonCache();
    this->recent_ipv4_cache[0][0] = 0;
    this->recent_ipv4_cache[0][1] = 0;
    this->recent_ipv4_cache[1][0] = 0;
    this->recent_ipv4_cache[0][1] = 0;

}


CryptoAnon::~CryptoAnon() {
    delete(this->ipv4_cache);
    EVP_CIPHER_CTX_cleanup(this->ctx);
    EVP_CIPHER_CTX_free(this->ctx);
}

static inline uint32_t generateFirstPad(uint8_t *pad) {
    uint32_t fp = 0;

    fp = (((uint32_t)pad[0]) << 24) + (((uint32_t)pad[1]) << 16) +
            (((uint32_t)pad[2]) << 8) + (uint32_t)pad[3];
    return fp;

}

uint32_t CryptoAnon::anonIPv4(uint32_t orig) {
    uint32_t cacheprefix =
            (orig >> (32 - this->cachebits)) << (32 - this->cachebits);
    uint32_t result = 0;

    if (this->recent_ipv4_cache[0][0] == orig)
        return this->recent_ipv4_cache[0][1];
    else if (this->recent_ipv4_cache[1][0] == orig) {
        uint32_t tmp = this->recent_ipv4_cache[1][1];
        this->recent_ipv4_cache[1][0] = this->recent_ipv4_cache[0][0];
        this->recent_ipv4_cache[1][1] = this->recent_ipv4_cache[0][1];
        this->recent_ipv4_cache[0][0] = orig;
        this->recent_ipv4_cache[0][1] = tmp;
        return tmp;

    }

    result = this->lookupv4Cache(cacheprefix);
    result = this->encrypt32Bits(orig, this->cachebits, 32, result);

    this->recent_ipv4_cache[1][0] = this->recent_ipv4_cache[0][0];
    this->recent_ipv4_cache[1][1] = this->recent_ipv4_cache[0][1];
    this->recent_ipv4_cache[0][0] = orig;
    this->recent_ipv4_cache[0][1] = result ^ orig;

    return this->recent_ipv4_cache[0][1];
}

static uint64_t swap64(uint64_t num) {
    uint32_t swapa, swapb;
    uint64_t res;

    swapa = (num & 0xffffffff);
    swapb = (num >> 32);
    swapa = ntohl(swapa);
    swapb = ntohl(swapb);
    res =(uint64_t)swapa << 32 | (swapb);
    return res;
}

void CryptoAnon::anonIPv6(uint8_t *orig, uint8_t *result) {

    uint64_t prefix, anonprefixmap;
    uint64_t suffix, anonsuffixmap;

    memcpy(&prefix, orig, 8);
    memcpy(&suffix, orig + 8, 8);

    prefix = swap64(prefix);
    suffix = swap64(suffix);

    anonprefixmap = this->lookupv6Cache(prefix);
    anonsuffixmap = this->lookupv6Cache(suffix);

    prefix = (swap64(anonprefixmap ^ prefix));
    suffix = (swap64(anonsuffixmap ^ suffix));

    memcpy(result, &prefix, sizeof(uint64_t));
    memcpy(result + sizeof(uint64_t), &suffix, sizeof(uint64_t));

}

uint32_t CryptoAnon::lookupv4Cache(uint32_t prefix) {

    IPv4AnonCache::iterator it = this->ipv4_cache->find(prefix);

    if (it == this->ipv4_cache->end()) {
        uint32_t prefmask = this->encrypt32Bits(prefix, 0, this->cachebits, 0);
        (*this->ipv4_cache)[prefix] = prefmask;
        return prefmask;
    }
    return it->second;

}

uint64_t CryptoAnon::lookupv6Cache(uint64_t prefix) {
    IPv6AnonCache::iterator it = this->ipv6_cache->find(prefix);

    if (it == this->ipv6_cache->end()) {
        uint64_t prefmask = this->encrypt64Bits(prefix);
        (*this->ipv6_cache)[prefix] = prefmask;
        return prefmask;
    }
    return it->second;
}

uint32_t CryptoAnon::encrypt32Bits(uint32_t orig, uint8_t start, uint8_t stop, 
        uint32_t res) {
    uint8_t rin_output[32];
    uint8_t rin_input[16];
    uint32_t first4pad;
    int outl = 32;

    memcpy(rin_input, this->padding, 16);
    first4pad = generateFirstPad(this->padding);

    for (int pos = start; pos < stop; pos ++) {
        uint32_t input;

        /* The MS bits are taken from the original address. The remaining
         * bits are taken from padding. first4pad is used to help ensure we
         * use the right bits from padding when pos < 32.
         */
        if (pos == 0) {
            input = first4pad;
        } else {
            input = ((orig >> (32 - pos)) << (32 - pos)) |
                    ((first4pad << pos) >> pos);
        }

        rin_input[0] = (uint8_t) (input >> 24);
        rin_input[1] = (uint8_t) ((input << 8) >> 24);
        rin_input[2] = (uint8_t) ((input << 16) >> 24);
        rin_input[3] = (uint8_t) ((input << 24) >> 24);

        /* Encryption: we're using AES as a pseudorandom function. For each
         * bit in the original address, we use the first bit of the resulting
         * encrypted output as part of an XOR mask */
        EVP_EncryptUpdate(this->ctx, (unsigned char *)rin_output, &outl, 
                (unsigned char *)rin_input, 16);

        /* Put the first bit of the output into the right slot of our mask */
        res |= (((uint32_t)rin_output[0]) >> 7) << (31 - pos);

    }
    return res;

}

uint64_t CryptoAnon::encrypt64Bits(uint64_t orig) {

    /* See encrypt32Bits for more explanation of how this works */
    uint8_t rin_output[32];
    uint8_t rin_input[16];
    uint64_t first8pad;
    int outl = 32;
    uint64_t result = 0;

    memcpy(rin_input, this->padding, 16);
    memcpy(&first8pad, this->padding, 8);

    for (int pos = 0; pos < 64; pos ++) {
        uint64_t input;

        if (pos == 0) {
            input = first8pad;
        } else {
            input = ((orig >> (64 - pos)) << (64 - pos)) |
                    ((first8pad << pos) >> pos);
        }

        memcpy(rin_input, &input, 8);

        EVP_EncryptUpdate(this->ctx, (unsigned char *)rin_output, &outl,
                (unsigned char *)rin_input, 16);

        result |= ((((uint64_t)rin_output[0]) >> 7) << (63 - pos));
    }

    return result;
}

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
