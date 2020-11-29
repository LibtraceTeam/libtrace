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


#ifndef WDCAP_ANON_H
#define WDCAP_ANON_H

#include "config.h"
#include <sys/types.h>
#include <inttypes.h>

#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>
#endif

#define SALT_LENGTH 32

enum {
    RADIUS_ANON_MODE_BINARY,
    RADIUS_ANON_MODE_NUMERIC,
    RADIUS_ANON_MODE_TEXT,
};

class Anonymiser {
public:
    Anonymiser(uint8_t *salt);
    virtual ~Anonymiser();

    virtual uint32_t anonIPv4(uint32_t orig) {return 0;};
    virtual void anonIPv6(uint8_t *orig, uint8_t *result) {};

    uint8_t *digest_message(uint8_t *src_ptr, uint32_t src_length, uint8_t anon_mode);

private:

#ifdef HAVE_LIBCRYPTO
    uint8_t salt[SALT_LENGTH];
    EVP_MD_CTX *mdctx;
    uint8_t buffer[32];
#endif

};

class PrefixSub: public Anonymiser {
public:
    PrefixSub(const char *ipv4_key, const char *ipv6_key, uint8_t *salt);
    ~PrefixSub();
    uint32_t anonIPv4(uint32_t orig);
    void anonIPv6(uint8_t *orig, uint8_t *result);

private:
    uint32_t ipv4_prefix;
    uint32_t ipv4_mask;

    uint8_t ipv6_prefix[16];
    uint8_t ipv6_mask[16];

};

#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>
#include <map>

typedef std::map<uint32_t, uint32_t> IPv4AnonCache;
typedef std::map<uint64_t, uint64_t> IPv6AnonCache;

class CryptoAnon : public Anonymiser {
public:
    CryptoAnon(uint8_t *key, uint8_t len, uint8_t cachebits, uint8_t *salt);
    ~CryptoAnon();

    uint32_t anonIPv4(uint32_t orig);
    void anonIPv6(uint8_t *orig, uint8_t *result);

private:
    uint8_t padding[16];
    uint8_t key[16];
    uint8_t cachebits;

    IPv4AnonCache *ipv4_cache;
    IPv6AnonCache *ipv6_cache;

    uint32_t recent_ipv4_cache[2][2];
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx;

    uint32_t encrypt32Bits(uint32_t orig, uint8_t start, uint8_t stop,
            uint32_t res);
    uint64_t encrypt64Bits(uint64_t orig); 
    uint32_t lookupv4Cache(uint32_t prefix);
    uint64_t lookupv6Cache(uint64_t prefix);

};
#endif

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
