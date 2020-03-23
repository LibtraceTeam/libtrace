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
#include <arpa/inet.h>
#include <inttypes.h>
#include "libtrace.h"
/** @file
 *
 * @brief Header file containing definitions of functions and macros that deal
 * with byteswapping within libtrace and libpacketdump. 
 *
 * @author Perry Lorier
 * @author Shane Alcock
 * 
 * @version $Id$
 */

#ifndef LT_BYTESWAP_H_
#define LT_BYTESWAP_H_
#ifdef __cplusplus 
extern "C" {
#endif

/** Byteswaps a 64-bit value.
 *
 * @param num           The value to be byteswapped.
 * @return The byteswapped 64-bit number
 *
 */
DLLEXPORT uint64_t byteswap64(uint64_t num);

/** Byteswaps a 32-bit value.
 *
 * @param num           The value to be byteswapped.
 * @return The byteswapped 32-bit number
 *
 */
uint32_t byteswap32(uint32_t num);

/** Byteswaps a 16-bit value.
 *
 * @param num           The value to be byteswapped.
 * @return The byteswapped 16-bit number
 *
 */
uint16_t byteswap16(uint16_t num);


#if __BYTE_ORDER == __BIG_ENDIAN
#define bswap_host_to_be64(num) ((uint64_t)(num))
#define bswap_host_to_le64(num) byteswap64(num)
#define bswap_host_to_be32(num) ((uint32_t)(num))
#define bswap_host_to_le32(num) byteswap32(num)
#define bswap_host_to_be16(num) ((uint16_t)(num))
#define bswap_host_to_le16(num) byteswap16(num)

#define bswap_be_to_host64(num) ((uint64_t)(num))
#define bswap_le_to_host64(num) byteswap64(num)
#define bswap_be_to_host32(num) ((uint32_t)(num))
#define bswap_le_to_host32(num) byteswap32(num)
#define bswap_be_to_host16(num) ((uint16_t)(num))
#define bswap_le_to_host16(num) byteswap16(num)

/* We use ntoh*() here, because the compiler may
 * attempt to optimise it
 */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define bswap_host_to_be64(num) (byteswap64(num))
#define bswap_host_to_le64(num) ((uint64_t)(num))
#define bswap_host_to_be32(num) (htonl(num))
#define bswap_host_to_le32(num) ((uint32_t)(num))
#define bswap_host_to_be16(num) (htons(num))
#define bswap_host_to_le16(num) ((uint16_t)(num))

#define bswap_be_to_host64(num) (byteswap64(num))
#define bswap_le_to_host64(num) ((uint64_t)(num))
#define bswap_be_to_host32(num) (ntohl(num))
#define bswap_le_to_host32(num) ((uint32_t)(num))
#define bswap_be_to_host16(num) (ntohs(num))
#define bswap_le_to_host16(num) ((uint16_t)(num))

#else
#error "Unknown byte order"
#endif

#ifdef __cplusplus 
}
#endif

#endif
