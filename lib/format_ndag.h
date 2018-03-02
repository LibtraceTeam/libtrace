/*
 *
 * Copyright (c) 2007-2017 The University of Waikato, Hamilton, New Zealand.
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


#ifndef FORMAT_NDAG_H_
#define FORMAT_NDAG_H_

#include <libtrace.h>

#define NDAG_MAX_DGRAM_SIZE (8900)

#define NDAG_MAGIC_NUMBER (0x4E444147)
#define NDAG_EXPORT_VERSION 1


enum {
        NDAG_PKT_BEACON = 0x01,
        NDAG_PKT_ENCAPERF = 0x02,
        NDAG_PKT_RESTARTED = 0x03,
        NDAG_PKT_ENCAPRT = 0x04,
        NDAG_PKT_KEEPALIVE = 0x05
};

/* == Protocol header structures == */

/* Common header -- is prepended to all exported records */
typedef struct ndag_common_header {
        uint32_t magic;
        uint8_t version;
        uint8_t type;
        uint16_t monitorid;
} PACKED ndag_common_t;

/* Beacon -- structure is too simple to be worth defining as a struct */
/*
 * uint16_t numberofstreams;
 * uint16_t firststreamport;
 * uint16_t secondstreamport;
 * ....
 * uint16_t laststreamport;
 */

/* Encapsulation header -- used by both ENCAPERF and ENCAPRT records */
typedef struct ndag_encap {
        uint64_t started;
        uint32_t seqno;
        uint16_t streamid;
        uint16_t recordcount; /* acts as RT type for ENCAPRT records */
} PACKED ndag_encap_t;

#endif
