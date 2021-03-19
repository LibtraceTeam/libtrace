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
#ifndef DAG_LEGACY_H
#define DAG_LEGACY_H

/** @file
 *
 * @brief Header file describing the framing formats used by old legacy DAG
 * implementations.
 *
 * @author Daniel Lawson
 * @author Perry Lorier
 * @author Shane Alcock
 *
 * @version $Id$
 *
 */


/** Legacy ATM cell header */
typedef struct legacy_cell {
        uint64_t  ts;		/**< 64-bit timestamp in the ERF format */
        uint32_t  crc;		/**< CRC checksum */
} PACKED legacy_cell_t;
ct_assert(sizeof(legacy_cell_t) == 12);

/** Legacy Ethernet header */
typedef struct legacy_ether {
        uint64_t  ts;		/**< 64-bit timestamp in the ERF format */
        uint16_t  wlen;		/**< Wire length */
} PACKED legacy_ether_t;
ct_assert(sizeof(legacy_ether_t) == 10);

/** Legacy Packet-over-SONET header */
typedef struct legacy_pos {
        uint64_t  ts;		/**< 64-bit timestamp in the ERF format */
        uint32_t  slen;		/**< Capture length */
        uint32_t  wlen;		/**< Wire length */
} PACKED legacy_pos_t;
ct_assert(sizeof(legacy_pos_t) == 16);

/** ATM cell header capture, a la Auckland VII */
typedef struct atmhdr {
	uint32_t ts_fraction;	/**< Partial seconds portion of the timestamp */
	uint32_t ts_sec;	/**< Seconds portion of the timestamp */
} PACKED atmhdr_t;
ct_assert(sizeof(atmhdr_t) == 8);

/** Legacy header format used for capturing the NZIX-I trace set */
typedef struct legacy_nzix {
	uint32_t ts;		/**< Time elapsed since the last packet in
				     microseconds */
	uint32_t crc;		/**< CRC checksum */
	uint32_t len;		/**< Wire length */

	/* The padding has actually been placed in the middle of the IP
	 * header - when we read in the packet, we will move various bits
	 * of the packet around until the padding ends up here and the 
	 * IP header is undivided */
	uint8_t pad[2];		/**< Padding */
} PACKED legacy_nzix_t;
ct_assert(sizeof(legacy_nzix_t) == 14);
#endif
