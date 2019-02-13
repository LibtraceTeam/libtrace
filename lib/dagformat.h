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
/** @file
 *
 * @brief Header file containing definitions required to process DAG / ERF
 * traces
 *
 * @author Daniel Lawson
 * @author Perry Lorier
 * @author Shane Alcock
 *
 * @version $Id$
 *
 * Most of the structures defined in here are already defined in the Endace DAG
 * libraries, but we need to re-define them ourselves here so that we can
 * process ERF traces without requiring the user to buy a DAG card :)
 */
#ifndef _DAGFORMAT_H_
#define _DAGFORMAT_H_

#include "libtrace.h"
#include "erftypes.h"

#ifdef WIN32
#pragma pack(push)
#pragma pack(1)
#endif

/** GPP Type 1 */
typedef struct pos_rec {
	uint32_t  hdlc;			/**< The HDLC header */	
	uint8_t	  pload[1];		/**< First byte of payload */
}  PACKED pos_rec_t;

/** GPP Type 2 */
typedef struct eth_rec {
	uint8_t   offset;		/**< Ethernet record offset */
	uint8_t   pad;			/**< Padding */
	uint8_t   dst[6];		/**< Destination MAC address */	
	uint8_t   src[6];		/**< Source MAC address */
	uint16_t  etype;		/**< Ethertype */
	uint8_t   pload[1];		/**< First byte of payload */
}  PACKED eth_rec_t;

/** GPP Type 3 */
typedef struct atm_rec {
	uint32_t  header;		/**< The ATM header */ 
	uint8_t   pload[1];		/**< First byte of payload */
}  PACKED atm_rec_t;

/** GPP Type 4 */
typedef struct aal5_rec {
	uint32_t  header; 		/**< The AAL5 header */
	uint8_t   pload[1];		/**< First byte of payload */
}  PACKED aal5_rec_t;

/** Flags */
typedef struct flags {
	LT_BITFIELD8  iface:2;		/**< Interface (direction) */
	LT_BITFIELD8  vlen:1;		/**< Varying Record Lengths Present */
	LT_BITFIELD8  trunc:1;		/**< Truncated Record */
	LT_BITFIELD8  rxerror:1;	/**< RX Error detected */
	LT_BITFIELD8  dserror:1;	/**< Data stream error */
	LT_BITFIELD8  pad:2;		/**< Unused */
} PACKED flags_t;

/** GPP Global type */
typedef struct dag_record {
	uint64_t  ts;		/**< ERF timestamp */
	uint8_t   type;		/**< GPP record type */
	flags_t   flags;	/**< Flags */
	uint16_t  rlen;		/**< Record len (capture+framing) */
	uint16_t  lctr;		/**< Loss counter */
	uint16_t  wlen;		/**< Wire length */
	union {
		pos_rec_t       pos;		
		eth_rec_t       eth;
		atm_rec_t       atm;
		aal5_rec_t      aal5;
	} rec;			/**< The captured record itself */
} PACKED dag_record_t;

typedef struct dag_section_header {
	uint16_t type;
	uint16_t len;
} PACKED dag_sec_t;

struct dag_opthdr {
	uint16_t optcode;
	uint16_t optlen;
} PACKED;

#ifdef WIN32
#pragma pack(pop)
#endif

/** The size of the ERF record header, without the rec field */
#define dag_record_size         16U

#endif /* _DAGFORMAT_H_ */
