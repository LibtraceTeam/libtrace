/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson 
 *          Perry Lorier 
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
#ifndef _WAG_H_
#define _WAG_H_

struct wag_event_t {
	uint32_t length;
	uint32_t timestamp_hi;
	uint32_t timestamp_lo;
	uint32_t type;
	uint32_t seq_num;
	uint8_t payload[];
};

struct wag_data_event_t {
	uint32_t rx_params;
	uint32_t rx_rssi;
	uint32_t frame_length;
	uint8_t data[];
};

struct ieee_802_11_header {
	uint8_t      protocol:2;
	uint8_t	     type:2;
	uint8_t      subtype:4;
	uint8_t	     to_ds:1;
	uint8_t	     from_ds:1;
	uint8_t	     more_frag:1;
	uint8_t	     retry:1;
	uint8_t	     power:1;
	uint8_t	     more_data:1;
	uint8_t	     wep:1;
	uint8_t	     order:1;
	uint16_t     duration;
	uint8_t      mac1[6];
	uint8_t      mac2[6];
	uint8_t      mac3[6];
	uint16_t     SeqCtl;
	uint8_t      mac4[6];
	uint8_t	     data[];
};

struct ieee_802_11_payload {
	uint16_t     type;
	uint8_t	     data[];
};

#endif
