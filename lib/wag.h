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

// Generic field breakdowns
struct wag_frame_hdr {
  uint16_t magic;
  uint16_t size;
  uint16_t type;
  uint16_t subtype;
};

struct wag_timestamp {
  uint32_t secs;
  uint32_t subsecs;
};

// Received packet frame fields
struct wag_stream_info {
  uint16_t unused_1;
  uint16_t unused_2;
  uint16_t unused_3;
  uint16_t packets_lost;
};

struct wag_plcp_hdr {
  uint8_t  signal;
  uint8_t  service;
  uint16_t length;
};

struct wag_rxparams {
  uint8_t         rssi;
  uint8_t         rxstatus;
  uint16_t        length;
  struct wag_plcp_hdr plcp;
};

struct wag_data_frame {
  struct wag_frame_hdr hdr;
  struct wag_stream_info strinfo;
  struct wag_timestamp ts;
  struct wag_rxparams rxinfo;
  char data[1];
};

// Transmit packet frame fields
struct wag_txparams {
  uint8_t         gain;
  uint8_t         mode;
  uint16_t        length;
  uint32_t        unused_1;
};

struct wag_tx_data_frame {
  struct wag_frame_hdr hdr;
  uint32_t         unused_1;
  uint32_t         unused_2;
  struct wag_txparams  txinfo;
  char data[1];
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
	uint8_t	     data[1];
};

struct ieee_802_11_payload {
	uint16_t     type;
	uint8_t	     data[1];
};

#endif
