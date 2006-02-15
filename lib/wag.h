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

#ifndef _WAG_H
#define _WAG_H

/* This is the WAG magic number - used to delimit frames */
#define WAG_MAGIC               (0xdaa1)

/* Define frame types */
#define FRAME_TYPE_DATA         (0x0000)
#define FRAME_TYPE_UNDEFINED    (0xffff)

/* Define frame subtypes */
#define FRAME_SUBTYPE_DATA_RX   (0x0000)
#define FRAME_SUBTYPE_DATA_TX   (0x0001)

/* This is the common part of the frame header.
 * We synchronise by scanning a stream to look for the magic number (WAG_MAGIC).
 * We can then tell the size and type of this frame, and pass over it if necessary.
 */
struct frame_t {
  uint16_t magic;                                   /* magic number (0xdaa1) */
  uint16_t size;                                    /* total frame size in bytes */
  uint16_t type;                                    /* frame type */
  uint16_t subtype;                                 /* frame subtype */
};

/*/////////////////////////////////////////////////////////////////////////////////
//
// Frames that the radio part of the WAG framework understands
//
///////////////////////////////////////////////////////////////////////////////////
// Common subfields...
*/

/* timestamp */
struct timestamp_t {
  uint32_t           secs;                          /* seconds since start of 01-01-1970 */
  uint32_t           subsecs;                       /* (1/(2^32))ths of a second */
};

/* frame stream information */
struct strinfo_t {
  uint16_t unused_1;
  uint16_t unused_2;
  uint16_t unused_3;
  uint16_t packets_lost;
};

/* Type: DATA, Subtype: RX */
struct frame_data_rx_t {
  struct frame_t                 hdr;               /* common frame header */
  struct strinfo_t               strinfo;           /* stream status */
  struct timestamp_t             ts;                /* timestamp of reception of this frame */
  struct {
    uint8_t              rssi;                      /* receive signal strength of this frame */
    uint8_t              rxstatus;                  /* rx status bits from the modem */
    uint16_t             length;                    /* length in bytes of the frame payload */
    struct {
      uint8_t  signal;                              /* 802.11PLCP signal field */
      uint8_t  service;                             /* 802.11PLCP service field */
      uint16_t length; } plcp; } rxinfo;            /* 802.11PLCP length field (uS) */
  char                           data[0];           /* placeholder to allow payload access */
};

/* Type: DATA, Subtype: TX */
struct frame_data_tx_t {
  struct frame_t                 hdr;               /* common frame header */
  uint64_t                       unused_1;         
  uint64_t                       unused_2;          
  struct {
    uint8_t  gain;                                  /* tx gain with which to send this packet */
    uint8_t  mode;                                  /* tx mode with which to send this packet */
    uint16_t length;                                /* length in bytes of the frame payload */
    uint32_t unused_1; }         txinfo;            
  char                           data[0];           /* placeholder to allow payload access */
};

struct ieee_802_11_header {
        unsigned int      protocol:2;
        unsigned int      type:2;
        unsigned int      subtype:4;
        unsigned int      to_ds:1;
        unsigned int      from_ds:1;
        unsigned int      more_frag:1;
        unsigned int      retry:1;
        unsigned int      power:1;
        unsigned int      more_data:1;
        unsigned int      wep:1;
        unsigned int      order:1;
        unsigned int     duration;
        uint8_t      mac1[6];
        uint8_t      mac2[6];
        uint8_t      mac3[6];
        uint16_t     SeqCtl;
        uint8_t      mac4[6];
        uint8_t      data[1];
};

struct ieee_802_11_payload {
        uint16_t     type;
        uint8_t      data[1];
};


#endif
