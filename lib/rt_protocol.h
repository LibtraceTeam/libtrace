/*
 * This file is part of wdcap
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson
 *          Shane Alcock
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * wdcap is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wdcap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wdcap; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 */

#ifndef _RT_PROTOCOL_H_
#define _RT_PROTOCOL_H_
#include "config.h"

#ifdef HAVE_DAG
#	include <dagapi.h>
#	include <dagnew.h>
#else 
#	include <dagformat.h>
#endif

#include <libfifo.h>

#define CAPTURE_PORT 3434
#define COLLECTOR_PORT 3435

#define MAXDATASIZE 65536

// Server status codes
#define S_KEYCHANGE 1 // Encryption key has changed, flush collection to disk
#define S_DISKWARN 2 // Disk-backed fifo is > 75% used
#define S_DISKCRIT 4 // Disk-backed fifo  is > 90% used
#define S_DISKFULL 8 // Disk-backed fifo is > 95% used
#define S_STATUS 16 // Packet is a fifo_status packet
#define S_LOSTDATA 32 // capture restarted, flush collection to disk
#define S_LOSTCONN 64 // connection to collector restarted, flush collection to disk
/* ----------------------*/ 
/* Codes for messages that cannot be parsed by libtrace */ 
#define S_ALLCONN 128 // Already someone connected. Go away
#define S_DUCKINFO 256 // Duck information packet
#define S_FINISH 512 // No more data - close connection
#define S_ACCEPT 1024 // Connection accepted

#define S_MESSAGE_ONLY S_ALLCONN

// fifo_state_t is a tricky data type to transmit and receive so
// it's easier to create a specialised structure
typedef struct fifo_info {
	fifo_offset_t length;
	fifo_offset_t used;
	fifo_offset_t in;
	fifo_offset_t out;
	fifo_offset_t ack;
} fifo_info_t;

typedef struct fifo_status {
	fifo_info_t fifo;
} fifo_status_t;

typedef struct duck_info {
	duck_inf duck;
} duck_info_t;

typedef struct packet_header {
	uint32_t message;
	dag_record_t erf;
} packet_header_t;

typedef struct ack_packet {
	uint32_t header;
	long long int ts;
} ack_packet_t;

// Client message codes
#define M_HALT_CAPTURE 1	// Request to halt capture
#define M_START_CAPTURE 2	// Request to restart capture
#define M_CONFIGURE 4 		// Configuration info follows
#define M_ACK 8                 // Ack

#endif // _RT_PROTOCOL_H_
