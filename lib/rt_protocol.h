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

#define MAXDATASIZE 65536

#define RT_DATA 1
#define RT_MSG 2

typedef struct rt_status {
	uint8_t type;
	uint8_t reserved;
	uint16_t message;
} rt_status_t;


typedef struct packet_header {
	rt_status_t header;
	dag_record_t erf;
} packet_header_t;

typedef struct ack_packet {
	rt_status_t header;
	long long int ts;
} ack_packet_t;

#endif // _RT_PROTOCOL_H_
