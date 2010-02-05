/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock 
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

#ifndef FORMAT_ERF_H
#define FORMAT_ERF_H

#include "libtrace.h"

/** @file
 *
 * @brief Header file defining functions that apply to all libtrace formats
 * that use the ERF record format, e.g. ERF, DAG 2.4, DAG 2.5
 *
 * @author Daniel Lawson
 * @author Perry Lorier
 * @author Shane Alcock
 *
 * @version $Id$
 *
 * Not too much detail required with these functions - this header file exists
 * solely to ensure that we don't have to duplicate the same code across 
 * multiple format modules.
 */

int erf_get_framing_length(const libtrace_packet_t *packet);
libtrace_linktype_t erf_get_link_type(const libtrace_packet_t *packet);
libtrace_direction_t erf_get_direction(const libtrace_packet_t *packet);
libtrace_direction_t erf_set_direction(libtrace_packet_t *packet, libtrace_direction_t direction);
uint64_t erf_get_erf_timestamp(const libtrace_packet_t *packet);
int erf_get_capture_length(const libtrace_packet_t *packet);
int erf_get_wire_length(const libtrace_packet_t *packet);
size_t erf_set_capture_length(libtrace_packet_t *packet, size_t size);

#endif
