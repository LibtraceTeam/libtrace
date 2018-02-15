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
int erf_is_color_type(uint8_t erf_type);

#endif
