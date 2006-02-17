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

#ifndef FORMAT_HELPER_H
#define FORMAT_HELPER_H
#include "common.h"

int trace_read(libtrace_t *libtrace, void *buffer, size_t len);

struct libtrace_eventobj_t trace_event_device(libtrace_t *trace, libtrace_packet_t *packet);
struct libtrace_eventobj_t trace_event_trace(libtrace_t *trace, libtrace_packet_t *packet);

LIBTRACE_FILE trace_open_file(libtrace_t *libtrace);
#endif /* FORMAT_HELPER_H */
