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

#include <stdio.h>
#include "libtrace.h"
#include "libpacketdump.h"

int main(int argc, char *argv[]) {

	struct libtrace_packet_t *packet = trace_packet_create();
	struct libtrace_t *trace;

	if (argc!=2) {
		printf("usage: %s erfuri\n",argv[0]);
		printf("This program dumps every packet out to stdout");
		return 1;
	}

        trace = trace_create(argv[1]);

	while (trace_read_packet(trace,&packet)>0) {
		trace_dump_packet(&packet);
		printf("\n");
        }

        trace_destroy(trace);
        return 0;
}
