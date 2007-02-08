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
 * $Id: test-rtclient.c,v 1.2 2006/02/27 03:41:12 perry Exp $
 *
 */
#include <libtrace.h>
#include <assert.h>

void test_forgotten_wronly()
{
	libtrace_out_t *out;
	libtrace_t *trace;
	libtrace_packet_t *packet;
	int err;
	int zero = 0;

	out = trace_create_output("pcapfile:traces/100_packets_out.pcap");
	assert(out);
	assert (!trace_is_err_output(out));
	/* Note: no WRONLY/RDWR */
	err = trace_config_output(out,TRACE_OPTION_OUTPUT_FILEFLAGS,&zero);
	assert(err==0);
	assert(!trace_is_err_output(out));

	err = trace_start_output(out);
	assert(err == 0);
	assert(!trace_is_err_output(out));

	trace = trace_create("pcapfile:traces/100_packets.pcap");
	assert(trace);
	assert(!trace_is_err(trace));
	
	err = trace_start(trace);
	assert(!trace_is_err(trace));
	assert(err == 0);

	packet = trace_create_packet();
	assert(packet);

	err = trace_read_packet(trace, packet);
	assert(err>0);

	err = trace_write_packet(out,packet);
	assert(err == -1); 		/* Should fail */
	assert(trace_is_err_output(out)); 

	trace_destroy_output(out);
	trace_destroy_packet(packet);
	trace_destroy(trace);
}

int main(int argc, char *argv[]) 
{
	test_forgotten_wronly();

	return 0;
}
