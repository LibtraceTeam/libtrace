/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007 The University of Waikato, Hamilton, New Zealand.
 * Authors: Richard Sanger
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
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <math.h>
#include <signal.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "dagformat.h"
#include "libtrace.h"

#define ERROR(mesg, ...) { \
	err = 1; \
	fprintf(stderr, "%s Error: " mesg, uri_read, __VA_ARGS__); \
}

static const char *uri_read;
static libtrace_t *trace_read;


/**
 * Source packet we modify this every write see build_packet
 */
static unsigned char buffer1[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, /* Dest Mac */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x06, /* Src Mac */
	0x01, 0x01, /* Ethertype = Experimental */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
};

static unsigned char buffer2[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, /* Dest Mac */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x06, /* Src Mac */
	0x01, 0x01, /* Ethertype = Experimental */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
};


static void signal_handler(int signal)
{
	if (signal == SIGALRM) {
		fprintf(stderr, "!!!Failed due to Timeout!!!\n");
		exit(-1);
	}
}

/**
 * Verifies a packet matches with what we expected
 */
static int verify_packet(libtrace_packet_t *packet, size_t expected_size)
{
	int err = 0;

	// Verify wirelen - Wirelen includes checksum of 4 bytes
	if (trace_get_wire_length(packet) != expected_size + 4) {
		ERROR("trace_get_wire_length() incorrect, read %zu expected %zu\n",
				trace_get_wire_length(packet), expected_size + 4);
	}
	// Verify caplen is no more than we asked for, this is allowed
	// to include the CRC sum but should still be snapped off if applicable
	if (trace_get_capture_length(packet) == MIN(expected_size, 30)) {
		// Good
	} else if (trace_get_capture_length(packet) == MIN(expected_size+4, 30)) {
		// Good
	} else {
		ERROR("trace_get_capture_length() incorrect, read %zu expected %zu (or %zu)\n",
			trace_get_capture_length(packet), MIN(expected_size, 30), MIN(expected_size+4, 30));
	}
	return err;
}

static void iferr_out(libtrace_out_t *trace)
{
	libtrace_err_t err = trace_get_err_output(trace);
	if (err.err_num == 0)
		return;
	printf("Error: %s\n", err.problem);
	exit(1);
}

static void iferr(libtrace_t *trace)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num == 0)
		return;
	printf("Error: %s\n", err.problem);
	exit(1);
}

int main(int argc, char *argv[])
{
	libtrace_out_t *trace_write;
	libtrace_packet_t *packet;
	int psize;
	int err = 0;
	int opt;

	if (argc < 3) {
		fprintf(stderr, "usage: %s type(write) type(read)\n", argv[0]);
		return 1;
	}

	signal(SIGALRM, signal_handler);
	// Timeout after 5 seconds
	alarm(5);

	trace_write = trace_create_output(argv[1]);
	iferr_out(trace_write);
	uri_read = argv[2];
	trace_read = trace_create(uri_read);
	iferr(trace_read);

	// Set snaplen to 30 bytes
	opt = 30;
	if (trace_config(trace_read, TRACE_OPTION_SNAPLEN, &opt) != 0)
	iferr(trace_read);

	trace_start_output(trace_write);
	iferr_out(trace_write);
	trace_start(trace_read);
	iferr(trace_read);

	packet = trace_create_packet();

	// Write out buffer1 and buffer2 (only buffer 2 should be snapped)
	trace_construct_packet(packet, TRACE_TYPE_ETH, buffer1, sizeof(buffer1));
	if (trace_write_packet(trace_write, packet) == -1) {
		iferr_out(trace_write);
	}
	trace_construct_packet(packet, TRACE_TYPE_ETH, buffer2, sizeof(buffer2));
	if (trace_write_packet(trace_write, packet) == -1) {
		iferr_out(trace_write);
	}
	trace_destroy_packet(packet);
	trace_destroy_output(trace_write);

	// Now read the 2 packets back in
	packet = trace_create_packet();

	if ((psize = trace_read_packet(trace_read, packet)) < 0) {
		iferr(trace_read);
		// EOF we shouldn't hit this with a live format
		fprintf(stderr, "Error: looks like we lost some packets!\n");
		err = 1;
	} else {
		err |= verify_packet(packet, sizeof(buffer1));
		if ((psize = trace_read_packet(trace_read, packet)) < 0) {
			iferr(trace_read);
			// EOF we shouldn't hit this with a live format
			fprintf(stderr, "Error: looks like we lost some packets!\n");
			err = 1;
		} else {
			err |= verify_packet(packet, sizeof(buffer2));
		}
	}

	trace_destroy_packet(packet);
	trace_destroy(trace_read);

	return err;
}