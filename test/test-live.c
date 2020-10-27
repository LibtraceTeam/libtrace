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
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "dagformat.h"
#include "libtrace.h"


#define ONCE(run_me) { \
	static int hit = 0; \
	if (!hit) { \
		run_me \
	} \
	hit = 1; \
}

#define ERROR(mesg, ...) { \
	ONCE( \
		err = 1; \
		fprintf(stderr, "%s[%d] Error: " mesg, uri_read, i, __VA_ARGS__); \
	) \
}

static const char *uri_read = "";
static sig_atomic_t i = 0;
static sig_atomic_t reading = 0;
static libtrace_t *trace_read = NULL;
static int test_size = 100;


/**
 * Source packet we modify this every write see build_packet
 */
static unsigned char buffer[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, /* Dest Mac */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x06, /* Src Mac */
	0x01, 0x01, /* Ethertype = Experimental */
	0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, /* payload */
};


union uint32_char {
	char chars[4];
	uint32_t i32;
};

/* Build a unique packet from a seed value of i */
static void build_packet(int i)
{
	// Shh about them type-punned aliasing issues
	union uint32_char u;
	srand(i);
	u.i32 = (uint32_t) rand();
	buffer[sizeof(libtrace_ether_t)] = u.chars[0];
	buffer[sizeof(libtrace_ether_t)+1] = u.chars[1];
	buffer[sizeof(libtrace_ether_t)+2] = u.chars[2];
	buffer[sizeof(libtrace_ether_t)+3] = u.chars[3];
}

static void dumparray(unsigned char *arr, size_t len)
{
	size_t i;

	fprintf(stderr, "{");
	for (i = 0; i < len; ++i) {
		fprintf(stderr, "0x%02X,", arr[i]);
	}
	fprintf(stderr, "}\n");
}

/**
 * Verifies statistic counters at the end of the trace
 */
static int verify_counters(libtrace_t *trace_read)
{
	int err = 0;
        libtrace_stat_t *stat;

        stat = trace_create_statistics();

        trace_get_statistics(trace_read, stat);
	// Assume no loss here, if not the case we would of hung in reading loop
	// anyway
        if (!stat->dropped_valid) {
		printf("\tInfo: trace does not support drop counter\n");
        } else if (stat->dropped != 0) {
		ERROR("Trace dropped %zu packets\n", stat->dropped);
	}

        if (!stat->filtered_valid) {
		printf("\tInfo: trace does not support filter counter\n");
        } else if (stat->filtered != 0) {
		ERROR("Trace filtered %zu packets\n", stat->filtered);
	}

        if (!stat->received_valid) {
		printf("\tInfo: trace does not support received counter\n");
        } else if (stat->received != (uint32_t) test_size) {
		ERROR("Trace received %zu/%u packets\n", stat->received,
				(uint32_t)test_size);
        }

        if (!stat->accepted_valid) {
		printf("\tInfo: trace does not support accepted counter\n");
        } else if (stat->accepted != (uint32_t) test_size) {
		ERROR("Trace only accepted %zu/%u packets\n", stat->accepted,
                                (uint32_t)test_size);
        }

	return err;
}

static void signal_handler(int signal)
{
	if (signal == SIGALRM) {
		if (reading) {
			verify_counters(trace_read);
			fprintf(stderr, "!!!Timeout after reading only %d packets of %d!!!\n", i, test_size);
		} else {
			fprintf(stderr, "!!!Timeout after writing only %d packets of %d!!!\n", i, test_size);
		}
		exit(-1);
	}
}

/**
 * Verifies a packet matches with what we expected
 */
static int verify_packet(libtrace_packet_t *packet, int seq_num)
{
	int err = 0;
	static int caplen_incld_crc = -1;
	static double ts = -1;
	libtrace_linktype_t linktype;
	uint32_t remaining;
	unsigned char* pktbuffer;

	// Verify wirelen - Wirelen includes checksum of 4 bytes
	if (trace_get_wire_length(packet) != sizeof(buffer) + 4) {
		ERROR("Incorrect trace_get_wire_length(), read %zu expected %zu\n",
				trace_get_wire_length(packet), sizeof(buffer) + 4);
	}

	// Verify caplen
	if (trace_get_capture_length(packet) == sizeof(buffer)) {
		if (caplen_incld_crc == 1) {
			ERROR("Expected trace_get_capture_length() to EXCLUDE the Ethernet checksum,"
				" read %zu expected %zu\n", trace_get_capture_length(packet),
				sizeof(buffer));
		} else {
			caplen_incld_crc = 0;
		}
	} else if (trace_get_capture_length(packet) == sizeof(buffer) + 4) {
		if (caplen_incld_crc == 0) {
			ERROR("Expected trace_get_capture_length() to INCLUDE the Ethernet checksum,"
				" read %zu expected %zu\n", trace_get_capture_length(packet),
				sizeof(buffer)+4);
		} else {
			caplen_incld_crc = 1;
		}
	} else {
		ERROR("Incorrect trace_get_capture_length(), read %zu expected %zu (or %zu)\n",
			trace_get_capture_length(packet), sizeof(buffer), sizeof(buffer)+4);
	}

	// Verify a packets contents
	pktbuffer = trace_get_packet_buffer(packet, &linktype, &remaining);
	assert(trace_get_capture_length(packet) == remaining);
	assert(linktype == TRACE_TYPE_ETH);
	// Refill the buffer with the expected data
	build_packet(seq_num);
	if (memcmp(pktbuffer, buffer, MIN(sizeof(buffer), remaining)) != 0) {
		ERROR("Packet contents do not match\n%s", "Received:\n");
		ONCE(
		dumparray(pktbuffer, remaining);
		fprintf(stderr, "Expected:\n");
		dumparray(buffer, sizeof(buffer));
		)
	}

	// Check times count up like we'd expect
	if (ts != 1 && trace_get_seconds(packet) < ts) {
		ERROR("Timestamps aren't increasing, ts=%f last_ts=%f\n",
			trace_get_seconds(packet), ts);
	}

	ts = trace_get_seconds(packet);

	// Verify trace_get and set direction work
	libtrace_direction_t dir_set;
	if ((dir_set = trace_set_direction(packet, TRACE_DIR_OUTGOING)) != -1) {
		if (trace_get_direction(packet) != TRACE_DIR_OUTGOING) {
			ERROR("Trace lies about its ability to set TRACE_DIR_OUTGOING,"
				"read %d expected %d\n", trace_get_direction(packet),
				TRACE_DIR_OUTGOING);
		}
	}
	if ((dir_set = trace_set_direction(packet, TRACE_DIR_INCOMING)) != -1) {
		if (trace_get_direction(packet) != TRACE_DIR_INCOMING) {
			ERROR("Trace lies about its ability to set TRACE_DIR_INCOMING,"
				"read %d expected %d\n", trace_get_direction(packet),
				TRACE_DIR_INCOMING);
		}
	}
	if ((dir_set = trace_set_direction(packet, TRACE_DIR_OTHER)) != -1) {
		if (trace_get_direction(packet) != TRACE_DIR_OTHER) {
			ERROR("Trace lies about its ability to set TRACE_DIR_OTHER,"
				"read %d expected %d\n", trace_get_direction(packet),
				TRACE_DIR_OTHER);
		}
	}
	if ((dir_set = trace_set_direction(packet, TRACE_DIR_UNKNOWN)) != -1) {
		if (trace_get_direction(packet) != TRACE_DIR_UNKNOWN) {
			ERROR("Trace lies about its ability to set TRACE_DIR_UNKNOWN,"
				"read %d expected %d\n", trace_get_direction(packet),
				TRACE_DIR_UNKNOWN);
		}
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

	if (argc < 2) {
		fprintf(stderr, "usage: %s type(write) [type(read)]\n", argv[0]);
		return 1;
	}

	signal(SIGALRM, signal_handler);
	// Timeout after 5 seconds
	alarm(5);

	trace_write = trace_create_output(argv[1]);
	iferr_out(trace_write);
	if (argc > 2) {
		uri_read = argv[2];
		trace_read = trace_create(uri_read);
		iferr(trace_read);
	}

	if (strncmp(uri_read, "pcapint", 7) == 0) {
		/* The newer Linux memmap (ring:) implementation of PCAP only makes
		 * space for about 30 maybe 31 packet buffers. If we exceed this we'll
		 * drop packets. */
		test_size = 30;
	}

	trace_start_output(trace_write);
	iferr_out(trace_write);
	if (argc > 2) {
		trace_start(trace_read);
		iferr(trace_read);
	}

	packet = trace_create_packet();

	// Write out test_size (100) almost identical packets
	for (i = 0; i < test_size; i++) {
		build_packet(i);
		trace_construct_packet(packet, TRACE_TYPE_ETH, buffer, sizeof(buffer));
		if (trace_write_packet(trace_write, packet) == -1) {
			iferr_out(trace_write);
		}
	}
	trace_destroy_packet(packet);
	trace_destroy_output(trace_write);

	if (argc <= 2) {
		printf("Sent %d packets\n", test_size);
		return 0;
	}

	// Now read back in, we assume that buffers internally can buffer
	// the packets without losing them
	packet = trace_create_packet();

	reading = 1;
	for (i = 0; i < test_size; i++) {
		if ((psize = trace_read_packet(trace_read, packet)) < 0) {
			iferr(trace_read);
			// EOF we shouldn't hit this with a live format
			fprintf(stderr, "Error: looks like we lost some packets!\n");
			err = 1;
			break;
		}
		err |= verify_packet(packet, i);
	}

	err |= verify_counters(trace_read);

	trace_destroy_packet(packet);
	trace_destroy(trace_read);

	return err;
}
