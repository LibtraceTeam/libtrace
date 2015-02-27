/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007 The University of Waikato, Hamilton, New Zealand.
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
#ifndef WIN32
#  include <sys/time.h>
#  include <netinet/in.h>
#  include <netinet/in_systm.h>
#  include <netinet/tcp.h>
#  include <netinet/ip.h>
#  include <netinet/ip_icmp.h>
#  include <arpa/inet.h>
#  include <sys/socket.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "dagformat.h"
#include "libtrace.h"
#include "data-struct/vector.h"
#include "combiners.h"

void iferr(libtrace_t *trace,const char *msg)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s: %s\n", msg, err.problem);
	exit(1);
}

const char *lookup_uri(const char *type) {
	if (strchr(type,':'))
		return type;
	if (!strcmp(type,"erf"))
		return "erf:traces/100_packets.erf";
	if (!strcmp(type,"rawerf"))
		return "rawerf:traces/100_packets.erf";
	if (!strcmp(type,"pcap"))
		return "pcap:traces/100_packets.pcap";
	if (!strcmp(type,"wtf"))
		return "wtf:traces/wed.wtf";
	if (!strcmp(type,"rtclient"))
		return "rtclient:chasm";
	if (!strcmp(type,"pcapfile"))
		return "pcapfile:traces/100_packets.pcap";
	if (!strcmp(type,"pcapfilens"))
		return "pcapfile:traces/100_packetsns.pcap";
	if (!strcmp(type, "duck"))
		return "duck:traces/100_packets.duck";
	if (!strcmp(type, "legacyatm"))
		return "legacyatm:traces/legacyatm.gz";
	if (!strcmp(type, "legacypos"))
		return "legacypos:traces/legacypos.gz";
	if (!strcmp(type, "legacyeth"))
		return "legacyeth:traces/legacyeth.gz";
	if (!strcmp(type, "tsh"))
		return "tsh:traces/10_packets.tsh.gz";
	return type;
}

int globalcount = 0;

static void reporter(libtrace_t *libtrace, libtrace_result_t *res, libtrace_message_t *mesg) {
	static uint64_t last = -1;
	static int pktcount = 0;
	if (res) {
		libtrace_packet_t *packet = libtrace_result_get_value(res).pkt;
		assert(libtrace_result_get_key(res) == trace_packet_get_order(packet));
		if(last == (uint64_t)-1) {
			last = libtrace_result_get_key(res);
		} else {
		assert (last < libtrace_result_get_key(res));
		last = libtrace_result_get_key(res);
		}
		pktcount++;
		trace_free_result_packet(libtrace, packet);
	} else {
		// Mesg
		switch (mesg->code) {
		case MESSAGE_STOPPING:
			globalcount = pktcount;
		default:
			break;
		}
	}
}

static void* per_packet(libtrace_t *trace, libtrace_packet_t *pkt, 
						libtrace_message_t *mesg,
						libtrace_thread_t *t) {
	UNUSED static __thread int x = 0;
	if (pkt) {
		int a,*b,c=0;
		// Do some work to even out the load on cores
		b = &c;
		for (a = 0; a < 10000000; a++) {
			c += a**b;
		}
		x = c;
		trace_publish_result(trace, t, trace_packet_get_order(pkt), (libtrace_generic_t){.pkt=pkt}, RESULT_PACKET);
		return NULL;
	}
	else switch (mesg->code) {
		// We don't care we have no state
		default:
			break;
	}
	return pkt;
}

int main(int argc, char *argv[]) {
	int error = 0;
	int expected = 100;
	const char *tracename;
	libtrace_t *trace;

	if (argc<2) {
		fprintf(stderr,"usage: %s type\n",argv[0]);
		return 1;
	}

	tracename = lookup_uri(argv[1]);

	trace = trace_create(tracename);
	iferr(trace,tracename);

	if (strcmp(argv[1],"rtclient")==0) expected=101;

	trace_set_combiner(trace, &combiner_ordered, (libtrace_generic_t){0});

	trace_pstart(trace, NULL, per_packet, reporter);
	iferr(trace,tracename);

	/* Make sure traces survive a pause */
	trace_ppause(trace);
	iferr(trace,tracename);
	trace_pstart(trace, NULL, NULL, NULL);
	iferr(trace,tracename);

	/* Wait for all threads to stop */
	trace_join(trace);

	if (error == 0) {
		if (globalcount == expected) {
			printf("success: %d packets read\n",expected);
		} else {
			printf("failure: %d packets expected, %d seen\n",expected,globalcount);
			error = 1;
		}
	} else {
		iferr(trace,tracename);
	}
	trace_destroy(trace);
	return error;
}
