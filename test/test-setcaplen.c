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
 * $Id: test-pcap-to-erf.c,v 1.3 2006/02/27 03:41:12 perry Exp $
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

#include "dagformat.h"
#include "libtrace.h"

void iferr(libtrace_t *trace)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s\n",err.problem);
	exit(1);
}

void iferrout(libtrace_out_t *trace)
{
	libtrace_err_t err = trace_get_err_output(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s\n",err.problem);
	exit(1);
}

char *lookup_uri(const char *type) 
{
	if (!strcmp(type,"erf"))
		return "erf:traces/100_packets.erf";
	if (!strcmp(type,"pcap"))
		return "pcap:traces/100_packets.pcap";
	if (!strcmp(type,"pcapng"))
		return "pcapng:traces/100_packets.pcapng";
	if (!strcmp(type,"wtf"))
		return "wtf:traces/wed.wtf";
	if (!strcmp(type,"rtclient"))
		return "rtclient:chasm";
	if (!strcmp(type,"pcapfile"))
		return "pcapfile:traces/100_packets.pcap";
	if (!strcmp(type,"pcapfilens"))
		return "pcapfile:traces/100_packetsns.pcap";
	if (!strcmp(type,"legacyatm"))
		return "legacyatm:traces/legacyatm.gz";
	if (!strcmp(type,"legacypos"))
		return "legacypos:traces/legacypos.gz";
	if (!strcmp(type,"legacyeth"))
		return "legacyeth:traces/legacyeth.gz";
	if (!strcmp(type, "duck"))
		return "duck:traces/100_packets.duck";
	if (!strcmp(type, "tsh"))
		return "tsh:traces/10_packets.tsh.gz";
	if (!strcmp(type, "sll1"))
		return "pcapfile:traces/sll.pcap.gz";
	if (!strcmp(type, "sll2"))
		return "pcapfile:traces/100_sll.pcap";
	return "unknown";
}

char *lookup_out_uri(const char *type) {
	if (!strcmp(type,"erf"))
		return "erf:traces/100_packets.out.erf";
	if (!strcmp(type,"pcap"))
		return "pcap:traces/100_packets.out.pcap";
	if (!strcmp(type,"pcapfile"))
		return "pcapfile:traces/100_packets.out.pcap";
	if (!strcmp(type,"wtf"))
		return "wtf:traces/wed.out.wtf";
	if (!strcmp(type,"duck"))
		return "duck:traces/100_packets.out.duck";
	return "unknown";
}

static int time_changed(libtrace_packet_t *packet, 
		libtrace_packet_t *packet2) {

	struct timeval tv1, tv2;

	tv1 = trace_get_timeval(packet);
	tv2 = trace_get_timeval(packet2);
	
	if (tv1.tv_sec != tv2.tv_sec || 
		tv1.tv_usec - tv2.tv_usec > 1 ||
		tv2.tv_usec - tv1.tv_usec > 1) { 
		printf("Timestamps differ: %u.%u vs %u.%u\n",
				tv1.tv_sec, tv1.tv_usec, 
				tv2.tv_sec, tv2.tv_usec);

		return 1;
	}
	return 0;

}

static int length_changed(libtrace_packet_t *packet, 
		libtrace_packet_t *packet2) {

	uint16_t wlen_1 = trace_get_wire_length(packet);
	uint16_t wlen_2 = trace_get_wire_length(packet2);

	if (wlen_1 != wlen_2)
		return true;

	return false;

}

int main(int argc, char *argv[]) {
        int psize = 0;
	int error = 0;
	int count = 0;
	int level = 0;
	int expected = 100;
	libtrace_t *trace,*trace2;
	libtrace_out_t *outtrace;
	libtrace_packet_t *packet,*packet2;
	const char *trace1name;
	const char *trace2name;

	trace = trace_create(lookup_uri(argv[1]));
	iferr(trace);

	if (strcmp(argv[1],"rtclient")==0)
		expected=101;

	outtrace = trace_create_output(lookup_out_uri(argv[2]));
	iferrout(outtrace);

	level=0;
	trace_config_output(outtrace,TRACE_OPTION_OUTPUT_COMPRESS,&level);
	if (trace_is_err_output(outtrace)) {
		trace_perror_output(outtrace,"WARNING: ");
	}

	trace_start(trace);
	iferr(trace);
	trace_start_output(outtrace);
	iferrout(outtrace);
	
	packet=trace_create_packet();
        for (;;) {
		if ((psize = trace_read_packet(trace, packet)) <0) {
			error = 1;
			break;
		}
		if (psize == 0) {
			error = 0;
			break;
		}

                trace_set_capture_length(packet, 32);
		if (trace_write_packet(outtrace,packet) > 0)
		        count ++;
		iferrout(outtrace);
		if (count>100)
			break;
        }
	trace_destroy_packet(packet);
	if (error == 0) {
		if (count != expected) {
			printf("failure: %d packets expected, %d seen\n",expected,count);
			error = 1;
		}
	} else {
		iferr(trace);
	}
        trace_destroy(trace);
	trace_destroy_output(outtrace);

	if (error)
		return error;

	/* Now read it back in again and check it's all kosher */
	trace1name = lookup_uri(argv[1]);
	trace = trace_create(trace1name);
	iferr(trace);
	trace_start(trace);
	trace2name = lookup_out_uri(argv[2]);
	trace2 = trace_create(trace2name);
	iferr(trace2);
	trace_start(trace2);
	iferr(trace2);
	packet=trace_create_packet();
	packet2=trace_create_packet();
	count=0;
	while(trace_read_packet(trace,packet)>0) {
		int err;

                if (IS_LIBTRACE_META_PACKET(packet))
                        continue;

		++count;
                do {
        		if ((err=trace_read_packet(trace2,packet2))<1) {
	        		printf("premature EOF on destination, %i from %s, %i from %s\n",count,lookup_uri(argv[1]),count-1,lookup_out_uri(argv[2]));
		        	iferr(trace2);
			        error=1;
        			break;
	        	}
                } while (IS_LIBTRACE_META_PACKET(packet2));

		/* The capture length might be snapped down to the wire length */
                if (trace_get_capture_length(packet) == 32) {
                        printf("original packet has been snapped?!\n");
                        abort();
                }

                if (trace_get_capture_length(packet2) != 32) {
                        printf("failed to properly snap packet\n");
                        abort();
                }

		if (length_changed(packet, packet2)) {
			printf("\t%s\t%s\n",
				trace1name,
				trace2name);
			printf("caplen\t%zd\t%zd\t%+zd\n",
				trace_get_capture_length(packet),
				trace_get_capture_length(packet2),
				trace_get_capture_length(packet2)-trace_get_capture_length(packet));
			printf("wirelen\t%zd\t%zd\t%+zd\n",
				trace_get_wire_length(packet),
				trace_get_wire_length(packet2),
				trace_get_wire_length(packet2)-trace_get_wire_length(packet));
			printf("link\t%d\t%d\n",
				trace_get_link_type(packet),
				trace_get_link_type(packet2));
			abort();
		}

		if (time_changed(packet, packet2)) {
			error = 1;
			break;
		}

	}
	if (trace_read_packet(trace2,packet2)>0) {
		printf("Extra packets after EOF\n");
		error=1;
	}
	trace_destroy(trace);
	trace_destroy(trace2);
	trace_destroy_packet(packet);
	trace_destroy_packet(packet2);

        printf("snapped %d packets\n", count);

        return error;
}
