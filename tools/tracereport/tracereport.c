/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson 
 *          Perry Lorier 
 *          Josef Vodanovich
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

/* This program takes a series of traces and bpf filters and outputs how many
 * bytes/packets
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>

#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

struct libtrace_t *trace;
uint32_t reports_required = 0;
int packets_read = 0;

static volatile int done=0;

static void cleanup_signal(int sig UNUSED)
{
	done=1;
	trace_interrupt();
}

/* Process a trace, counting packets that match filter(s) */
static void run_trace(char *uri, libtrace_filter_t *filter, int count) 
{
	struct libtrace_packet_t *packet = trace_create_packet();

	/* Already read the maximum number of packets - don't need to read
	 * anything from this trace */
	if ((count >= 0 && packets_read >= count) || done)
		return;

	trace = trace_create(uri);
	
	if (trace_is_err(trace)) {
		trace_perror(trace,"trace_create");
		return;
	}

	if (filter) {
		trace_config(trace,TRACE_OPTION_FILTER,filter);
	}

	if (trace_start(trace)==-1) {
		trace_perror(trace,"trace_start");
		return;
	}

	while (1) {
		int psize;
		
		if (count >= 0 && packets_read >= count)
			break;
		if (done)
			break;
		if ((psize = trace_read_packet(trace, packet)) <1) {
			break;
		}
		if (reports_required & REPORT_TYPE_MISC)
			misc_per_packet(packet);
		if (reports_required & REPORT_TYPE_ERROR)
			error_per_packet(packet);
		if (reports_required & REPORT_TYPE_PORT)
			port_per_packet(packet);
		if (reports_required & REPORT_TYPE_PROTO)
			protocol_per_packet(packet);
		if (reports_required & REPORT_TYPE_TOS)
			tos_per_packet(packet);
		if (reports_required & REPORT_TYPE_TTL)
			ttl_per_packet(packet);
		if (reports_required & REPORT_TYPE_FLOW)
			flow_per_packet(packet);
		if (reports_required & REPORT_TYPE_TCPOPT)
			tcpopt_per_packet(packet);
		if (reports_required & REPORT_TYPE_SYNOPT)
			synopt_per_packet(packet);
		if (reports_required & REPORT_TYPE_NLP)
			nlp_per_packet(packet);
		if (reports_required & REPORT_TYPE_DIR)
			dir_per_packet(packet);
		if (reports_required & REPORT_TYPE_ECN)
			ecn_per_packet(packet);
		if (reports_required & REPORT_TYPE_TCPSEG)
			tcpseg_per_packet(packet);

		packets_read ++;
	}
	if (reports_required & REPORT_TYPE_DROPS)
		drops_per_trace(trace);
	trace_destroy(trace);
}

static void usage(char *argv0)
{
	fprintf(stderr,"Usage:\n"
	"%s flags traceuri [traceuri...]\n"
	"-f --filter=bpf	\tApply BPF filter. Can be specified multiple times\n"
	"-c --count=N		Stop after reading N packets\n"
	"-e --error		Report packet errors (e.g. checksum failures, rxerrors)\n"
	"-F --flow		Report flows\n"
	"-m --misc		Report misc information (start/end times, duration, pps)\n"
	"-P --protocol		Report transport protocols\n"
	"-p --port		Report port numbers\n"
	"-T --tos		Report IP TOS\n"
	"-t --ttl		Report IP TTL\n"
	"-O --tcpoptions	\tReport TCP Options\n"
	"-o --synoptions	\tReport TCP Options seen on SYNs\n"
	"-n --nlp		Report network layer protocols\n"
	"-d --direction		Report direction\n"
	"-C --ecn		Report TCP ECN information\n"
	"-s --tcpsegment	\tReport TCP segment size\n"
	"-H --help		Print libtrace runtime documentation\n"
	,argv0);
	exit(1);
}

int main(int argc, char *argv[]) {

	int i;
	int opt;
	char *filterstring=NULL;
	struct sigaction sigact;
	int count = -1;

	libtrace_filter_t *filter = NULL;/*trace_bpf_setfilter(filterstring); */

	while (1) {
		int option_index;
		struct option long_options[] = {
			{ "count", 		1, 0, 'c' },
			{ "ecn",		0, 0, 'C' },
			{ "direction", 		0, 0, 'd' },
			{ "drops",		0, 0, 'D' },
			{ "error",		0, 0, 'e' },
			{ "flow", 		0, 0, 'F' },
			{ "filter",		1, 0, 'f' },
			{ "help",		0, 0, 'H' },
			{ "misc",		0, 0, 'm' },
			{ "nlp",		0, 0, 'n' },
			{ "tcpoptions",		0, 0, 'O' },
			{ "synoptions",		0, 0, 'o' },
			{ "protocol", 		0, 0, 'P' },
			{ "port",		0, 0, 'p' },
			{ "tcpsegment", 	0, 0, 's' },
			{ "tos",		0, 0, 'T' },
			{ "ttl", 		0, 0, 't' },
			{ NULL, 		0, 0, 0 }
		};
		opt = getopt_long(argc, argv, "Df:HemFPpTtOondCsc:", 
				long_options, &option_index);
		if (opt == -1)
			break;
		
		switch (opt) {
			case 'c':
				count = atoi(optarg);
				break;
			case 'C':
				reports_required |= REPORT_TYPE_ECN;
				break;
			case 'd':
				reports_required |= REPORT_TYPE_DIR;
				break;
			case 'D':
				reports_required |= REPORT_TYPE_DROPS;
				break;
			case 'e':
				reports_required |= REPORT_TYPE_ERROR;
				break;
			case 'F':
				reports_required |= REPORT_TYPE_FLOW;
				break;
			case 'f':
				filterstring = optarg;
				break;
			case 'H':
				usage(argv[0]);
				break;
			case 'm':
				reports_required |= REPORT_TYPE_MISC;
				break;
			case 'n':
				reports_required |= REPORT_TYPE_NLP;
				break;
			case 'O':
				reports_required |= REPORT_TYPE_TCPOPT;
				break;
			case 'o':
				reports_required |= REPORT_TYPE_SYNOPT;
				break;
			case 'P':
				reports_required |= REPORT_TYPE_PROTO;
				break;
			case 'p':
				reports_required |= REPORT_TYPE_PORT;
				break;
			case 's':
				reports_required |= REPORT_TYPE_TCPSEG;
				break;
			case 'T':
				reports_required |= REPORT_TYPE_TOS;
				break;
			case 't':
				reports_required |= REPORT_TYPE_TTL;
				break;
			default:
				usage(argv[0]);
		}
	}

	/* Default to all reports, instead of no reports at all.  It's annoying
	 * waiting for 10 minutes for a trace to process then discover you 
	 * forgot to ask for any reports!
	 */
	if (reports_required == 0) {
		reports_required = ~0;

		/* Except we might want to not do the flow report, because 
		 * that can be rather resource-intensive */
		reports_required &= ~REPORT_TYPE_FLOW;
	}


	if (filterstring) {
		filter = trace_create_filter(filterstring);
	}

	sigact.sa_handler = cleanup_signal;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_RESTART;

	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
		
	
	for(i=optind;i<argc;++i) {
		/* This is handy for knowing how far through the traceset
		 * we are - printing to stderr because we use stdout for
		 * genuine output at the moment */
		fprintf(stderr, "Reading from trace: %s\n", argv[i]);
		run_trace(argv[i],filter, count);
	}

	if (reports_required & REPORT_TYPE_MISC)
		misc_report();
	if (reports_required & REPORT_TYPE_ERROR)
		error_report();
	if (reports_required & REPORT_TYPE_FLOW)
		flow_report();
	if (reports_required & REPORT_TYPE_TOS)
		tos_report();
	if (reports_required & REPORT_TYPE_PROTO)
		protocol_report();
	if (reports_required & REPORT_TYPE_PORT)
		port_report();
	if (reports_required & REPORT_TYPE_TTL)
		ttl_report();	
	if (reports_required & REPORT_TYPE_TCPOPT)
		tcpopt_report();
	if (reports_required & REPORT_TYPE_SYNOPT)
		synopt_report();
	if (reports_required & REPORT_TYPE_NLP)
		nlp_report();
	if (reports_required & REPORT_TYPE_DIR)
		dir_report();
	if (reports_required & REPORT_TYPE_ECN)
		ecn_report();
	if (reports_required & REPORT_TYPE_TCPSEG)
		tcpseg_report();
	if (reports_required & REPORT_TYPE_DROPS)
		drops_report();
	return 0;
}
