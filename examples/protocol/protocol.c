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

#include <stdio.h> /* printf */
#include <netinet/in.h> /* ntohs */
#include <netdb.h>
#include "dagformat.h"
#include <getopt.h>

#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <linux/types.h>
//#include <linux/linkage.h>
//#define  access_ok(type,addr,size) 1

static inline unsigned short ip_fast_csum(unsigned char * iph,
					  unsigned int ihl) {
	unsigned int sum;

	__asm__ __volatile__("
	    movl (%1), %0
	    subl $4, %2
	    jbe 2f
	    addl 4(%1), %0
	    adcl 8(%1), %0
	    adcl 12(%1), %0
1:	    adcl 16(%1), %0
	    lea 4(%1), %1
	    decl %2
	    jne	1b
	    adcl $0, %0
	    movl %0, %2
	    shrl $16, %0
	    addw %w2, %w0
	    adcl $0, %0
	    notl %0
2:
	    "
	/* Since the input registers which are loaded with iph and ipl
	   are modified, we must also specify them as outputs, or gcc
	   will assume they contain their original values. */
	: "=r" (sum), "=r" (iph), "=r" (ihl)
	: "1" (iph), "2" (ihl));
	return(sum);
}

#define  IN_CHKSUM(IP)  ip_fast_csum((unsigned char *)(IP), 5)


#include "libtrace.h"

struct libtrace_t *trace;
struct libtrace_filter_t *filter;

char *buffer[4096];
uint64_t badchksum = 0;
char *uri = 0;
char *filterstring = 0;

int do_cksum = 0;
int loop = 0;
int do_w_cksum = 0;
uint64_t rxerr = 0;
static void usage();
static void parse_cmdline(int argc, char **argv);

int main(int argc, char **argv) {

	struct libtrace_ip *ipptr = 0;
	struct libtrace_packet_t packet;
	
        int psize;

	parse_cmdline(argc,argv);

	if (!uri) {
		printf("Incorrect usage: need a URI\n");
		usage(argv[0]);
	}
	do {
		trace = trace_create(uri);
		if (filterstring) {
			filter = trace_bpf_setfilter(filterstring);
		}

		for (;;) {
			if ((psize = trace_read_packet(trace, &packet)) <= 0) {
				// terminate
				break;
			}

			if (filter) {
				if (!trace_bpf_filter(filter,&packet)) {
					continue;
				}
			}
			ipptr = trace_get_ip(&packet);

			if (ipptr) {
				if(do_cksum && IN_CHKSUM(ipptr)) {
					badchksum ++;
				} else if (do_w_cksum && ipptr->ip_sum) {
					badchksum ++;
				} else {
					printf("%d:%d\n",ipptr->ip_p,trace_get_link_type(&packet));
				}
			}
		}
		if (do_cksum || do_w_cksum) {
			printf("Bad checksums seen: %llu\n",badchksum);
			printf("RX Errors seen: %llu\n",rxerr);
		}
		trace_destroy(trace);
	} while (loop);
        return 0;
}


static void usage(char *prog) {
	printf("usage: %s [-h] [-c | -w] [-u <uri>] [-f <filterstring>]\n",prog);
	printf("        -h		this help message\n");
	printf("        -c		perform ip checksum test\n");
	printf("        -w 		check WDCAPd ip checksum value\n");
	printf("        -u uri		uri to connect to\n");
	printf("	-f filterstring BPF filterstring to apply\n");
	printf("	-l 		loop the input\n");
	printf("\n");
	printf(" The use of -c and -w are exclusive: -c is used for normal traces, while -w applies to traces taken from the Waikato Capture point\n");
}

static void parse_cmdline(int argc, char **argv){
	int opt;
	if (argc == 1) {
		usage(argv[0]);
		exit(0);
	}
	
	while ((opt = getopt(argc,argv, "hcwu:f:l")) != EOF) {
		switch(opt) {
			case 'h':
				usage(argv[0]);
				exit(0);
			case 'c':
				do_cksum = 1;
				break;
			case 'w':
				do_w_cksum = 1;
				break;
			case 'u':
				uri = strdup(optarg);
				break;
			case 'f':
				filterstring = strdup(optarg);
				break;
			case 'l':
				loop = 1;
				break;
			default:
				usage(argv[0]);
				exit(0);
		}

	}

	if (do_cksum && do_w_cksum) {
		usage(argv[0]);
		exit(0);
	}

}
