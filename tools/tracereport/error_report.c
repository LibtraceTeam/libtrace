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


#include <netdb.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdio.h>
#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

static uint64_t rx_errors = 0;
static uint64_t ip_errors = 0;
static uint64_t tcp_errors = 0;

void error_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	struct libtrace_tcp *tcp = trace_get_tcp(packet);
	void *link = trace_get_packet_buffer(packet,NULL,NULL);
	if (!link) {
		++rx_errors;
	}
	
	/* This isn't quite as simple as it seems.
	 *
	 * If the packets were captured via wdcap's anonymisation module,
	 * the checksum is set to 0 when it is correct and 1 if incorrect.
	 *
	 * If a different capture method is used, there's a good chance the
	 * checksum has not been altered
	 */
	if (ip) {
		if (ntohs(ip->ip_sum)!=0)
			++ip_errors;
	}
	if (tcp) {
		if (ntohs(tcp->check)!=0)
			++tcp_errors;
	}
}

void error_report(void)
{
	FILE *out = fopen("error.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	
	fprintf(out, "RX Errors: %" PRIu64 "\n",rx_errors);
	fprintf(out, "IP Checksum errors: %" PRIu64 "\n",ip_errors);
	/*printf("TCP Checksum errors: %" PRIu64 "\n",tcp_errors); */

	fclose(out);
}
