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
#include <stdlib.h>
#include "libtrace.h"
#include "tracereport.h"
#include "contain.h"
#include "report.h"

static uint64_t flow_count=0;

struct fivetuple_t {
	uint32_t ipa;
	uint32_t ipb;
	uint16_t porta;
	uint16_t portb;
	uint8_t prot;
};

static int fivetuplecmp(struct fivetuple_t a, struct fivetuple_t b)
{
	if (a.porta != b.porta) return a.porta-b.porta;
	if (a.portb != b.portb) return a.portb-b.portb;
	if (a.ipa != b.ipa) return a.ipa-b.ipa;
	if (a.ipb != b.ipb) return a.ipb-b.ipb;
	return a.prot - b.prot;
}

static int flowset_cmp(const splay *a, const splay *b);
SET_CREATE(flowset,struct fivetuple_t,fivetuplecmp)

void flow_per_packet(struct libtrace_packet_t *packet)
{
	struct libtrace_ip *ip = trace_get_ip(packet);
	struct fivetuple_t ft;
	if (!ip)
		return;
	ft.ipa=ip->ip_src.s_addr;
	ft.ipb=ip->ip_dst.s_addr;
	ft.porta=trace_get_source_port(packet);
	ft.portb=trace_get_destination_port(packet);
	ft.prot = 0;

	if (!SET_CONTAINS(flowset,ft)) {
		SET_INSERT(flowset,ft);
		flow_count++;
	}
}

void flow_report(void)
{
	FILE *out = fopen("flows.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	fprintf(out, "Flows: %" PRIu64 "\n",flow_count);
	fclose(out);
}
