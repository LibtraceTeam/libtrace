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

#ifdef HAVE_PCAP
#include "config.h"

#ifndef HAVE_PCAP_NEXT_EX
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <libtrace.h>
#include <stdlib.h>

/* Custom implementation of pcap_next_ex as some versions of PCAP do not have
 * it */

struct pcap_data_t {
	struct pcap_pkthdr *header;
	u_char *payload;
};


static struct pcap_data_t pcap_data;

static void trace_pcap_handler(u_char *user, const struct pcap_pkthdr *pcaphdr,const u_char *pcappkt) {
        struct pcap_data_t *packet = (struct pcap_data_t *)user;

	/* pcaphdr and pcappkt don't seem to persist for particularly long
	 * so we need to memcpy them. Obviously, this spoils the whole
	 * zero-copy concept but if you're using outdated pcap libraries
	 * you deserve everything you get 
	 */
	memcpy(packet->header, pcaphdr, sizeof(struct pcap_pkthdr));
	memcpy(packet->payload, pcappkt, packet->header->len);
}


int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
                        const u_char **pkt_data) {

	int pcapbytes = 0;

	pcap_data.header = *pkt_header;
	pcap_data.payload = *pkt_data;

	pcapbytes = pcap_dispatch(p, 1, &trace_pcap_handler,
                       (u_char *) &pcap_data);

	if (pcapbytes == -1)
		return -1;

	if (pcapbytes == 0 && pcap_file(p) != NULL)
		return -2;

	if (pcapbytes == 0)
		return 0;

        return 1;
}
#endif

#endif //HAVE_PCAP
