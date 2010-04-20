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

#include "libtrace.h"

void iferr(libtrace_t *trace)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s\n",err.problem);
	exit(1);
}


int main(int argc, char *argv[]) {
	libtrace_t *trace;
	libtrace_packet_t *packet;
	int result;
	uint64_t tsft;
	uint16_t freq, tmp16;
	uint8_t flags, rate, sdbm, ndbm, sdb, antenna, tmp8;
	
	uint16_t total_freq, expected_freq = 24170;
	
	void *l;
	libtrace_linktype_t lt;
	trace = trace_create("pcapfile:traces/10_packets_radiotap.pcap");
	iferr(trace);

	trace_start(trace);
	iferr(trace);
	
	packet=trace_create_packet();

	trace_read_packet(trace, packet);

	l = trace_get_packet_buffer(packet, &lt,NULL);

	/* Check that the right linktype is being reported for this trace */
	assert(lt == TRACE_TYPE_80211_RADIO);

	/* Check that fields that exist in this trace are reported as 
	 * existing */
	assert(trace_get_wireless_tsft(l,lt,&tsft));
	assert(trace_get_wireless_rate(l,lt,&rate));
	assert(trace_get_wireless_freq(l,lt,&freq));
	assert(trace_get_wireless_signal_strength_dbm(l,lt,(int8_t *)&sdbm));
	assert(trace_get_wireless_noise_strength_dbm(l,lt,(int8_t *)&ndbm));
	assert(trace_get_wireless_signal_strength_db(l,lt,&sdb));
	assert(trace_get_wireless_antenna(l,lt,&antenna));

	/* Check that the fields that do not exist in this trace are
	 * reported as not existing */
	assert(!trace_get_wireless_noise_strength_db(l,lt,&tmp8));
	assert(!trace_get_wireless_tx_attenuation(l,lt,&tmp16));
	assert(!trace_get_wireless_tx_attenuation_db(l,lt,&tmp16));
	assert(!trace_get_wireless_tx_power_dbm(l,lt,(int8_t *)&tmp8));

	/* Check that the functions are returning the right values for
	 * this trace
	 * TODO: Check all fields :)
	 */
	total_freq = freq;
	
	while((result = trace_read_packet(trace, packet)) > 0) {
		/* This trace has no FCS at the end of packets, so ensure
		 * that wire-length is 4 bytes greater than capture length */
		int caplen = trace_get_capture_length(packet);
		int wirelen = trace_get_wire_length(packet);
		assert(wirelen == caplen + 4);
		if(trace_get_wireless_freq(l,lt,&freq)) 
			total_freq += freq;
	}

	assert(total_freq == expected_freq);

	trace_destroy_packet(packet);
	trace_destroy(trace);
		
	/* Now check that we don't process non-radiotap traces */
	
	trace = trace_create("pcapfile:traces/100_packets.pcap");
	iferr(trace);
	trace_start(trace);
	iferr(trace);
	packet = trace_create_packet();
	trace_read_packet(trace,packet);
	l = trace_get_packet_buffer(packet,&lt,NULL);
	assert(lt != TRACE_TYPE_80211_RADIO);

	assert(!trace_get_wireless_tsft(l,lt,&tsft));
	assert(!trace_get_wireless_rate(l,lt,&rate));
	assert(!trace_get_wireless_freq(l,lt,&freq));
	assert(!trace_get_wireless_signal_strength_dbm(l,lt,(int8_t *)&sdbm));
	assert(!trace_get_wireless_noise_strength_dbm(l,lt,(int8_t *)&ndbm));
	assert(!trace_get_wireless_signal_strength_db(l,lt,&sdb));
	assert(!trace_get_wireless_antenna(l,lt,&antenna));
	assert(!trace_get_wireless_noise_strength_db(l,lt,&tmp8));
	assert(!trace_get_wireless_tx_attenuation(l,lt,&tmp16));
	assert(!trace_get_wireless_tx_attenuation_db(l,lt,&tmp16));
	assert(!trace_get_wireless_tx_power_dbm(l,lt,(int8_t *)&tmp8));


	trace_destroy_packet(packet);
        trace_destroy(trace);
	return 0;
}
