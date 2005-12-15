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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_ether.h>

//extern "C" {
#include "dagformat.h"
#include "libtrace.h"
//}

struct libtrace_t *trace;
int                _fcs_bits = 32;
#define SCANSIZE 4096
char buffer[SCANSIZE];

struct network_id {
    uint32_t network;
    uint32_t netmask;
    struct network_id *next;
} *head = NULL;


/* one big glorious function */
int main(int argc, char *argv[]) {

    char *uri;
    int psize = 0;
    char *filename;
    FILE* input;
    
    struct pcap_pkthdr *header;
    struct libtrace_packet_t *packet = trace_create_packet();
    unsigned long seconds, subseconds;
    unsigned short rlen, lctr, wlen, offset, pad;
    unsigned char type, flags;
    struct network_id* locals;
    uint32_t address = 0;
    uint32_t netmask = 0;
    int data_size;
    struct libtrace_tcp *tcpptr = 0;
    int octets[4];
    int hlen;
    struct libtrace_ip *ipptr;

    
    // 2 parameters only, both neccessary
    if (argc == 3) {
	uri = strdup(argv[1]);
	filename = strdup(argv[2]);
    }
    else
    {
	// this message isnt very good
	fprintf(stderr, 
		"Usage: %s <source> <local_list>\n"
		"\n"
		"  <source> is a libtrace pcap uri, eg:\n"
		"	pcapint:eth0\n"
		"	pcap:/path/to/trace.pcap\n"
		"  <local_list> is the name of a file which contains pairs of networks\n"
		"  and netmasks for internal networks, one per line\n"
		"  eg:\n"
		"	192.168.0.0 255.255.255.0\n"
		"	192.168.1.0 255.255.255.0\n",
		argv[0]);
	exit(1);
    }
    //---------------------------------------------------------------------

    // open list of internal networks
    if( (input = fopen(filename, "r")) == NULL )
	        return -1;

    // read the network/mask pairs in
    while(1)
    {
	int num = fscanf(input,"%d.%d.%d.%d"
		,&octets[0],&octets[1],&octets[2],&octets[3]);

	// might as well do some error checking, give a message
	if(num != 4)
	    if(num < 1)
		break;
	    else
	    {
		fprintf(stderr, "Error reading network in networks file\n");
		exit(1);
	    }
	
	// pack the bytes into a single number
	for(int i=0; i<4; i++)
	{
	    address = address << 8;
	    address = address | octets[i];
	}

    	if( (fscanf(input,"%d.%d.%d.%d"
			,&octets[0],&octets[1],&octets[2],&octets[3])) != 4)
	{
	    fprintf(stderr, "Error reading netmask in networks file\n");
	    exit(1);
	}
	for(int i=0; i<4; i++)
	{
	    netmask = netmask << 8;
	    netmask = netmask | octets[i];
	}

	// tack this new address onto the front of the list
	network_id *newId = new network_id;
	newId->network = address;
	newId->netmask = netmask;
	newId->next = head;
	head = newId;
    }
    fclose(input);
    //----------------------------------------------------------------------

    // create an trace to the given uri
    trace = trace_create(uri);

    for (;;) {
	if ((psize = trace_read_packet(trace, &packet)) 
		== -1) {
	    // terminate
	    break;
	}
	// buffer returned is pcap-->ethernet-->upperlayers
	header = (struct pcap_pkthdr*)packet.buffer;

	// if this isnt an ip packet, ignore it
	if(! ((packet.buffer + sizeof(struct pcap_pkthdr))[12] == 8 &&
	    (packet.buffer + sizeof(struct pcap_pkthdr))[13] == 0))
	    continue;
	

	ipptr = trace_get_ip(&packet);
	hlen = ipptr->ip_hl*4;

	// work out how much packet we need...ethernet + ip + whatever
	switch(ipptr->ip_p)
	{
	    case 1: data_size = 14 + hlen; break;
	    case 6: tcpptr = (struct libtrace_tcp *) ((uint8_t *)ipptr + hlen);
		    data_size = 14 + hlen + (tcpptr->doff*4); break;
	    case 17: data_size = 14 + hlen + 8; break;
	    default: data_size = 14 + (ipptr->ip_hl*4); break;
	};

	// start making the erf header
	subseconds = (unsigned long)header->ts.tv_usec;
	seconds = (unsigned long)header->ts.tv_sec;
	fwrite(&subseconds, 4, 1, stdout);
	fwrite(&seconds, 4, 1, stdout);

	// type is always ethernet afaic
	type = 2;
	fwrite(&type, 1, 1, stdout);

	// set the direction based on the list of local addresses
	locals = head;
	while(locals != NULL)
	{
	    if((locals->netmask&ntohl(ipptr->ip_src.s_addr)) == locals->network)
	    {
		flags = 0;
		break;
	    }
	    locals = locals->next;
	}
	
	// address didnt match any in list, so its foreign
	if(locals == NULL)
	    flags = 1;

	// 8 = truncated record, 4 = varying record lengths...
	//flags = flags + 12;//XXX

	// flags is only being used for interface
	fwrite(&flags, 1, 1, stdout);

	// rlen = length of packet that we will keep + dag header
	rlen = htons(data_size+18);
	fwrite(&rlen, 2, 1, stdout);
	
	// loss counter can stay at zero
	lctr = 0;
	fwrite(&lctr, 2, 1, stdout);

	// this is total length of packet that we saw I think
	//wlen = htons(data_size);
	wlen = htons(header->len);//XXX
	fwrite(&wlen, 2, 1, stdout);

	// never have an offset
	offset = 0;
	fwrite(&offset, 1, 1, stdout);

	// no padding
	pad = 0;
	fwrite(&pad, 1, 1, stdout);
	// 18 bytes of header so far

	// write as much of the packet as we need (just the headers)
	fwrite(packet.buffer + sizeof(pcap_pkthdr), 1, data_size, stdout);
    }

    trace_destroy(trace);
    return 0;
}

