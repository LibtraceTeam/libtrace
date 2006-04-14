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
 * $Id: format_template.c,v 1.13 2005/11/22 23:38:56 dlawson Exp $
 *
 */

#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "config.h"
#include "stdlib.h"

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
# error "Can't find inttypes.h"
#endif 

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

static struct libtrace_format_t linuxnative;

struct libtrace_format_data_t {
	int fd;
};

struct libtrace_linuxnative_header {
	struct timeval ts;
	int wirelen;
	struct sockaddr_ll hdr;
};

#define FORMAT(x) ((struct libtrace_format_data_t*)(x))

static int linuxnative_init_input(struct libtrace_t *libtrace) {
	struct sockaddr_ll addr;
	libtrace->format_data = (struct libtrace_format_data_t *)
		malloc(sizeof(struct libtrace_format_data_t));
	FORMAT(libtrace->format_data)->fd = 
				socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (FORMAT(libtrace->format_data)->fd==-1) {
		free(libtrace->format_data);
		return -1;
	}
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (strlen(libtrace->uridata)) {
		addr.sll_ifindex = if_nametoindex(libtrace->uridata);
		if (addr.sll_ifindex == 0) {
			close(FORMAT(libtrace->format_data)->fd);
			free(libtrace->format_data);
			return -1;
		}
	}
	else {
		addr.sll_ifindex = 0;
	}
	if (bind(FORMAT(libtrace->format_data)->fd,
				(struct sockaddr*)&addr,
				sizeof(addr))==-1) {
		free(libtrace->format_data);
		return -1;
	}
	/* enable promisc mode when listening on an interface */
	if (addr.sll_ifindex!=0) {
		struct packet_mreq mreq;
		socklen_t socklen = sizeof(mreq);
		mreq.mr_ifindex = addr.sll_ifindex;
		mreq.mr_type = PACKET_MR_PROMISC;
		setsockopt(FORMAT(libtrace->format_data)->fd,
				SOL_PACKET,
				PACKET_ADD_MEMBERSHIP,
				&mreq,
				socklen);
	}

	return 0;
}

static int linuxnative_fin_input(struct libtrace_t *libtrace) {
	close(FORMAT(libtrace->format_data)->fd);
	free(libtrace->format_data);
	return 0;
}

static int linuxnative_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	struct libtrace_linuxnative_header *hdr;
	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
		packet->buf_control = TRACE_CTRL_PACKET;
	}

	packet->header = packet->buffer;
	packet->type = RT_DATA_LINUX_NATIVE;
	packet->payload = packet->buffer+sizeof(*hdr);

	hdr=(void*)packet->buffer;
	socklen_t socklen=sizeof(hdr->hdr);
	hdr->wirelen = recvfrom(FORMAT(libtrace->format_data)->fd,
			(void*)packet->payload,
			LIBTRACE_PACKET_BUFSIZE-sizeof(*hdr),
			MSG_TRUNC,
			(void *)&hdr->hdr,
			&socklen);

	if (hdr->wirelen==-1)
		return -1;

	if (ioctl(FORMAT(libtrace->format_data)->fd,SIOCGSTAMP,&hdr->ts)==-1)
		perror("ioctl(SIOCGSTAMP)");

	return hdr->wirelen+sizeof(*hdr);
}

static libtrace_linktype_t linuxnative_get_link_type(const struct libtrace_packet_t *packet) {
	switch htons((((struct libtrace_linuxnative_header*)(packet->buffer))->hdr.sll_protocol)) {
		case ETH_P_IP:
		case ETH_P_IPV6:
		case ETH_P_ARP:
			return TRACE_TYPE_ETH;
		default: /* shrug, beyond me! */
			printf("unknown type %x\n",(((struct libtrace_linuxnative_header*)(packet->buffer))->hdr.sll_protocol));
			return -1;
	}
}

static int8_t linuxnative_get_direction(const struct libtrace_packet_t *packet) {
	switch (((struct libtrace_linuxnative_header*)(packet->buffer))->hdr.sll_pkttype) {
		case PACKET_OUTGOING:
			return 0;
		default:
			return 1;
	}
}

static struct timeval linuxnative_get_timeval(const struct libtrace_packet_t *packet) { 
	return ((struct libtrace_linuxnative_header*)(packet->buffer))->ts;
}

static int linuxnative_get_wire_length(const struct libtrace_packet_t *packet) {
	return ((struct libtrace_linuxnative_header*)(packet->buffer))->wirelen;
}

static int linuxnative_get_framing_length(const struct libtrace_packet_t *packet) {
	return sizeof(struct libtrace_linuxnative_header);
}

static size_t linuxnative_set_capture_length(struct libtrace_packet_t *packet,size_t size) {
	return -1;
}

static int linuxnative_get_fd(const libtrace_t *trace) {
	return FORMAT(trace->format_data)->fd;
}

static void linuxnative_help() {
	printf("linuxnative format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tint:\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tnone\n");
	printf("\n");
	return;
}
static struct libtrace_format_t linuxnative = {
	"int",
	"$Id: format_linuxnative.c,v 1.13 2005/11/22 23:38:56 dlawson Exp $",
	TRACE_FORMAT_LINUX_NATIVE,
	linuxnative_init_input,	 	/* init_input */
	NULL,				/* config_input */
	NULL,				/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_ouput */
	linuxnative_fin_input,		/* fin_input */
	NULL,				/* fin_output */
	linuxnative_read_packet,	/* read_packet */
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	linuxnative_get_link_type,	/* get_link_type */
	linuxnative_get_direction,	/* get_direction */
	NULL,				/* set_direction */
	NULL,				/* get_erf_timestamp */
	linuxnative_get_timeval,	/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	NULL,				/* get_capture_length */
	linuxnative_get_wire_length,	/* get_wire_length */
	linuxnative_get_framing_length,	/* get_framing_length */
	NULL,				/* set_capture_length */
	linuxnative_get_fd,		/* get_fd */
	trace_event_trace,		/* trace_event */
	linuxnative_help,		/* help */
	NULL
};

void __attribute__((constructor)) linuxnative_constructor() {
	register_format(&linuxnative);
}
