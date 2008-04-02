/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008 The University of Waikato, Hamilton, New Zealand.
 * Authors: Perry Lorier 
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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>


struct libtrace_format_data_t {
	int fd;
	int snaplen;
	int promisc;
	void *buffer;
	void *bufptr;
	unsigned int buffersize;
	int remaining;
	unsigned int linktype;
	struct bpf_stat stats;
	int stats_valid;
};

#define FORMATIN(x) ((struct libtrace_format_data_t*)((x->format_data)))

#define BPFHDR(x) ((struct bpf_hdr *)((x)->header))

static int bpf_init_input(libtrace_t *libtrace) 
{
	libtrace->format_data = (struct libtrace_format_data_t *)
		malloc(sizeof(struct libtrace_format_data_t));
	FORMATIN(libtrace)->fd = -1;
	FORMATIN(libtrace)->promisc = 0;
	FORMATIN(libtrace)->snaplen = 65536;
	FORMATIN(libtrace)->stats_valid = 0;

	return 0;
}

static int bpf_start_input(libtrace_t *libtrace)
{
	int bpfid=0;
	struct bpf_version bv;
	struct ifreq ifr;
	unsigned int v;

	/* Find and open a bpf device */
	do {
		char buffer[64];
		snprintf(buffer,sizeof(buffer),"/dev/bpf%d", bpfid);
		bpfid++;
		
		FORMATIN(libtrace)->fd = open(buffer, O_RDONLY);
	} while(FORMATIN(libtrace)->fd == -1 && errno == EBUSY);

	if (FORMATIN(libtrace)->fd == -1) {
		trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,
				"No free bpf devices");
		return -1;
	}

	/* Check the BPF Version is ok */
	if (ioctl(FORMATIN(libtrace)->fd, BIOCVERSION, &bv) == -1) {
		trace_set_err(libtrace,errno,
				"Failed to read the bpf version");
		close(FORMATIN(libtrace)->fd);
		return -1;
	}

	if (bv.bv_major != BPF_MAJOR_VERSION) {
		trace_set_err(libtrace,errno, 
			"Unknown kernel BPF version (%d.%d, libtrace requires at least %d.%d)",
			bv.bv_major,
			bv.bv_minor,
			BPF_MAJOR_VERSION,
			BPF_MINOR_VERSION);
		close(FORMATIN(libtrace)->fd);
		return -1;
	}

	if (bv.bv_minor < BPF_MINOR_VERSION) {
		trace_set_err(libtrace,errno, "Kernel version too old (%d.%d, libtrace requires at least %d.%d)",
			bv.bv_major,
			bv.bv_minor,
			BPF_MAJOR_VERSION,
			BPF_MINOR_VERSION);
		close(FORMATIN(libtrace)->fd);
		return -1;
	}

	/* We assume the default kernel buffer size is sufficient. */
	if (ioctl(FORMATIN(libtrace)->fd, BIOCGBLEN,
			&FORMATIN(libtrace)->buffersize)==-1) {
		trace_set_err(libtrace,errno,"Failed to find buffer length");
		close(FORMATIN(libtrace)->fd);
		return -1;
	}

	FORMATIN(libtrace)->buffer = malloc(FORMATIN(libtrace)->buffersize);
	FORMATIN(libtrace)->bufptr = FORMATIN(libtrace)->buffer;
	FORMATIN(libtrace)->remaining = 0;

	/* attach to the device */
	strncpy(ifr.ifr_name, libtrace->uridata, sizeof(ifr.ifr_name));
	if (ioctl(FORMATIN(libtrace)->fd, BIOCSETIF, &ifr) == -1) {
		trace_set_err(libtrace,errno,"Failed to attach");
		close(FORMATIN(libtrace)->fd);
		return -1;
	}

	if (ioctl(FORMATIN(libtrace)->fd, BIOCGDLT,
			 &FORMATIN(libtrace)->linktype) == -1) {
		trace_set_err(libtrace,errno,"Failed to retrieve link type");
		close(FORMATIN(libtrace)->fd);
		return -1;
	}
	
	/* TODO: If BIOCGDLTLIST exists then we should perhaps do something
	 *       with it.  We don't have the same concept of multiple DLT's
         *       as pcap does.  We grab the rawest possible thing and then
	 *	 decode packets by understanding the protocols.  So perhaps
	 *	 we should setup a rating of DLT's that we'll prefer in order.
	 *       For example we should try and get 802.11 frames rather than
	 *       802.3 frames.  The general rule should be "whatever actually
	 *       went over the air", although of course if we don't support
	 *       what went over the air we should fall back to something we
	 *       /do/ support.
	 */
	
	/* Using timeouts seems sucky.  We'll always use immediate mode.  We
         * pray the kernel is smart enough that if a another packet arrives
         * while we're processing this one that it will buffer them into it's
	 * kernel buffer so we can recieve packets later. (It'll need to do this
	 * to deal with us spending time processing the last 'n' packets anyway)
	 */
	
	v=1;
	if (ioctl(FORMATIN(libtrace)->fd, BIOCIMMEDIATE, &v) == -1) {
		trace_set_err(libtrace,errno,"Failed to set immediate mode");
		close(FORMATIN(libtrace)->fd);
		return -1;
	}

	if (FORMATIN(libtrace)->promisc) {
		if (ioctl(FORMATIN(libtrace)->fd, BIOCPROMISC, NULL) == -1) {
			trace_set_err(libtrace,errno,
				"Failed to set promisc mode");
			close(FORMATIN(libtrace)->fd);
			return -1;

		}
	}

	FORMATIN(libtrace)->stats_valid = 0;

	/* TODO: we should always set a bpf filter for snapping */

	/* We're done! */
	return 0;
}

static uint64_t bpf_get_received_packets(libtrace_t *trace)
{
	if (trace->format_data == NULL)
		return (uint64_t)-1;

	if (FORMATIN(trace)->fd == -1) {
		/* Almost certainly a 'dead' trace so there is no socket
		 * for us to query */
		return (uint64_t) -1;
	}
	/* If we're called with stats_valid == 0, or we're called again
	 * then refresh the stats.  Don't refresh the stats if we're called
	 * immediately after get_dropped_packets
	 */
	if ((FORMATIN(trace)->stats_valid & 1)
		|| (FORMATIN(trace)->stats_valid == 0)) {
		ioctl(FORMATIN(trace)->fd, BIOCGSTATS, &FORMATIN(trace)->stats);
		FORMATIN(trace)->stats_valid |= 1;
	}

	return FORMATIN(trace)->stats.bs_recv;
}

static uint64_t bpf_get_dropped_packets(libtrace_t *trace)
{
	if (trace->format_data == NULL)
		return (uint64_t)-1;

	if (FORMATIN(trace)->fd == -1) {
		/* Almost certainly a 'dead' trace so there is no socket
		 * for us to query */
		return (uint64_t) -1;
	}
	/* If we're called with stats_valid == 0, or we're called again
	 * then refresh the stats.  Don't refresh the stats if we're called
	 * immediately after get_received_packets
	 */
	if ((FORMATIN(trace)->stats_valid & 2) 
		|| (FORMATIN(trace)->stats_valid == 0)) {
		ioctl(FORMATIN(trace)->fd, BIOCGSTATS, &FORMATIN(trace)->stats);
		FORMATIN(trace)->stats_valid |= 2;
	}

	return FORMATIN(trace)->stats.bs_drop;
}

static int bpf_pause_input(libtrace_t *libtrace)
{
	close(FORMATIN(libtrace)->fd);
	FORMATIN(libtrace)->fd=-1;

	return 0;
}

static int bpf_fin_input(libtrace_t *libtrace) 
{
	free(libtrace->format_data);
	return 0;
}

static int bpf_config_input(libtrace_t *libtrace,
		trace_option_t option,
		void *data)
{
	switch(option) {
		case TRACE_OPTION_SNAPLEN:
			FORMATIN(libtrace)->snaplen=*(int*)data;
			return 0;
		case TRACE_OPTION_PROMISC:
			FORMATIN(libtrace)->promisc=*(int*)data;
			return 0;
		case TRACE_OPTION_FILTER:
			/* We don't support bpf filters in any special way
			 * so return an error and let libtrace deal with
			 * emulating it
			 */
			break;
		case TRACE_OPTION_META_FREQ:
			/* No meta-data for this format */
			break;
		case TRACE_OPTION_EVENT_REALTIME:
			/* captures are always realtime */
			break;

		/* Avoid default: so that future options will cause a warning
		 * here to remind us to implement it, or flag it as
		 * unimplementable
		 */
	}
	trace_set_err(libtrace,TRACE_ERR_UNKNOWN_OPTION,
			"Unknown option %i", option);
	return -1;
}

static int bpf_prepare_packet(libtrace_t *libtrace, libtrace_packet_t *packet,
		void *buffer, libtrace_rt_types_t rt_type, uint32_t flags) {
        if (packet->buffer != buffer &&
                        packet->buf_control == TRACE_CTRL_PACKET) {
                free(packet->buffer);
        }

        if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER) {
                packet->buf_control = TRACE_CTRL_PACKET;
        } else
                packet->buf_control = TRACE_CTRL_EXTERNAL;


        packet->buffer = buffer;
        packet->header = buffer;
	packet->type = rt_type;

	/* Find the payload */
	/* TODO: Pcap deals with a padded FDDI linktype here */
	packet->payload=(char *)buffer + BPFHDR(packet)->bh_hdrlen;

	if (libtrace->format_data == NULL) {
		if (bpf_init_input(libtrace))
			return -1;
	}

	return 0;
}
	
static int bpf_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) 
{
	uint32_t flags = 0;
	
	/* Fill the buffer */
	if (FORMATIN(libtrace)->remaining<=0) {
		int ret;

		ret=read(FORMATIN(libtrace)->fd,
			FORMATIN(libtrace)->buffer,
			FORMATIN(libtrace)->buffersize);

		if (ret == -1) {
			trace_set_err(libtrace,errno,"Failed to read");
			return -1;
		}

		if (ret == 0) {
			/* EOF */
			return 0;
		}

		FORMATIN(libtrace)->remaining=ret;
		FORMATIN(libtrace)->bufptr=
				FORMATIN(libtrace)->buffer;
	}
	flags |= TRACE_PREP_DO_NOT_OWN_BUFFER;
	/* Read one packet out */
	
	if (packet->buf_control == TRACE_CTRL_PACKET)
		free(packet->buffer);

	if (bpf_prepare_packet(libtrace, packet, FORMATIN(libtrace)->bufptr,
		TRACE_RT_DATA_BPF, flags)) {
		return -1;
	}
	

	/* Now deal with any padding */
	FORMATIN(libtrace)->bufptr+=
		BPF_WORDALIGN(BPFHDR(packet)->bh_hdrlen
		+BPFHDR(packet)->bh_caplen);
	FORMATIN(libtrace)->remaining-=
		BPF_WORDALIGN(BPFHDR(packet)->bh_hdrlen
		+BPFHDR(packet)->bh_caplen);

	return BPFHDR(packet)->bh_datalen+BPFHDR(packet)->bh_hdrlen;
}

static libtrace_linktype_t bpf_get_link_type(const libtrace_packet_t *packet) {
	return pcap_linktype_to_libtrace(FORMATIN(packet->trace)->linktype);
}

static libtrace_direction_t bpf_get_direction(const libtrace_packet_t *packet) {
	/* BPF Sadly can't do direction tagging */
	return ~0;
}

static struct timeval bpf_get_timeval(const libtrace_packet_t *packet) 
{
	struct timeval tv;
	/* OpenBSD uses a bpf_timeval rather than a timeval so we must copy
	 * each timeval element individually rather than doing a structure
	 * assignment */
	tv.tv_sec = BPFHDR(packet)->bh_tstamp.tv_sec;
	tv.tv_usec = BPFHDR(packet)->bh_tstamp.tv_usec;

	return tv;
}

static int bpf_get_capture_length(const libtrace_packet_t *packet)
{
	/* BPF Doesn't include the FCS, we do. */
	return BPFHDR(packet)->bh_caplen+4;
}

static int bpf_get_wire_length(const libtrace_packet_t *packet) 
{
	return BPFHDR(packet)->bh_datalen+4;
}

static int bpf_get_framing_length(UNUSED 
		const libtrace_packet_t *packet) 
{
	return BPFHDR(packet)->bh_hdrlen;
}

static int bpf_get_fd(const libtrace_t *trace) {
	return FORMATIN(trace)->fd;
}

static void bpf_help() {
	printf("bpf format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tbpf:\n");
	printf("\n");
	return;
}
static struct libtrace_format_t bpf = {
	"bpf",
	"$Id$",
	TRACE_FORMAT_BPF,
	bpf_init_input,	 	/* init_input */
	bpf_config_input,	/* config_input */
	bpf_start_input,	/* start_input */
	bpf_pause_input,	/* pause_input */
	NULL,			/* init_output */
	NULL,			/* config_output */
	NULL,			/* start_ouput */
	bpf_fin_input,		/* fin_input */
	NULL,			/* fin_output */
	bpf_read_packet,	/* read_packet */
	bpf_prepare_packet, 	/* prepare_packet */
	NULL,			/* fin_packet */
	NULL,			/* write_packet */
	bpf_get_link_type,	/* get_link_type */
	bpf_get_direction,	/* get_direction */
	NULL,			/* set_direction */
	NULL,			/* get_erf_timestamp */
	bpf_get_timeval,	/* get_timeval */
	NULL,			/* get_seconds */
	NULL,			/* seek_erf */
	NULL,			/* seek_timeval */
	NULL,			/* seek_seconds */
	bpf_get_capture_length,	/* get_capture_length */
	bpf_get_wire_length,	/* get_wire_length */
	bpf_get_framing_length,	/* get_framing_length */
	NULL,			/* set_capture_length */
	bpf_get_received_packets,/* get_received_packets */
	NULL,			/* get_filtered_packets */
	bpf_get_dropped_packets,/* get_dropped_packets */
	NULL,			/* get_captured_packets */
	bpf_get_fd,		/* get_fd */
	trace_event_device,	/* trace_event */
	bpf_help,		/* help */
	NULL
};

void bpf_constructor() {
	register_format(&bpf);
}
