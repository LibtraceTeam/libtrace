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

/* This format module deals with using the Linux Native capture format.
 *
 * Linux Native is a LIVE capture format.
 *
 * This format also supports writing which will write packets out to the 
 * network as a form of packet replay. This should not be confused with the 
 * RT protocol which is intended to transfer captured packet records between 
 * RT-speaking programs.
 */

#include "config.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "libtrace_arphrd.h"
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
# error "Can't find inttypes.h"
#endif

#include "format_linux_common.h"

#define SLL_HEADER_LENGTH 6

#ifdef HAVE_NETPACKET_PACKET_H

static bool linuxnative_can_write(libtrace_packet_t *packet) {
	/* Get the linktype */
        libtrace_linktype_t ltype = trace_get_link_type(packet);

        if (ltype == TRACE_TYPE_NONDATA) {
                return false;
        }
        if (ltype == TRACE_TYPE_CONTENT_INVALID) {
                return false;
        }
        if (ltype == TRACE_TYPE_PCAPNG_META) {
                return false;
        }
        if (ltype == TRACE_TYPE_ERF_META) {
                return false;
        }

        return true;
}

static int linuxnative_start_input(libtrace_t *libtrace)
{
	int ret = linuxcommon_start_input_stream(libtrace, FORMAT_DATA_FIRST);
	return ret;
}

#ifdef HAVE_PACKET_FANOUT
static int linuxnative_pstart_input(libtrace_t *libtrace) {
	return linuxcommon_pstart_input(libtrace, linuxcommon_start_input_stream);
}
#endif

static int linuxnative_start_output(libtrace_out_t *libtrace)
{
	FORMAT_DATA_OUT->fd = socket(PF_PACKET, SOCK_RAW, 0);
	if (FORMAT_DATA_OUT->fd==-1) {
		free(FORMAT_DATA_OUT);
		trace_set_err_out(libtrace, errno, "Failed to create raw socket");
		return -1;
	}

	return 0;
}

static int linuxnative_fin_output(libtrace_out_t *libtrace)
{
	close(FORMAT_DATA_OUT->fd);
	FORMAT_DATA_OUT->fd=-1;
	free(libtrace->format_data);
	return 0;
}
#endif /* HAVE_NETPACKET_PACKET_H */

static int linuxnative_prepare_packet(libtrace_t *libtrace UNUSED, 
		libtrace_packet_t *packet, void *buffer, 
		libtrace_rt_types_t rt_type, uint32_t flags) {

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
	packet->payload = (char *)buffer + 
		sizeof(struct libtrace_linuxnative_header);
	packet->type = rt_type;

	/*
	if (libtrace->format_data == NULL) {
		if (linuxnative_init_input(libtrace))
			return -1;
	}
	*/
	return 0;
	
}

#define LIBTRACE_MIN(a,b) ((a)<(b) ? (a) : (b))

/* 20 isn't enough on x86_64 */
#define CMSG_BUF_SIZE 128

#ifdef HAVE_NETPACKET_PACKET_H
inline static int linuxnative_read_stream(libtrace_t *libtrace,
                                          libtrace_packet_t *packet,
                                          struct linux_per_stream_t *stream,
                                          libtrace_message_queue_t *queue)
{
	struct libtrace_linuxnative_header *hdr;
	struct msghdr msghdr;
	struct iovec iovec;
	unsigned char controlbuf[CMSG_BUF_SIZE];
	struct cmsghdr *cmsg;
	int snaplen;

	uint32_t flags = 0;
	fd_set readfds;
	struct timeval tout;
	int ret;
	
	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
		if (!packet->buffer) {
			perror("Cannot allocate buffer");
		}
	}

	flags |= TRACE_PREP_OWN_BUFFER;
	
	packet->type = TRACE_RT_DATA_LINUX_NATIVE;

	hdr=(struct libtrace_linuxnative_header*)packet->buffer;
	snaplen=LIBTRACE_MIN(
			(int)LIBTRACE_PACKET_BUFSIZE-(int)sizeof(*hdr),
			(int)FORMAT_DATA->snaplen);
	/* Prepare the msghdr and iovec for the kernel to write the
	 * captured packet into. The msghdr will point to the part of our
	 * buffer reserved for sll header, while the iovec will point at
	 * the buffer following the sll header. */

	msghdr.msg_name = &hdr->hdr;
	msghdr.msg_namelen = sizeof(struct sockaddr_ll);

	msghdr.msg_iov = &iovec;
	msghdr.msg_iovlen = 1;

	msghdr.msg_control = &controlbuf;
	msghdr.msg_controllen = CMSG_BUF_SIZE;
	msghdr.msg_flags = 0;

	iovec.iov_base = (void*)(packet->buffer+sizeof(*hdr));
	iovec.iov_len = snaplen;

	// Check for a packet - TODO only Linux has MSG_DONTWAIT should use fctl O_NONBLOCK
	/* Try check ahead this should be fast if something is waiting  */
	hdr->wirelen = recvmsg(stream->fd, &msghdr, MSG_DONTWAIT | MSG_TRUNC);

	/* No data was waiting */
	if ((int) hdr->wirelen == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		/* Do message queue check or select */
		int message_fd = 0;
		int largestfd = stream->fd;

		/* Also check the message queue */
		if (queue) {
			message_fd = libtrace_message_queue_get_fd(queue);
			if (message_fd > largestfd)
				largestfd = message_fd;
		}
		do {
			/* Use select to allow us to time out occasionally to check if someone
			 * has hit Ctrl-C or otherwise wants us to stop reading and return
			 * so they can exit their program.
			 */
			tout.tv_sec = 0;
			tout.tv_usec = 500000;
			/* Make sure we reset these each loop */
			FD_ZERO(&readfds);
			FD_SET(stream->fd, &readfds);
			if (queue)
				FD_SET(message_fd, &readfds);

			ret = select(largestfd+1, &readfds, NULL, NULL, &tout);
			if (ret >= 1) {
				/* A file descriptor triggered */
				break;
			} else if (ret < 0 && errno != EINTR) {
				trace_set_err(libtrace, errno, "select");
				return -1;
			} else {
				if ((ret=is_halted(libtrace)) != -1)
					return ret;
                                /* If we dont have access to the queue we have to return
                                 * and let libtrace check */
                                if (!queue) {
                                    return READ_MESSAGE;
                                }
			}
		}
		while (ret <= 0);

		/* Message waiting? */
		if (queue && FD_ISSET(message_fd, &readfds))
			return READ_MESSAGE;

		/* We must have a packet */
		hdr->wirelen = recvmsg(stream->fd, &msghdr, MSG_TRUNC);
	}

	if (hdr->wirelen==~0U) {
		trace_set_err(libtrace,errno,"recvmsg");
		return -1;
	}

	hdr->caplen=LIBTRACE_MIN((unsigned int)snaplen,(unsigned int)hdr->wirelen);

	/* Extract the timestamps from the msghdr and store them in our
	 * linux native encapsulation, so that we can preserve the formatting
	 * across multiple architectures */

	for (cmsg = CMSG_FIRSTHDR(&msghdr);
			cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
			&& cmsg->cmsg_type == SO_TIMESTAMP
			&& cmsg->cmsg_len <= CMSG_LEN(sizeof(struct timeval))) {
			
			struct timeval *tv;
			tv = (struct timeval *)CMSG_DATA(cmsg);
			
			
			hdr->tv.tv_sec = tv->tv_sec;
			hdr->tv.tv_usec = tv->tv_usec;
			hdr->timestamptype = TS_TIMEVAL;
			break;
		} 
#ifdef SO_TIMESTAMPNS
		else if (cmsg->cmsg_level == SOL_SOCKET
			&& cmsg->cmsg_type == SO_TIMESTAMPNS
			&& cmsg->cmsg_len <= CMSG_LEN(sizeof(struct timespec))) {

			struct timespec *tv;
			tv = (struct timespec *)CMSG_DATA(cmsg);

			hdr->ts.tv_sec = tv->tv_sec;
			hdr->ts.tv_nsec = tv->tv_nsec;
			hdr->timestamptype = TS_TIMESPEC;
			break;
		}
#endif
	}

	/* Did we not get given a timestamp? Try to get one from the
	 * file descriptor directly */
	if (cmsg == NULL) {
		struct timeval tv;
		if (ioctl(stream->fd, SIOCGSTAMP,&tv)==0) {
			hdr->tv.tv_sec = tv.tv_sec;
			hdr->tv.tv_usec = tv.tv_usec;
			hdr->timestamptype = TS_TIMEVAL;
		}
		else {
			hdr->timestamptype = TS_NONE;
		}
	}


	/* Buffer contains all of our packet (including our custom header) so
	 * we just need to get prepare_packet to set all our packet pointers
	 * appropriately */
	packet->trace = libtrace;
	if (linuxnative_prepare_packet(libtrace, packet, packet->buffer,
				packet->type, flags))
		return -1;
	
	if (hdr->timestamptype == TS_TIMEVAL) {
		packet->order = (((uint64_t)hdr->tv.tv_sec) << 32)
        	            + ((((uint64_t)hdr->tv.tv_usec) << 32) /1000000);
	} else if (hdr->timestamptype == TS_TIMESPEC) {
		packet->order = (((uint64_t)hdr->ts.tv_sec) << 32)
        	            + ((((uint64_t)hdr->ts.tv_nsec) << 32) /1000000000);
	} else {
		packet->order = 0;
	}

        if (packet->order <= stream->last_timestamp) {
                packet->order = stream->last_timestamp + 1;
        }

        stream->last_timestamp = packet->order;

	return hdr->wirelen+sizeof(*hdr);
}

static int linuxnative_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) 
{
	return linuxnative_read_stream(libtrace, packet, FORMAT_DATA_FIRST, NULL);
}

#ifdef HAVE_PACKET_FANOUT
static int linuxnative_pread_packets(libtrace_t *libtrace,
                                     libtrace_thread_t *t,
                                     libtrace_packet_t *packets[],
                                     UNUSED size_t nb_packets) {
	/* For now just read one packet */
	packets[0]->error = linuxnative_read_stream(libtrace, packets[0],
	                                               t->format_data, &t->messages);
	if (packets[0]->error >= 1)
		return 1;
	else
		return packets[0]->error;
}
#endif

static int linuxnative_write_packet(libtrace_out_t *libtrace,
		libtrace_packet_t *packet) 
{
	/* Check linuxnative can write this type of packet */
	if (!linuxnative_can_write(packet)) {
		return 0;
	}

	struct sockaddr_ll hdr;
	int ret = 0;

	hdr.sll_family = AF_PACKET;
	hdr.sll_protocol = 0;
	hdr.sll_ifindex = if_nametoindex(libtrace->uridata);
	hdr.sll_hatype = 0;
	hdr.sll_pkttype = 0;
	hdr.sll_halen = htons(SLL_HEADER_LENGTH); /* FIXME */
	memcpy(hdr.sll_addr,packet->payload,(size_t)SLL_HEADER_LENGTH);

	/* This is pretty easy, just send the payload using sendto() (after
	 * setting up the sll header properly, of course) */
	ret = sendto(FORMAT_DATA_OUT->fd,
			packet->payload,
			trace_get_capture_length(packet),
			0,
			(struct sockaddr*)&hdr, (socklen_t)sizeof(hdr));

	if (ret < 0) {
		trace_set_err_out(libtrace, errno, "sendto failed");
	}

	return ret;
}
#endif /* HAVE_NETPACKET_PACKET_H */


static libtrace_linktype_t linuxnative_get_link_type(const struct libtrace_packet_t *packet) {
	uint16_t linktype=(((struct libtrace_linuxnative_header*)(packet->buffer))
				->hdr.sll_hatype);
	return linuxcommon_get_link_type(linktype);
}

static libtrace_direction_t linuxnative_get_direction(const struct libtrace_packet_t *packet) {
	return linuxcommon_get_direction(((struct libtrace_linuxnative_header*)(packet->buffer))->hdr.sll_pkttype);
}

static libtrace_direction_t linuxnative_set_direction(
		libtrace_packet_t *packet,
		libtrace_direction_t direction) {
	return linuxcommon_set_direction(&((struct libtrace_linuxnative_header*)(packet->buffer))->hdr, direction);
}

static struct timespec linuxnative_get_timespec(const libtrace_packet_t *packet) 
{
	struct libtrace_linuxnative_header *hdr = 
		(struct libtrace_linuxnative_header*) packet->buffer;
	/* We have to upconvert from timeval to timespec */
	if (hdr->timestamptype == TS_TIMEVAL) {
		struct timespec ts;
		ts.tv_sec = hdr->tv.tv_sec;
		ts.tv_nsec = hdr->tv.tv_usec*1000;
		return ts;
	}
	else {
		struct timespec ts;
		ts.tv_sec = hdr->ts.tv_sec;
		ts.tv_nsec = hdr->ts.tv_nsec;
		return ts;
	}
}

static struct timeval linuxnative_get_timeval(const libtrace_packet_t *packet) 
{
	struct libtrace_linuxnative_header *hdr = 
		(struct libtrace_linuxnative_header*) packet->buffer;
	/* We have to downconvert from timespec to timeval */
	if (hdr->timestamptype == TS_TIMESPEC) {
		struct timeval tv;
		tv.tv_sec = hdr->ts.tv_sec;
		tv.tv_usec = hdr->ts.tv_nsec/1000;
		return tv;
	}
	else {
		struct timeval tv;
		tv.tv_sec = hdr->tv.tv_sec;
		tv.tv_usec = hdr->tv.tv_usec;
		return tv;
	}
}

static int linuxnative_get_capture_length(const libtrace_packet_t *packet)
{
	return ((struct libtrace_linuxnative_header*)(packet->buffer))->caplen;
}


static int linuxnative_get_wire_length(const libtrace_packet_t *packet) 
{

	int wirelen = ((struct libtrace_linuxnative_header*)(packet->buffer))->wirelen;

	/* Include the missing FCS */
	if (trace_get_link_type(packet) == TRACE_TYPE_ETH)
		wirelen += 4;

	return wirelen;
}


static int linuxnative_get_framing_length(UNUSED 
		const libtrace_packet_t *packet) 
{
	return sizeof(struct libtrace_linuxnative_header);
}

static size_t linuxnative_set_capture_length(libtrace_packet_t *packet, 
		size_t size) {

	struct libtrace_linuxnative_header *linux_hdr = NULL;
	if (!packet) {
		fprintf(stderr, "NULL packet passed into linuxnative_set_capture_length()\n");
		/* Return -1 on error? */
		return ~0U;
	}
	if (size > trace_get_capture_length(packet)) {
		/* We should avoid making a packet larger */
		return trace_get_capture_length(packet);
	}
	
	/* Reset the cached capture length */
	packet->cached.capture_length = -1;

	linux_hdr = (struct libtrace_linuxnative_header *)packet->header;
	linux_hdr->caplen = size;
	return trace_get_capture_length(packet);
}

#ifdef HAVE_NETPACKET_PACKET_H
static void linuxnative_help(void) {
	printf("linuxnative format module: $Revision: 1793 $\n");
	printf("Supported input URIs:\n");
	printf("\tint:eth0\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tint:eth0\n");
	printf("\n");
	return;
}

static struct libtrace_format_t linuxnative = {
	"int",
	"$Id$",
	TRACE_FORMAT_LINUX_NATIVE,
	linuxcommon_probe_filename,	/* probe filename */
	NULL,				/* probe magic */
	linuxcommon_init_input,	 	/* init_input */
	linuxcommon_config_input,	/* config_input */
	linuxnative_start_input,	/* start_input */
	linuxcommon_pause_input,	/* pause_input */
	linuxcommon_init_output,	/* init_output */
	NULL,				/* config_output */
	linuxnative_start_output,	/* start_ouput */
	linuxcommon_fin_input,		/* fin_input */
	linuxnative_fin_output,		/* fin_output */
	linuxnative_read_packet,	/* read_packet */
	linuxnative_prepare_packet,	/* prepare_packet */
	NULL,				/* fin_packet */
	linuxnative_write_packet,	/* write_packet */
	NULL,				/* flush_output */
	linuxnative_get_link_type,	/* get_link_type */
	linuxnative_get_direction,	/* get_direction */
	linuxnative_set_direction,	/* set_direction */
	NULL,				/* get_erf_timestamp */
	linuxnative_get_timeval,	/* get_timeval */
	linuxnative_get_timespec,	/* get_timespec */
	NULL,				/* get_seconds */
	NULL,                           /* get_meta_section */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	linuxnative_get_capture_length,	/* get_capture_length */
	linuxnative_get_wire_length,	/* get_wire_length */
	linuxnative_get_framing_length,	/* get_framing_length */
	linuxnative_set_capture_length,	/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	linuxcommon_get_statistics,	/* get_statistics */
	linuxcommon_get_fd,		/* get_fd */
	trace_event_device,		/* trace_event */
	linuxnative_help,		/* help */
	NULL,				/* next pointer */
#ifdef HAVE_PACKET_FANOUT
	{true, -1},			/* Live, no thread limit */
	linuxnative_pstart_input,	/* pstart_input */
	linuxnative_pread_packets,	/* pread_packets */
	linuxcommon_pause_input,	/* ppause */
	linuxcommon_fin_input,		/* p_fin */
	linuxcommon_pregister_thread,	/* register thread */
	NULL,				/* unregister thread */
	NULL				/* get thread stats */
#else
        NON_PARALLEL(true)
#endif
};
#else
static void linuxnative_help(void) {
	printf("linuxnative format module: $Revision: 1793 $\n");
	printf("Not supported on this host\n");
}

static struct libtrace_format_t linuxnative = {
	"int",
	"$Id$",
	TRACE_FORMAT_LINUX_NATIVE,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
	NULL,	 			/* init_input */
	NULL,				/* config_input */
	NULL,				/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_ouput */
	NULL,				/* fin_input */
	NULL,				/* fin_output */
	NULL,				/* read_packet */
	linuxnative_prepare_packet,	/* prepare_packet */
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	NULL,				/* flush_output */
	linuxnative_get_link_type,	/* get_link_type */
	linuxnative_get_direction,	/* get_direction */
	linuxnative_set_direction,	/* set_direction */
	NULL,				/* get_erf_timestamp */
	linuxnative_get_timeval,	/* get_timeval */
	linuxnative_get_timespec,	/* get_timespec */
	NULL,				/* get_seconds */
	NULL,                           /* get_meta_section */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	linuxnative_get_capture_length,	/* get_capture_length */
	linuxnative_get_wire_length,	/* get_wire_length */
	linuxnative_get_framing_length,	/* get_framing_length */
	linuxnative_set_capture_length,	/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	linuxcommon_get_statistics,	/* get_statistics */
	NULL,				/* get_fd */
	NULL,				/* trace_event */
	linuxnative_help,		/* help */
	NULL,			/* next pointer */
	NON_PARALLEL(true)
};
#endif /* HAVE_NETPACKET_PACKET_H */

void linuxnative_constructor(void) {
	register_format(&linuxnative);
}
