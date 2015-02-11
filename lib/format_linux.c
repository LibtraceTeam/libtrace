/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock
 *          Richard Sanger 
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
#include <assert.h>

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
# error "Can't find inttypes.h"
#endif

#include "format_linux.h"


#ifdef HAVE_NETPACKET_PACKET_H
static int linuxnative_probe_filename(const char *filename)
{
	/* Is this an interface? */
	return (if_nametoindex(filename) != 0);
}

static int linuxnative_init_input(libtrace_t *libtrace)
{
	struct linux_per_stream_t stream_data= ZERO_LINUX_STREAM;

	libtrace->format_data = (struct linux_format_data_t *)
		malloc(sizeof(struct linux_format_data_t));
	assert(libtrace->format_data != NULL);

	FORMAT_DATA->per_stream =
		libtrace_list_init(sizeof(stream_data));
	assert(FORMAT_DATA->per_stream != NULL);

	libtrace_list_push_back(FORMAT_DATA->per_stream, &stream_data);

	FORMAT_DATA->promisc = -1;
	FORMAT_DATA->snaplen = LIBTRACE_PACKET_BUFSIZE;
	FORMAT_DATA->filter = NULL;
	FORMAT_DATA->stats_valid = 0;
	FORMAT_DATA->fanout_flags = PACKET_FANOUT_LB;
	/* Some examples use pid for the group however that would limit a single
	 * application to use only int/ring format, instead using rand */
	FORMAT_DATA->fanout_group = (uint16_t) rand();
	FORMAT_DATA->format = TRACE_RT_DATA_LINUX_NATIVE;

	return 0;
}

static int linuxnative_init_output(libtrace_out_t *libtrace)
{
	libtrace->format_data = (struct linux_format_data_out_t*)
		malloc(sizeof(struct linux_format_data_out_t));
	assert(libtrace->format_data != NULL);

	FORMAT_DATA_OUT->fd = -1;
	FORMAT_DATA_OUT->tx_ring = NULL;
	FORMAT_DATA_OUT->txring_offset = 0;
	FORMAT_DATA_OUT->queue = 0;
	FORMAT_DATA_OUT->max_order = MAX_ORDER;
	FORMAT_DATA_OUT->format = TRACE_FORMAT_LINUX_NATIVE;

	return 0;
}

/* Close an input stream, this is safe to be called part way through
 * initilisation as a cleanup function assuming streams were set to
 * ZERO_LINUX_STREAM to begin with.
 */
static inline void linuxnative_close_input_stream(libtrace_t *libtrace,
                                                  struct linux_per_stream_t *stream) {
	if (stream->fd != -1)
		close(stream->fd);
	stream->fd = -1;
	/* TODO maybe store size against stream XXX */
	if (stream->rx_ring)
		munmap(stream->rx_ring,
		       FORMAT_DATA->req.tp_block_size *
		       FORMAT_DATA->req.tp_block_nr);
	stream->rx_ring = NULL;
}

static inline int linuxnative_start_input_stream(libtrace_t *libtrace,
                                                 struct linux_per_stream_t *stream)
{
	struct sockaddr_ll addr;
	const int one = 1;
	memset(&addr,0,sizeof(addr));
	libtrace_filter_t *filter = FORMAT_DATA->filter;

	/* Create a raw socket for reading packets on */
	stream->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (stream->fd==-1) {
		trace_set_err(libtrace, errno, "Could not create raw socket");
		return -1;
	}

	/* Bind to the capture interface */
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (strlen(libtrace->uridata)) {
		addr.sll_ifindex = if_nametoindex(libtrace->uridata);
		if (addr.sll_ifindex == 0) {
			linuxnative_close_input_stream(libtrace, stream);
			trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				      "Failed to find interface %s",
				      libtrace->uridata);
			return -1;
		}
	} else {
		addr.sll_ifindex = 0;
	}
	if (bind(stream->fd,
	         (struct sockaddr*)&addr,
	         (socklen_t)sizeof(addr))==-1) {
		linuxnative_close_input_stream(libtrace, stream);
		trace_set_err(libtrace, errno,
			      "Failed to bind to interface %s",
			      libtrace->uridata);
		return -1;
	}

	/* If promisc hasn't been specified, set it to "true" if we're
	 * capturing on one interface, or "false" if we're capturing on
	 * all interfaces.
	 */
	if (FORMAT_DATA->promisc==-1) {
		if (addr.sll_ifindex!=0)
			FORMAT_DATA->promisc=1;
		else
			FORMAT_DATA->promisc=0;
	}

	/* Enable promiscuous mode, if requested */
	if (FORMAT_DATA->promisc) {
		struct packet_mreq mreq;
		socklen_t socklen = sizeof(mreq);
		memset(&mreq,0,sizeof(mreq));
		mreq.mr_ifindex = addr.sll_ifindex;
		mreq.mr_type = PACKET_MR_PROMISC;
		if (setsockopt(stream->fd,
			       SOL_PACKET,
			       PACKET_ADD_MEMBERSHIP,
			       &mreq,
			       socklen)==-1) {
			perror("setsockopt(PROMISC)");
		}
	}

	/* Set the timestamp option on the socket - aim for the most detailed
	 * clock resolution possible */
#ifdef SO_TIMESTAMPNS
	if (setsockopt(stream->fd,
		       SOL_SOCKET,
		       SO_TIMESTAMPNS,
		       &one,
		       (socklen_t)sizeof(one))!=-1) {
		FORMAT_DATA->timestamptype = TS_TIMESPEC;
	}
	else
	/* DANGER: This is a dangling else to only do the next setsockopt()
	 * if we fail the first! */
#endif
		if (setsockopt(stream->fd,
			       SOL_SOCKET,
			       SO_TIMESTAMP,
			       &one,
			       (socklen_t)sizeof(one))!=-1) {
			FORMAT_DATA->timestamptype = TS_TIMEVAL;
		}
		else
			FORMAT_DATA->timestamptype = TS_NONE;

	/* Push BPF filter into the kernel. At this stage we can safely assume
	 * that the filterstring has been compiled, or the filter was supplied
	 * pre-compiled.
	 */
	if (filter != NULL) {
		/* Check if the filter was successfully compiled. If not,
		 * it is probably a bad filter and we should return an error
		 * before the caller tries to read any packets */
		if (filter->flag == 0) {
			linuxnative_close_input_stream(libtrace, stream);
			trace_set_err(libtrace, TRACE_ERR_BAD_FILTER,
				      "Cannot attach a bad filter to %s",
				      libtrace->uridata);
			return -1;
		}

		if (setsockopt(stream->fd,
			       SOL_SOCKET,
			       SO_ATTACH_FILTER,
			       &filter->filter,
			       sizeof(filter->filter)) == -1) {
			perror("setsockopt(SO_ATTACH_FILTER)");
		} else {
			/* The socket accepted the filter, so we need to
			 * consume any buffered packets that were received
			 * between opening the socket and applying the filter.
			 */
			void *buf = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
			while(recv(stream->fd,
				   buf,
				   (size_t)LIBTRACE_PACKET_BUFSIZE,
				   MSG_DONTWAIT) != -1) { }
			free(buf);
		}
	}

	FORMAT_DATA->stats_valid = 0;

	return 0;
}

static int linuxnative_start_input(libtrace_t *libtrace)
{
	int ret = linuxnative_start_input_stream(libtrace, FORMAT_DATA_FIRST);
	if (ret != 0) {
		libtrace_list_deinit(FORMAT_DATA->per_stream);
		free(libtrace->format_data);
		libtrace->format_data = NULL;
	}
	return ret;
}

/**
 * Converts a socket, either packet_mmap or standard raw socket into a
 * fanout socket.
 * NOTE: This means we can read from the socket with multiple queues,
 * each must be setup (identically) and then this called upon them
 *
 * @return 0 success, -1 error
 */
static inline int linuxnative_socket_to_packet_fanout(libtrace_t *libtrace,
                                                      struct linux_per_stream_t *stream)
{
	int fanout_opt = ((int)FORMAT_DATA->fanout_flags << 16) | (int)FORMAT_DATA->fanout_group;
	if (setsockopt(stream->fd, SOL_PACKET, PACKET_FANOUT,
			&fanout_opt, sizeof(fanout_opt)) == -1) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
		              "Converting the fd to a socket fanout failed %s",
		              libtrace->uridata);
		return -1;
	}
	return 0;
}

static int linuxnative_pstart_input(libtrace_t *libtrace) {
	int i = 0;
	int tot = libtrace->perpkt_thread_count;
	int iserror = 0;
	// We store this here otherwise it will be leaked if the memory doesn't know
	struct linux_per_stream_t empty_stream = ZERO_LINUX_STREAM;

	printf("Calling native pstart packet\n");
	for (i = 0; i < tot; ++i)
	{
		struct linux_per_stream_t *stream;
		/* Add storage for another stream */
		if (libtrace_list_get_size(FORMAT_DATA->per_stream) <= (size_t) i)
			libtrace_list_push_back(FORMAT_DATA->per_stream, &empty_stream);

		stream = libtrace_list_get_index(FORMAT_DATA->per_stream, i)->data;
		if (FORMAT_DATA->format == TRACE_RT_DATA_LINUX_NATIVE) {
			if (linuxnative_start_input_stream(libtrace, stream) != 0) {
				iserror = 1;
				break;
			}
		} else {
			perror("BAD CODE XXX TODO PUT CODE HERE!!");
			// This must be ring
			/*
			if (linuxring_start_input(libtrace) != 0) {
				iserror = 1;
				break;
			}*/
		}
		if (linuxnative_socket_to_packet_fanout(libtrace, stream) != 0)
		{
			iserror = 1;
			close(stream->fd);
			stream->fd = -1;
			break;
		}
	}
	
	// Roll back those that failed
	if (iserror) {
		for (i = i - 1; i >= 0; i--) {
			struct linux_per_stream_t *stream;
			stream = libtrace_list_get_index(FORMAT_DATA->per_stream, i)->data;
			linuxnative_close_input_stream(libtrace, stream);
		}
		libtrace_list_deinit(FORMAT_DATA->per_stream);
		free(libtrace->format_data);
		libtrace->format_data = NULL;
		return -1;
	}
	
	return 0;
}

static int linux_pregister_thread(libtrace_t *libtrace, libtrace_thread_t *t, bool reading) {
	fprintf(stderr, "registering thread %d!!\n", t->perpkt_num);
	if (reading) {
		/* XXX TODO remove this oneday make sure hasher thread still works */
		struct linux_per_stream_t *stream;
		stream = libtrace_list_get_index(FORMAT_DATA->per_stream,
		                                 t->perpkt_num)->data;
		t->format_data = stream;
		if (!stream) {
			/* This should never happen and indicates an
			 * internal libtrace bug */
			trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				      "Failed to attached thread %d to a stream",
				      t->perpkt_num);
			return -1;
		}
	}
	return 0;
}

static int linuxnative_start_output(libtrace_out_t *libtrace)
{
	FORMAT_DATA_OUT->fd = socket(PF_PACKET, SOCK_RAW, 0);
	if (FORMAT_DATA_OUT->fd==-1) {
		free(FORMAT_DATA_OUT);
		return -1;
	}

	return 0;
}


static int linuxnative_pause_input(libtrace_t *libtrace)
{
	size_t i;

	/* Stop and detach each stream */
	for (i = 0; i < libtrace_list_get_size(FORMAT_DATA->per_stream); ++i) {
		struct linux_per_stream_t *stream;
		stream = libtrace_list_get_index(FORMAT_DATA->per_stream, i)->data;
		linuxnative_close_input_stream(libtrace, stream);
	}

	return 0;
}

static int linuxnative_fin_input(libtrace_t *libtrace)
{
	if (libtrace->format_data) {
		if (FORMAT_DATA->filter != NULL)
			free(FORMAT_DATA->filter);

		if (FORMAT_DATA->per_stream)
			libtrace_list_deinit(FORMAT_DATA->per_stream);

		free(libtrace->format_data);
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

/* Compiles a libtrace BPF filter for use with a linux native socket */
static int linuxnative_configure_bpf(libtrace_t *libtrace, 
		libtrace_filter_t *filter) {
#ifdef HAVE_LIBPCAP 
	struct ifreq ifr;
	unsigned int arphrd;
	libtrace_dlt_t dlt;
	libtrace_filter_t *f;
	int sock;
	pcap_t *pcap;

	/* Take a copy of the filter object as it was passed in */
	f = (libtrace_filter_t *) malloc(sizeof(libtrace_filter_t));
	memcpy(f, filter, sizeof(libtrace_filter_t));
	
	/* If we are passed a filter with "flag" set to zero, then we must
	 * compile the filterstring before continuing. This involves
	 * determining the linktype, passing the filterstring to libpcap to
	 * compile, and saving the result for trace_start() to push into the
	 * kernel.
	 * If flag is set to one, then the filter was probably generated using
	 * trace_create_filter_from_bytecode() and so we don't need to do
	 * anything (we've just copied it above).
	 */
	if (f->flag == 0) {
		sock = socket(PF_INET, SOCK_STREAM, 0);
		memset(&ifr, 0, sizeof(struct ifreq));
		strncpy(ifr.ifr_name, libtrace->uridata, IF_NAMESIZE);
		if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) {
			perror("Can't get HWADDR for interface");
			return -1;
		}
		close(sock);

		arphrd = ifr.ifr_hwaddr.sa_family;
		dlt = libtrace_to_pcap_dlt(arphrd_type_to_libtrace(arphrd));

		pcap = pcap_open_dead(dlt, 
				FORMAT_DATA->snaplen);

		if (pcap_compile(pcap, &f->filter, f->filterstring, 0, 0) == -1) {
		        /* Filter didn't compile, set flag to 0 so we can
                         * detect this when trace_start() is called and
                         * produce a useful error
                         */
                        f->flag = 0;
                        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, 
                                        "Failed to compile BPF filter (%s): %s",
                                        f->filterstring, pcap_geterr(pcap));
                } else {
                        /* Set the "flag" to indicate that the filterstring 
                         * has been compiled
                         */
                        f->flag = 1;
		}

		pcap_close(pcap);
		
	}
	
	if (FORMAT_DATA->filter != NULL)
		free(FORMAT_DATA->filter);
	
	FORMAT_DATA->filter = f;
	
	return 0;
#else
	return -1
#endif
}
static int linuxnative_config_input(libtrace_t *libtrace,
		trace_option_t option,
		void *data)
{
	switch(option) {
		case TRACE_OPTION_SNAPLEN:
			FORMAT_DATA->snaplen=*(int*)data;
			return 0;
		case TRACE_OPTION_PROMISC:
			FORMAT_DATA->promisc=*(int*)data;
			return 0;
		case TRACE_OPTION_FILTER:
		 	return linuxnative_configure_bpf(libtrace, 
					(libtrace_filter_t *) data);
		case TRACE_OPTION_META_FREQ:
			/* No meta-data for this format */
			break;
		case TRACE_OPTION_EVENT_REALTIME:
			/* Live captures are always going to be in trace time */
			break;
		/* Avoid default: so that future options will cause a warning
		 * here to remind us to implement it, or flag it as
		 * unimplementable
		 */
	}
	
	/* Don't set an error - trace_config will try to deal with the
	 * option and will set an error if it fails */
	return -1;
}
#endif /* HAVE_NETPACKET_PACKET_H */


static int linuxnative_pconfig_input(libtrace_t *libtrace,
		trace_parallel_option_t option,
		void *data)
{
	switch(option) {
		case TRACE_OPTION_SET_HASHER:
			switch (*((enum hasher_types *)data)) {
				case HASHER_BALANCE:
					// Do fanout
					FORMAT_DATA->fanout_flags = PACKET_FANOUT_LB;
					// Or we could balance to the CPU
					return 0;
				case HASHER_BIDIRECTIONAL:
				case HASHER_UNIDIRECTIONAL:
					FORMAT_DATA->fanout_flags = PACKET_FANOUT_HASH;
					return 0;
				case HASHER_CUSTOM:
				case HASHER_HARDWARE:
					return -1;
			}
			break;
		/* Avoid default: so that future options will cause a warning
		 * here to remind us to implement it, or flag it as
		 * unimplementable
		 */
	}
	
	/* Don't set an error - trace_config will try to deal with the
	 * option and will set an error if it fails */
	return -1;
}


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
		int message_fd;
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
				if (libtrace_halt)
					return READ_EOF;
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
	
	if (linuxnative_prepare_packet(libtrace, packet, packet->buffer,
				packet->type, flags))
		return -1;
	
	return hdr->wirelen+sizeof(*hdr);
}

static int linuxnative_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) 
{
	return linuxnative_read_stream(libtrace, packet, FORMAT_DATA_FIRST, NULL);
}

static int linuxnative_pread_packets(libtrace_t *libtrace,
                                     libtrace_thread_t *t,
                                     libtrace_packet_t **packets,
                                     UNUSED size_t nb_packets) {
	/* For now just read one packet */
	packets[0]->error = linuxnative_read_stream(libtrace, packets[0],
	                                               t->format_data, &t->messages);
	if (packets[0]->error >= 1)
		return 1;
	else
		return packets[0]->error;
}

static int linuxnative_write_packet(libtrace_out_t *libtrace,
		libtrace_packet_t *packet) 
{
	struct sockaddr_ll hdr;
	int ret = 0;

	if (trace_get_link_type(packet) == TRACE_TYPE_NONDATA)
		return 0;

	hdr.sll_family = AF_PACKET;
	hdr.sll_protocol = 0;
	hdr.sll_ifindex = if_nametoindex(libtrace->uridata);
	hdr.sll_hatype = 0;
	hdr.sll_pkttype = 0;
	hdr.sll_halen = htons(6); /* FIXME */
	memcpy(hdr.sll_addr,packet->payload,(size_t)ntohs(hdr.sll_halen));

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
	return get_libtrace_link_type(linktype);
}

static libtrace_direction_t linuxnative_get_direction(const struct libtrace_packet_t *packet) {
	return get_libtrace_direction(((struct libtrace_linuxnative_header*)(packet->buffer))->hdr.sll_pkttype);
}

static libtrace_direction_t linuxnative_set_direction(
		libtrace_packet_t *packet,
		libtrace_direction_t direction) {
	return set_direction(&((struct libtrace_linuxnative_header*)(packet->buffer))->hdr, direction);
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
	assert(packet);
	if (size > trace_get_capture_length(packet)) {
		/* We should avoid making a packet larger */
		return trace_get_capture_length(packet);
	}
	
	/* Reset the cached capture length */
	packet->capture_length = -1;

	linux_hdr = (struct libtrace_linuxnative_header *)packet->header;
	linux_hdr->caplen = size;
	return trace_get_capture_length(packet);
}

static int linuxnative_get_fd(const libtrace_t *libtrace) {
	if (libtrace->format_data == NULL)
		return -1;
	return FORMAT_DATA_FIRST->fd;
}

/* Linux doesn't keep track how many packets were seen before filtering
 * so we can't tell how many packets were filtered.  Bugger.  So annoying.
 *
 * Since we tell libtrace that we do support filtering, if we don't declare
 * this here as failing, libtrace will happily report for us that it didn't
 * filter any packets, so don't lie -- return that we don't know.
 */
static uint64_t linuxnative_get_filtered_packets(libtrace_t *trace UNUSED) {
	return UINT64_MAX;
}

#ifdef HAVE_NETPACKET_PACKET_H
static void linuxnative_update_statistics(libtrace_t *libtrace) {
	struct tpacket_stats stats;
	size_t i;
	socklen_t len = sizeof(stats);

	for (i = 0; i < libtrace_list_get_size(FORMAT_DATA->per_stream); ++i) {
		struct linux_per_stream_t *stream;
		stream = libtrace_list_get_index(FORMAT_DATA->per_stream, i)->data;
		if (stream->fd != -1) {
			if (getsockopt(stream->fd,
			           SOL_PACKET,
			           PACKET_STATISTICS,
			           &stats,
			           &len) == 0) {
				if (FORMAT_DATA->stats_valid==0) {
					FORMAT_DATA->stats.tp_drops = stats.tp_drops;
					FORMAT_DATA->stats.tp_packets = stats.tp_packets;
					FORMAT_DATA->stats_valid = 1;
				} else {
					FORMAT_DATA->stats.tp_drops += stats.tp_drops;
					FORMAT_DATA->stats.tp_drops += stats.tp_packets;
				}
			} else {
				perror("getsockopt PACKET_STATISTICS failed");
			}
		}
	}
}
#endif

/* Number of packets that passed filtering */
static uint64_t linuxnative_get_captured_packets(libtrace_t *libtrace) {
	if (libtrace->format_data == NULL)
		return UINT64_MAX;
	if (FORMAT_DATA_FIRST->fd == -1) {
		/* This is probably a 'dead' trace so obviously we can't query
		 * the socket for capture counts, can we? */
		return UINT64_MAX;
	}

#ifdef HAVE_NETPACKET_PACKET_H
	linuxnative_update_statistics(libtrace);
	if (FORMAT_DATA->stats_valid)
		return FORMAT_DATA->stats.tp_packets;
	else
		return UINT64_MAX;
#else
	return UINT64_MAX;
#endif
}


/* Number of packets that got past filtering and were then dropped because
 * of lack of space.
 *
 * We could also try read from /sys/class/net/ethX/statistics/ to get
 * real drop counters and stuff.
 */
static uint64_t linuxnative_get_dropped_packets(libtrace_t *libtrace) {
	if (libtrace->format_data == NULL)
		return UINT64_MAX;
	if (FORMAT_DATA_FIRST->fd == -1) {
		/* This is probably a 'dead' trace so obviously we can't query
		 * the socket for drop counts, can we? */
		return UINT64_MAX;
	}

#ifdef HAVE_NETPACKET_PACKET_H
	linuxnative_update_statistics(libtrace);
	if (FORMAT_DATA->stats_valid)
		return FORMAT_DATA->stats.tp_drops;
	else
		return UINT64_MAX;
#else
	return UINT64_MAX;
#endif
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
	linuxnative_probe_filename,	/* probe filename */
	NULL,				/* probe magic */
	linuxnative_init_input,	 	/* init_input */
	linuxnative_config_input,	/* config_input */
	linuxnative_start_input,	/* start_input */
	linuxnative_pause_input,	/* pause_input */
	linuxnative_init_output,	/* init_output */
	NULL,				/* config_output */
	linuxnative_start_output,	/* start_ouput */
	linuxnative_fin_input,		/* fin_input */
	linuxnative_fin_output,		/* fin_output */
	linuxnative_read_packet,	/* read_packet */
	linuxnative_prepare_packet,	/* prepare_packet */
	NULL,				/* fin_packet */
	linuxnative_write_packet,	/* write_packet */
	linuxnative_get_link_type,	/* get_link_type */
	linuxnative_get_direction,	/* get_direction */
	linuxnative_set_direction,	/* set_direction */
	NULL,				/* get_erf_timestamp */
	linuxnative_get_timeval,	/* get_timeval */
	linuxnative_get_timespec,	/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	linuxnative_get_capture_length,	/* get_capture_length */
	linuxnative_get_wire_length,	/* get_wire_length */
	linuxnative_get_framing_length,	/* get_framing_length */
	linuxnative_set_capture_length,	/* set_capture_length */
	NULL,				/* get_received_packets */
	linuxnative_get_filtered_packets,/* get_filtered_packets */
	linuxnative_get_dropped_packets,/* get_dropped_packets */
	linuxnative_get_captured_packets,/* get_captured_packets */
	linuxnative_get_fd,		/* get_fd */
	trace_event_device,		/* trace_event */
	linuxnative_help,		/* help */
	NULL,					/* next pointer */
	{true, -1},              /* Live, no thread limit */
	linuxnative_pstart_input,			/* pstart_input */
	linuxnative_pread_packets,			/* pread_packets */
	linuxnative_pause_input,			/* ppause */
	linuxnative_fin_input,				/* p_fin */
	linuxnative_pconfig_input,			/* pconfig input */
	linux_pregister_thread,
	NULL
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
	linuxnative_get_link_type,	/* get_link_type */
	linuxnative_get_direction,	/* get_direction */
	linuxnative_set_direction,	/* set_direction */
	NULL,				/* get_erf_timestamp */
	linuxnative_get_timeval,	/* get_timeval */
	linuxnative_get_timespec,	/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	linuxnative_get_capture_length,	/* get_capture_length */
	linuxnative_get_wire_length,	/* get_wire_length */
	linuxnative_get_framing_length,	/* get_framing_length */
	linuxnative_set_capture_length,	/* set_capture_length */
	NULL,				/* get_received_packets */
	linuxnative_get_filtered_packets,/* get_filtered_packets */
	linuxnative_get_dropped_packets,/* get_dropped_packets */
	linuxnative_get_captured_packets,/* get_captured_packets */
	linuxnative_get_fd,		/* get_fd */
	trace_event_device,		/* trace_event */
	linuxnative_help,		/* help */
	NULL,			/* next pointer */
	NON_PARALLEL(true)
};
#endif /* HAVE_NETPACKET_PACKET_H */

struct libtrace_format_t *get_native_format(void)
{
	return &linuxnative;
}


void linuxnative_constructor(void) {
	register_format(&linuxnative);
}
