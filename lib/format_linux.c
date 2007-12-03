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
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <assert.h>

struct tpacket_stats {
	unsigned int tp_packets;
	unsigned int tp_drops;
};

struct libtrace_format_data_t {
	int fd;
	int snaplen;
	int promisc;
	libtrace_filter_t *filter;
	struct tpacket_stats stats;
	int stats_valid;
};

struct libtrace_linuxnative_header {
	struct timeval ts;
	int wirelen;
	int caplen;
	struct sockaddr_ll hdr;
};

struct libtrace_linuxnative_format_data_t {
	int fd;
};

#define FORMAT(x) ((struct libtrace_format_data_t*)(x))
#define DATAOUT(x) ((struct libtrace_linuxnative_format_data_t*)((x)->format_data))

static int linuxnative_init_input(libtrace_t *libtrace) 
{
	libtrace->format_data = (struct libtrace_format_data_t *)
		malloc(sizeof(struct libtrace_format_data_t));
	FORMAT(libtrace->format_data)->fd = -1;
	FORMAT(libtrace->format_data)->promisc = -1;
	FORMAT(libtrace->format_data)->snaplen = 65536;
	FORMAT(libtrace->format_data)->filter = NULL;
	FORMAT(libtrace->format_data)->stats_valid = 0;

	return 0;
}

static int linuxnative_init_output(libtrace_out_t *libtrace)
{
	libtrace->format_data = (struct libtrace_linuxnative_format_data_t*)
		malloc(sizeof(struct libtrace_linuxnative_format_data_t));
	DATAOUT(libtrace)->fd = -1;

	return 0;
}

static int linuxnative_start_input(libtrace_t *libtrace)
{
	struct sockaddr_ll addr;
	int one = 1;
	memset(&addr,0,sizeof(addr));
	libtrace_filter_t *filter = FORMAT(libtrace->format_data)->filter;
	FORMAT(libtrace->format_data)->fd = 
				socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (FORMAT(libtrace->format_data)->fd==-1) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Could not create raw socket");
		free(libtrace->format_data);
		return -1;
	}
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (strlen(libtrace->uridata)) {
		addr.sll_ifindex = if_nametoindex(libtrace->uridata);
		if (addr.sll_ifindex == 0) {
			close(FORMAT(libtrace->format_data)->fd);
			trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Failed to find interface %s", libtrace->uridata);
			free(libtrace->format_data);
			return -1;
		}
	}
	else {
		addr.sll_ifindex = 0;
	}
	if (bind(FORMAT(libtrace->format_data)->fd,
				(struct sockaddr*)&addr,
				(socklen_t)sizeof(addr))==-1) {
		free(libtrace->format_data);
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Failed to bind to interface %s", libtrace->uridata);
		return -1;
	}

	/* If promisc hasn't been specified, set it to "true" if we're 
	 * capturing on one interface, or "false" if we're capturing on
	 * all interfaces.
	 */ 
	if (FORMAT(libtrace->format_data)->promisc==-1) {
		if (addr.sll_ifindex!=0)
			FORMAT(libtrace->format_data)->promisc=1;
		else
			FORMAT(libtrace->format_data)->promisc=0;
	}
				
	if (FORMAT(libtrace->format_data)->promisc) {
		struct packet_mreq mreq;
		socklen_t socklen = sizeof(mreq);
		memset(&mreq,0,sizeof(mreq));
		mreq.mr_ifindex = addr.sll_ifindex;
		mreq.mr_type = PACKET_MR_PROMISC;
		setsockopt(FORMAT(libtrace->format_data)->fd,
				SOL_PACKET,
				PACKET_ADD_MEMBERSHIP,
				&mreq,
				socklen);
	}

	if (setsockopt(FORMAT(libtrace->format_data)->fd,
			SOL_SOCKET,
			SO_TIMESTAMP,
			&one,
			(socklen_t)sizeof(one))==-1) {
		perror("setsockopt(SO_TIMESTAMP)");
	}

	/* Push BPF filter into the kernel. At this stage we can safely assume
	 * that the filterstring has been compiled, or the filter was supplied
	 * pre-compiled.
	 */
	if (filter != NULL) {
		assert(filter->flag == 1);
		if (setsockopt(FORMAT(libtrace->format_data)->fd,
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
			while(recv(FORMAT(libtrace->format_data)->fd,
					buf,
					(size_t) LIBTRACE_PACKET_BUFSIZE,
					MSG_DONTWAIT) != -1) { }
			free(buf);
		}
	}

	FORMAT(libtrace->format_data)->stats_valid=0;
					
	return 0;
}

static int linuxnative_start_output(libtrace_out_t *libtrace)
{
	FORMAT(libtrace->format_data)->fd = 
				socket(PF_PACKET, SOCK_RAW, 0);
	if (FORMAT(libtrace->format_data)->fd==-1) {
		free(libtrace->format_data);
		return -1;
	}
	FORMAT(libtrace->format_data)->stats_valid=0;

	return 0;
}

static int linuxnative_pause_input(libtrace_t *libtrace)
{
	close(FORMAT(libtrace->format_data)->fd);
	FORMAT(libtrace->format_data)->fd=-1;

	return 0;
}

static int linuxnative_fin_input(libtrace_t *libtrace) 
{
	if (FORMAT(libtrace->format_data)->filter != NULL)
		free(FORMAT(libtrace->format_data)->filter);
	free(libtrace->format_data);
	
	return 0;
}

static int linuxnative_fin_output(libtrace_out_t *libtrace)
{
	close(DATAOUT(libtrace)->fd);
	DATAOUT(libtrace)->fd=-1;
	free(libtrace->format_data);
	return 0;
}

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
				FORMAT(libtrace->format_data)->snaplen);

		if (pcap_compile(pcap, &f->filter, f->filterstring, 0, 0) == -1) {
			perror("PCAP failed to compile the filterstring");
			return -1;
		}

		pcap_close(pcap);
		
		/* Set the "flag" to indicate that the filterstring has been
		 * compiled
		 */
		f->flag = 1;
	}
	
	if (FORMAT(libtrace->format_data)->filter != NULL)
		free(FORMAT(libtrace->format_data)->filter);
	
	FORMAT(libtrace->format_data)->filter = f;
	
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
			FORMAT(libtrace->format_data)->snaplen=*(int*)data;
			return 0;
		case TRACE_OPTION_PROMISC:
			FORMAT(libtrace->format_data)->promisc=*(int*)data;
			return 0;
		case TRACE_OPTION_FILTER:
		 	return linuxnative_configure_bpf(libtrace, 
					(libtrace_filter_t *) data);
		case TRACE_OPTION_META_FREQ:
			/* No meta-data for this format */
			break;
		case TRACE_OPTION_EVENT_REALTIME:
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

#define LIBTRACE_MIN(a,b) ((a)<(b) ? (a) : (b))

/* 20 isn't enough on x86_64 */
#define CMSG_BUF_SIZE 128
static int linuxnative_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) 
{
	struct libtrace_linuxnative_header *hdr;
	struct msghdr msghdr;
	struct iovec iovec;
	unsigned char controlbuf[CMSG_BUF_SIZE];
	struct cmsghdr *cmsg;
	socklen_t socklen;
	int snaplen;

	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
		packet->buf_control = TRACE_CTRL_PACKET;
	}

	packet->header = packet->buffer;
	packet->type = TRACE_RT_DATA_LINUX_NATIVE;
	packet->payload = (char*)packet->buffer+sizeof(*hdr);

	hdr=(struct libtrace_linuxnative_header*)packet->buffer;
	socklen=sizeof(hdr->hdr);
	snaplen=LIBTRACE_MIN(
			(int)LIBTRACE_PACKET_BUFSIZE-(int)sizeof(*hdr),
			(int)FORMAT(libtrace->format_data)->snaplen);

	msghdr.msg_name = &hdr->hdr;
	msghdr.msg_namelen = sizeof(struct sockaddr_ll);

	msghdr.msg_iov = &iovec;
	msghdr.msg_iovlen = 1;

	msghdr.msg_control = &controlbuf;
	msghdr.msg_controllen = CMSG_BUF_SIZE;
	msghdr.msg_flags = 0;

	iovec.iov_base = (void*)packet->payload;
	iovec.iov_len = snaplen;

	hdr->wirelen = recvmsg(FORMAT(libtrace->format_data)->fd, &msghdr, 0);

	if (hdr->wirelen==-1) {
		trace_set_err(libtrace,errno,"recvmsg");
		return -1;
	}

	hdr->caplen=LIBTRACE_MIN(snaplen,hdr->wirelen);

	for (cmsg = CMSG_FIRSTHDR(&msghdr);
			cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
			&& cmsg->cmsg_type == SO_TIMESTAMP
			&& cmsg->cmsg_len <= CMSG_LEN(sizeof(struct timeval))) {
			memcpy(&hdr->ts, CMSG_DATA(cmsg),
					sizeof(struct timeval));
			break;
		}
	}

	if (cmsg == NULL && ioctl(FORMAT(libtrace->format_data)->fd,
				SIOCGSTAMP,&hdr->ts)==-1)
		perror("ioctl(SIOCGSTAMP)");

	return hdr->wirelen+sizeof(*hdr);
}

static int linuxnative_write_packet(libtrace_out_t *trace, 
		libtrace_packet_t *packet) 
{
	struct sockaddr_ll hdr;

	hdr.sll_family = AF_PACKET;
	hdr.sll_protocol = 0;
	hdr.sll_ifindex = if_nametoindex(trace->uridata);
	hdr.sll_hatype = 0;
	hdr.sll_pkttype = 0;
	hdr.sll_halen = htons(6); /* FIXME */
	memcpy(hdr.sll_addr,packet->payload,(size_t)hdr.sll_halen);

	return sendto(DATAOUT(trace)->fd,
			packet->payload,
			trace_get_capture_length(packet),
			0,
			(struct sockaddr*)&hdr, (socklen_t)sizeof(hdr));

}

static libtrace_linktype_t linuxnative_get_link_type(const struct libtrace_packet_t *packet) {
	int linktype=(((struct libtrace_linuxnative_header*)(packet->buffer))
				->hdr.sll_hatype);
	switch (linktype) {
		case ARPHRD_ETHER:
			return TRACE_TYPE_ETH;
		case ARPHRD_PPP:
			return TRACE_TYPE_NONE;
		case ARPHRD_80211_RADIOTAP:
			return TRACE_TYPE_80211_RADIO;
		case ARPHRD_IEEE80211:
			return TRACE_TYPE_80211;
		case ARPHRD_SIT:
			return TRACE_TYPE_NONE;
		default: /* shrug, beyond me! */
			printf("unknown Linux ARPHRD type 0x%04x\n",linktype);
			return (libtrace_linktype_t)~0U;
	}
}

static libtrace_direction_t linuxnative_get_direction(const struct libtrace_packet_t *packet) {
	switch (((struct libtrace_linuxnative_header*)(packet->buffer))->hdr.sll_pkttype) {
		case PACKET_OUTGOING:
		case PACKET_LOOPBACK:
			return TRACE_DIR_OUTGOING;
		default:
			return TRACE_DIR_INCOMING;
	}
}

static libtrace_direction_t linuxnative_set_direction(
		libtrace_packet_t *packet,
		libtrace_direction_t direction) {

	switch (direction) {
		case TRACE_DIR_OUTGOING:
			((struct libtrace_linuxnative_header*)(packet->buffer))->hdr.sll_pkttype = PACKET_OUTGOING;
			return TRACE_DIR_OUTGOING;
		case TRACE_DIR_INCOMING:
			((struct libtrace_linuxnative_header*)(packet->buffer))->hdr.sll_pkttype = PACKET_HOST;
			return TRACE_DIR_INCOMING;
		default:
			return -1;
	}
}

static struct timeval linuxnative_get_timeval(const libtrace_packet_t *packet) 
{
	return ((struct libtrace_linuxnative_header*)(packet->buffer))->ts;
}

static int linuxnative_get_capture_length(const libtrace_packet_t *packet)
{
	return ((struct libtrace_linuxnative_header*)(packet->buffer))->caplen;
}

static int linuxnative_get_wire_length(const libtrace_packet_t *packet) 
{
	return ((struct libtrace_linuxnative_header*)(packet->buffer))->wirelen;
}

static int linuxnative_get_framing_length(UNUSED 
		const libtrace_packet_t *packet) 
{
	return sizeof(struct libtrace_linuxnative_header);
}

static int linuxnative_get_fd(const libtrace_t *trace) {
	return FORMAT(trace->format_data)->fd;
}

/* Linux doesn't keep track how many packets were seen before filtering
 * so we can't tell how many packets were filtered.  Bugger.  So annoying.
 *
 * Since we tell libtrace that we do support filtering, if we don't declare
 * this here as failing, libtrace will happily report for us that it didn't
 * filter any packets, so don't lie -- return that we don't know.
 */
static uint64_t linuxnative_get_filtered_packets(libtrace_t *trace) {
	return UINT64_MAX;
}

/* Number of packets that past filtering */
static uint64_t linuxnative_get_captured_packets(libtrace_t *trace) {
	if (FORMAT(trace->format_data)->stats_valid != 2) {
		socklen_t len = sizeof(FORMAT(trace->format_data)->stats);
		getsockopt(FORMAT(trace->format_data)->fd, 
				SOL_PACKET,
				PACKET_STATISTICS,
				&FORMAT(trace->format_data)->stats,
				&len);
		FORMAT(trace->format_data)->stats_valid = 1;
	}

	return FORMAT(trace->format_data)->stats.tp_packets;
}

/* Number of packets that got past filtering and were then dropped because
 * of lack of space
 */
static uint64_t linuxnative_get_dropped_packets(libtrace_t *trace) {
	if (FORMAT(trace->format_data)->stats_valid != 1) {
		socklen_t len = sizeof(FORMAT(trace->format_data)->stats);
		getsockopt(FORMAT(trace->format_data)->fd, 
				SOL_PACKET,
				PACKET_STATISTICS,
				&FORMAT(trace->format_data)->stats,
				&len);
		FORMAT(trace->format_data)->stats_valid = 2;
	}

	return FORMAT(trace->format_data)->stats.tp_drops;
}

static void linuxnative_help(void) {
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
	"$Id$",
	TRACE_FORMAT_LINUX_NATIVE,
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
	NULL,				/* fin_packet */
	linuxnative_write_packet,	/* write_packet */
	linuxnative_get_link_type,	/* get_link_type */
	linuxnative_get_direction,	/* get_direction */
	linuxnative_set_direction,	/* set_direction */
	NULL,				/* get_erf_timestamp */
	linuxnative_get_timeval,	/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	linuxnative_get_capture_length,	/* get_capture_length */
	linuxnative_get_wire_length,	/* get_wire_length */
	linuxnative_get_framing_length,	/* get_framing_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_received_packets */
	linuxnative_get_filtered_packets,/* get_filtered_packets */
	linuxnative_get_dropped_packets,/* get_dropped_packets */
	linuxnative_get_captured_packets,/* get_captured_packets */
	linuxnative_get_fd,		/* get_fd */
	trace_event_device,		/* trace_event */
	linuxnative_help,		/* help */
	NULL
};

void linuxnative_constructor(void) {
	register_format(&linuxnative);
}
