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


/* Various definitions required for the linux format. They were moved here,
 * because format_linux.c had a lot of header information before the actual
 * code. The linux headers have been copied into here rather than included to
 * support RT on machines that don't have the linux headers (like a mac for
 * example.
 */

#ifndef FORMAT_LINUX_COMMON_H
#define FORMAT_LINUX_COMMON_H

#include "libtrace.h"
#include "libtrace_int.h"

#ifdef HAVE_NETPACKET_PACKET_H

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/sockios.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/mman.h>

#include <fcntl.h>

/* MAX_ORDER is defined in linux/mmzone.h. 11 is default for 3.0 kernels.
 * max_order will be decreased by one if the ring buffer fails to allocate.
 * Used to get the correct sized buffers from the kernel.
 */
#define MAX_ORDER 11
/* Number of frames in the ring used by both TX and TR rings. More frames 
 * hopefully means less packet loss, especially if traffic comes in bursts.
 */
#define CONF_RING_FRAMES        0x100

#else	/* HAVE_NETPACKET_PACKET_H */

/* Need to know what a sockaddr_ll looks like */
struct sockaddr_ll {
	uint16_t sll_family;
	uint16_t sll_protocol;
	int32_t  sll_ifindex;
	uint16_t sll_hatype;
	uint8_t  sll_pkttype;
	uint8_t  sll_halen;
 	uint8_t  sll_addr[8];
};

/* Packet types.  */
#define PACKET_HOST             0               /* To us.  */
#define PACKET_BROADCAST        1               /* To all.  */
#define PACKET_MULTICAST        2               /* To group.  */
#define PACKET_OTHERHOST        3               /* To someone else.  */
#define PACKET_OUTGOING         4               /* Originated by us . */
#define PACKET_LOOPBACK         5
#define PACKET_FASTROUTE        6

/* Packet socket options.  */

#define PACKET_ADD_MEMBERSHIP           1
#define PACKET_DROP_MEMBERSHIP          2
#define PACKET_RECV_OUTPUT              3
#define PACKET_RX_RING                  5
#define PACKET_STATISTICS               6

#endif /* HAVE_NETPACKET_PACKET_H */

struct tpacket_stats {
	unsigned int tp_packets;
	unsigned int tp_drops;
};

typedef enum { TS_NONE, TS_TIMEVAL, TS_TIMESPEC } timestamptype_t;

/* linux/if_packet.h defines. They are here rather than including the header
 * this means that we can interpret a ring frame on a kernel that doesn't
 * support the format directly.
 */
#define	PACKET_RX_RING	5
#define PACKET_VERSION	10
#define PACKET_HDRLEN	11
#define	PACKET_TX_RING	13
#define PACKET_FANOUT	18
#define	TP_STATUS_USER	0x1
#define	TP_STATUS_SEND_REQUEST	0x1
#define	TP_STATUS_AVAILABLE	0x0
#define TO_TP_HDR2(x)	((struct tpacket2_hdr *) (x))
#define TO_TP_HDR3(x)	((struct tpacket3_hdr *) (x))
#define TPACKET_ALIGNMENT       16
#define TPACKET_ALIGN(x)        (((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))
#define TPACKET2_HDRLEN		(TPACKET_ALIGN(sizeof(struct tpacket2_hdr)) + sizeof(struct sockaddr_ll))
#define TPACKET3_HDRLEN		(TPACKET_ALIGN(sizeof(struct tpacket3_hdr)) + sizeof(struct sockaddr_ll))


/* Since 3.1 kernel we have packet_fanout support */
// schedule to socket by skb's rxhash - the implementation is bi-directional
#define PACKET_FANOUT_HASH              0
// schedule round robin
#define PACKET_FANOUT_LB                1
// schedule to the same socket that received the packet
#define PACKET_FANOUT_CPU               2
// Something to do with fragmented packets and hashing problems !! TODO figure out if this needs to be on
#define PACKET_FANOUT_FLAG_DEFRAG       0x8000
/* Included but unused by libtrace since Linux 3.10 */
// if one socket if full roll over to the next
#define PACKET_FANOUT_ROLLOVER          3
// This flag makes any other system roll over
#define PACKET_FANOUT_FLAG_ROLLOVER     0x1000
/* Included but unused by libtrace since Linux 3.12 */
// schedule random
#define PACKET_FANOUT_RND               4


enum tpacket_versions {
	TPACKET_V1,
	TPACKET_V2,
	TPACKET_V3
};

struct tpacket2_hdr {
	/* Frame status - in use by kernel or libtrace etc. */
	uint32_t	tp_status;
	/* Wire length */
	uint32_t	tp_len;
	/* Captured length */
	uint32_t	tp_snaplen;
	/* Offset in bytes from frame start to the mac (link layer) header */
	uint16_t	tp_mac;
	/* Offset in bytes from frame start to the net (network layer) header */
	uint16_t	tp_net;
	/* Timestamp */
	uint32_t	tp_sec;
	uint32_t	tp_nsec;
	/* Not used VLAN tag control information */
	uint16_t	tp_vlan_tci;
	uint16_t	tp_padding;
};

struct tpacket_hdr_variant1 {
	uint32_t	tp_rxhash;
	uint32_t	tp_vlan_tci;
};

struct tpacket3_hdr {
	uint32_t		tp_next_offset;
	uint32_t		tp_sec;
	uint32_t		tp_nsec;
	uint32_t		tp_snaplen;
	uint32_t		tp_len;
	uint32_t		tp_status;
	uint16_t		tp_mac;
	uint16_t		tp_net;
	/* pkt_hdr variants */
	union {
		struct tpacket_hdr_variant1 hv1;
	};
};

struct tpacket_req {
	unsigned int tp_block_size;  /* Minimal size of contiguous block */
	unsigned int tp_block_nr;    /* Number of blocks */
	unsigned int tp_frame_size;  /* Size of frame */
	unsigned int tp_frame_nr;    /* Total number of frames */
};

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

/* A structure we use to hold statistic counters from the network cards
 * as accessed via the /proc/net/dev
 */
struct linux_dev_stats {
	char if_name[IF_NAMESIZE];
	uint64_t rx_bytes;
	uint64_t rx_packets;
	uint64_t rx_errors;
	uint64_t rx_drops;
	uint64_t rx_fifo;
	uint64_t rx_frame;
	uint64_t rx_compressed;
	uint64_t rx_multicast;
	uint64_t tx_bytes;
	uint64_t tx_packets;
	uint64_t tx_errors;
	uint64_t tx_drops;
	uint64_t tx_fifo;
	uint64_t tx_colls;
	uint64_t tx_carrier;
	uint64_t tx_compressed;
};

/* Note that this structure is passed over the wire in rt encapsulation, and
 * thus we need to be careful with data sizes.  timeval's and timespec's
 * can also change their size on 32/64 machines.
 */
struct linux_format_data_t {
	/* The snap length for the capture */
	int snaplen;
	/* Flag indicating whether the interface should be placed in
	 * promiscuous mode */
	int promisc;
	/* The timestamp format used by the capture */
	timestamptype_t timestamptype;
	/* A BPF filter that is applied to every captured packet */
	libtrace_filter_t *filter;
	/* Statistics for the capture process, e.g. dropped packet counts */
	struct tpacket_stats stats;
	/* Statistics for the NIC rather than the socket */
	struct linux_dev_stats dev_stats;
	/* Flag indicating whether the statistics are current or not */
	int stats_valid;
	/* Used to determine buffer size for the ring buffer */
	uint32_t max_order;
	/* Used for the parallel case, fanout is the mode */
	uint16_t fanout_flags;
	/* The group lets Linux know which sockets to group together
	 * so we use a random here to try avoid collisions */
	uint16_t fanout_group;
	/* When running in parallel mode this is malloc'd with an array
	 * file descriptors from packet fanout will use, here we assume/hope
	 * that every ring can get setup the same */
	libtrace_list_t *per_stream;

};

struct linux_format_data_out_t {
	/* The file descriptor used to write the packets */
	int fd;
	/* The tx ring mmap location */
	char * tx_ring;
	/* The current frame number within the tx ring */
	int txring_offset;
	/* The current ring buffer layout */
	struct tpacket_req req;
	/* Our sockaddr structure, here so we can cache the interface number */
	struct sockaddr_ll sock_hdr;
	/* The (maximum) number of packets that haven't been written */
	int queue;
	/* The format this trace is using linuxring or linuxnative */
	libtrace_rt_types_t format;
	/* Used to determine buffer size for the ring buffer */
	uint32_t max_order;
        /* Maximum number of packets allowed in the tx queue before notifying the kernel */
        int tx_max_queue;
};

struct linux_per_stream_t {
	/* File descriptor for the memory mapped stream */
	int fd;
	/* Memory mapped buffer */
	char *rx_ring;
	/* Offset within the mapped buffer */
	int rxring_offset;
	/* The ring buffer layout */
	struct tpacket_req req;
	uint64_t last_timestamp;
} ALIGN_STRUCT(CACHE_LINE_SIZE);

#define ZERO_LINUX_STREAM {-1, MAP_FAILED, 0, {0,0,0,0}, 0}


/* Format header for encapsulating packets captured using linux native */
struct libtrace_linuxnative_header {
	/* Timestamp of the packet, as a timeval */
	struct {
		uint32_t tv_sec;
		uint32_t tv_usec;
	} tv;
	/* Timestamp of the packet, as a timespec */
	struct {
		uint32_t tv_sec;
		uint32_t tv_nsec;
	} ts;
	/* The timestamp format used by the process that captured this packet */
	uint8_t timestamptype;
	/* Wire length */
	uint32_t wirelen;
	/* Capture length */
	uint32_t caplen;
	/* The linux native header itself */
	struct sockaddr_ll hdr;
};

/* Helper macros to make addressing data in the above structures easier */
#define DATA(x) ((struct linux_format_data_t *)x->format_data)
#define DATA_OUT(x) ((struct linux_format_data_out_t *)x->format_data)
#define STREAM_DATA(x) ((struct linux_per_stream_t *)x->data)

#define FORMAT_DATA DATA(libtrace)
#define FORMAT_DATA_OUT DATA_OUT(libtrace)

#define FORMAT_DATA_HEAD FORMAT_DATA->per_stream->head
#define FORMAT_DATA_FIRST ((struct linux_per_stream_t *)FORMAT_DATA_HEAD->data)

/* Get the sockaddr_ll structure from a frame */
#define GET_SOCKADDR_HDR(x)  ((struct sockaddr_ll *) (((char *) (x))\
	+ TPACKET_ALIGN(sizeof(struct tpacket2_hdr))))

/* Common functions */
#ifdef HAVE_NETPACKET_PACKET_H
int linuxcommon_init_input(libtrace_t *libtrace);
int linuxcommon_init_output(libtrace_out_t *libtrace);
int linuxcommon_probe_filename(const char *filename);
int linuxcommon_config_input(libtrace_t *libtrace, trace_option_t option,
                             void *data);
int linuxcommon_config_output(libtrace_out_t *libtrace, trace_option_output_t option,
                             void *data);
void linuxcommon_close_input_stream(libtrace_t *libtrace,
                                    struct linux_per_stream_t *stream);
int linuxcommon_start_input_stream(libtrace_t *libtrace,
                                   struct linux_per_stream_t *stream);
int linuxcommon_pause_input(libtrace_t *libtrace);
int linuxcommon_get_fd(const libtrace_t *libtrace);
int linuxcommon_fin_input(libtrace_t *libtrace);
int linuxcommon_pregister_thread(libtrace_t *libtrace,
                                 libtrace_thread_t *t,
                                 bool reading);
int linuxcommon_pstart_input(libtrace_t *libtrace,
                             int (*start_stream)(libtrace_t *, struct linux_per_stream_t*));
#endif /* HAVE_NETPACKET_PACKET_H */

void linuxcommon_get_statistics(libtrace_t *libtrace, libtrace_stat_t *stat);

static inline libtrace_direction_t linuxcommon_get_direction(uint8_t pkttype)
{
	switch (pkttype) {
		case PACKET_OUTGOING:
		case PACKET_LOOPBACK:
			return TRACE_DIR_OUTGOING;
		case PACKET_OTHERHOST:
			return TRACE_DIR_OTHER;
		default:
			return TRACE_DIR_INCOMING;
	}
}

static inline libtrace_direction_t
linuxcommon_set_direction(struct sockaddr_ll * skadr,
                          libtrace_direction_t direction)
{
	switch (direction) {
		case TRACE_DIR_OUTGOING:
			skadr->sll_pkttype = PACKET_OUTGOING;
			return TRACE_DIR_OUTGOING;
		case TRACE_DIR_INCOMING:
			skadr->sll_pkttype = PACKET_HOST;
			return TRACE_DIR_INCOMING;
		case TRACE_DIR_OTHER:
			skadr->sll_pkttype = PACKET_OTHERHOST;
			return TRACE_DIR_OTHER;
		default:
			return -1;
	}
}

static inline libtrace_linktype_t linuxcommon_get_link_type(uint16_t linktype)
{
	/* Convert the ARPHRD type into an appropriate libtrace link type */
	switch (linktype) {
		case LIBTRACE_ARPHRD_ETHER:
		case LIBTRACE_ARPHRD_LOOPBACK:
			return TRACE_TYPE_ETH;
		case LIBTRACE_ARPHRD_PPP:
		case LIBTRACE_ARPHRD_IPGRE:
			return TRACE_TYPE_NONE;
		case LIBTRACE_ARPHRD_IEEE80211_RADIOTAP:
			return TRACE_TYPE_80211_RADIO;
		case LIBTRACE_ARPHRD_IEEE80211:
			return TRACE_TYPE_80211;
		case LIBTRACE_ARPHRD_SIT:
		case LIBTRACE_ARPHRD_NONE:
			return TRACE_TYPE_NONE;
		default: /* shrug, beyond me! */
			printf("unknown Linux ARPHRD type 0x%04x\n",linktype);
			return (libtrace_linktype_t)~0U;
	}
}

#ifdef HAVE_NETPACKET_PACKET_H
/**
 * Converts a socket, either packet_mmap or standard raw socket into a
 * fanout socket.
 * NOTE: This means we can read from the socket with multiple queues,
 * each must be setup (identically) and then this called upon them
 *
 * @return 0 success, -1 error
 */
static inline int linuxcommon_to_packet_fanout(libtrace_t *libtrace,
                                        struct linux_per_stream_t *stream)
{
        int fanout_opt;
        int attempts = 0;
        while (attempts < 5) {
                fanout_opt = ((int)FORMAT_DATA->fanout_flags << 16) |
                                 (int)FORMAT_DATA->fanout_group;

                if (setsockopt(stream->fd, SOL_PACKET, PACKET_FANOUT,
                                &fanout_opt, sizeof(fanout_opt)) == -1) {
                        FORMAT_DATA->fanout_group ++;
                        attempts ++;
                        continue;
                }
                return 0;
        }
        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
                        "Converting the fd to a socket fanout failed %s",
                        libtrace->uridata);
        return -1;
}
#endif /* HAVE_NETPACKET_PACKET_H */


#endif /* FORMAT_LINUX_COMMON_H */
