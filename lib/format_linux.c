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

#ifdef HAVE_NETPACKET_PACKET_H

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/mman.h>

/* MAX_ORDER is defined in linux/mmzone.h. 10 is default for 2.4 kernel.
 * max_order will be decreased by one if the ring buffer fails to allocate.
 * Used to get correct sized buffers from the kernel.
 */
#define MAX_ORDER 10

/* Cached page size, the page size shouldn't be changing */
static int pagesize = 0;

/* Number of frames in the ring used by both TX and TR rings. More frames 
 * hopefully means less packet loss, especially if traffic comes in bursts.
 */
#define CONF_RING_FRAMES        0x100

/* The maximum frames allowed to be waiting in the TX_RING before the kernel is 
 * notified to write them out. Make sure this is less than CONF_RING_FRAMES. 
 * Performance doesn't seem to increase any more when setting this above 10.
 */
#define TX_MAX_QUEUE		10

/* Get current frame in the ring buffer*/
#define GET_CURRENT_BUFFER(libtrace) ((void *) FORMAT(libtrace->format_data)->rx_ring + \
	(FORMAT(libtrace->format_data)->rxring_offset * FORMAT(libtrace->format_data)->req.tp_frame_size))


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
#define	TP_STATUS_USER	0x1
#define	TP_STATUS_SEND_REQUEST	0x1
#define	TP_STATUS_AVAILABLE	0x0
#define TO_TP_HDR(x)	((struct tpacket2_hdr *) (x))
#define TPACKET_ALIGNMENT       16
#define TPACKET_ALIGN(x)        (((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))
#define TPACKET_HDRLEN         (TPACKET_ALIGN(sizeof(struct tpacket2_hdr)) + sizeof(struct sockaddr_ll))

enum tpacket_versions {
	TPACKET_V1,
	TPACKET_V2
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

struct tpacket_req {
	unsigned int tp_block_size;  /* Minimal size of contiguous block */
	unsigned int tp_block_nr;    /* Number of blocks */
	unsigned int tp_frame_size;  /* Size of frame */
	unsigned int tp_frame_nr;    /* Total number of frames */
};

struct linux_format_data_t {
	/* The file descriptor being used for the capture */
	int fd;
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
	/* Flag indicating whether the statistics are current or not */
	int stats_valid;
	/* The rx ring mmap location*/
	char * rx_ring;
	/* The current frame number within the rx ring */	
	int rxring_offset;
	/* The actual format being used - ring vs int */
	libtrace_rt_types_t format;
	/* The current ring buffer layout */
	struct tpacket_req req;
	/* Used to determine buffer size for the ring buffer */	
	uint32_t max_order;
};


/* Note that this structure is passed over the wire in rt encapsulation, and 
 * thus we need to be careful with data sizes.  timeval's and timespec's 
 * can also change their size on 32/64 machines.
 */

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

struct linux_output_format_data_t {
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
};

/* Get the sockaddr_ll structure from a frame */
#define GET_SOCKADDR_HDR(x)  ((struct sockaddr_ll *) (((char *) (x))\
	+ TPACKET_ALIGN(sizeof(struct tpacket2_hdr))))

#define FORMAT(x) ((struct linux_format_data_t*)(x))
#define DATAOUT(x) ((struct linux_output_format_data_t*)((x)->format_data))

/* Get the start of the captured data. I'm not sure if tp_mac (link layer) is
 * always guaranteed. If it's not there then just use tp_net.
 */
#define TP_TRACE_START(mac, net, hdrend) \
	((mac) > (hdrend) && (mac) < (net) ? (mac) : (net))


#ifdef HAVE_NETPACKET_PACKET_H
/*
 * Try figure out the best sizes for the ring buffer. Ensure that:
 * - max(Block_size) == page_size << max_order
 * - Frame_size == page_size << x (so that block_size%frame_size == 0)
 *   This means that there will be no wasted space between blocks
 * - Frame_size < block_size
 * - Frame_size is as close as possible to LIBTRACE_PACKET_BUFSIZE, but not 
 *   bigger
 * - Frame_nr = Block_nr * (frames per block)
 * - CONF_RING_FRAMES is used a minimum number of frames to hold
 * - Calculates based on max_order and buf_min
 */
static void calculate_buffers(struct tpacket_req * req, int fd, char * uri,
		uint32_t max_order){
	
	struct ifreq ifr;
	unsigned max_frame = LIBTRACE_PACKET_BUFSIZE;
	pagesize = getpagesize();

	strcpy(ifr.ifr_name, uri);
	/* Don't bother trying to set frame size above mtu linux will drop
	 * these anyway.
	 *
	 * Remember, that our frame also has to include a TPACKET header!
	 */
	if (ioctl(fd, SIOCGIFMTU, (caddr_t) &ifr) >= 0) 
		max_frame = ifr.ifr_mtu + TPACKET_ALIGN(TPACKET_HDRLEN);
	if (max_frame > LIBTRACE_PACKET_BUFSIZE)
		max_frame = LIBTRACE_PACKET_BUFSIZE;

	/* Calculate frame size */
	req->tp_frame_size = pagesize;
	while(req->tp_frame_size < max_frame && 
			req->tp_frame_size < LIBTRACE_PACKET_BUFSIZE){
		req->tp_frame_size <<= 1;
	}
	if(req->tp_frame_size > LIBTRACE_PACKET_BUFSIZE)
		req->tp_frame_size >>= 1;

	/* Calculate block size */
	req->tp_block_size = pagesize << max_order;
	do{
		req->tp_block_size >>= 1;
	} while((CONF_RING_FRAMES * req->tp_frame_size) <= req->tp_block_size);
	req->tp_block_size <<= 1;
	
	/* Calculate number of blocks */
	req->tp_block_nr = (CONF_RING_FRAMES * req->tp_frame_size) 
			/ req->tp_block_size;
	if((CONF_RING_FRAMES * req->tp_frame_size) % req->tp_block_size != 0)
		req->tp_block_nr++;

	/* Calculate packets such that we use all the space we have to allocated */
	req->tp_frame_nr = req->tp_block_nr * 
			(req->tp_block_size / req->tp_frame_size);

	/*
	printf("MaxO 0x%x BS 0x%x BN 0x%x FS 0x%x FN 0x%x\n", 
		max_order, 
		req->tp_block_size, 
		req->tp_block_nr, 
		req->tp_frame_size, 
		req->tp_frame_nr);
	*/
	
	/* In case we have some silly values*/
	assert(req->tp_block_size);
	assert(req->tp_block_nr);
	assert(req->tp_frame_size);
	assert(req->tp_frame_nr);
	assert(req->tp_block_size % req->tp_frame_size == 0);
}


static int linuxnative_probe_filename(const char *filename)
{
	/* Is this an interface? */
	return (if_nametoindex(filename) != 0);
}

static inline void init_input(libtrace_t *libtrace){
	libtrace->format_data = (struct linux_format_data_t *)
		malloc(sizeof(struct linux_format_data_t));
	FORMAT(libtrace->format_data)->fd = -1;
	FORMAT(libtrace->format_data)->promisc = -1;
	FORMAT(libtrace->format_data)->snaplen = LIBTRACE_PACKET_BUFSIZE;
	FORMAT(libtrace->format_data)->filter = NULL;
	FORMAT(libtrace->format_data)->stats_valid = 0;
	FORMAT(libtrace->format_data)->rx_ring = NULL;
	FORMAT(libtrace->format_data)->rxring_offset = 0;
	FORMAT(libtrace->format_data)->max_order = MAX_ORDER;
}
static int linuxring_init_input(libtrace_t *libtrace) 
{	
	init_input(libtrace);
	FORMAT(libtrace->format_data)->format = TRACE_FORMAT_LINUX_RING;
	return 0;
}
static int linuxnative_init_input(libtrace_t *libtrace) 
{
	init_input(libtrace);
	FORMAT(libtrace->format_data)->format = TRACE_FORMAT_LINUX_NATIVE;
	return 0;
}

static inline void init_output(libtrace_out_t *libtrace)
{
	libtrace->format_data = (struct linux_output_format_data_t*)
		malloc(sizeof(struct linux_output_format_data_t));
	DATAOUT(libtrace)->fd = -1;
	DATAOUT(libtrace)->tx_ring = NULL;
	DATAOUT(libtrace)->txring_offset = 0;
	DATAOUT(libtrace)->queue = 0;
	DATAOUT(libtrace)->max_order = MAX_ORDER;
}
static int linuxnative_init_output(libtrace_out_t *libtrace)
{
	init_output(libtrace);
	DATAOUT(libtrace)->format = TRACE_FORMAT_LINUX_NATIVE;
	return 0;
}
static int linuxring_init_output(libtrace_out_t *libtrace)
{
	init_output(libtrace);
	DATAOUT(libtrace)->format = TRACE_FORMAT_LINUX_RING;
	return 0;
}

static int linuxnative_start_input(libtrace_t *libtrace)
{
	struct sockaddr_ll addr;
	int one = 1;
	memset(&addr,0,sizeof(addr));
	libtrace_filter_t *filter = FORMAT(libtrace->format_data)->filter;
	
	/* Create a raw socket for reading packets on */
	FORMAT(libtrace->format_data)->fd = 
				socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (FORMAT(libtrace->format_data)->fd==-1) {
		trace_set_err(libtrace, errno, "Could not create raw socket");
		free(libtrace->format_data);
		libtrace->format_data = NULL;
		return -1;
	}

	/* Bind to the capture interface */
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (strlen(libtrace->uridata)) {
		addr.sll_ifindex = if_nametoindex(libtrace->uridata);
		if (addr.sll_ifindex == 0) {
			close(FORMAT(libtrace->format_data)->fd);
			trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Failed to find interface %s", libtrace->uridata);
			free(libtrace->format_data);
			libtrace->format_data = NULL;
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
		libtrace->format_data = NULL;
		trace_set_err(libtrace, errno, "Failed to bind to interface %s", libtrace->uridata);
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
	
	/* Enable promiscuous mode, if requested */			
	if (FORMAT(libtrace->format_data)->promisc) {
		struct packet_mreq mreq;
		socklen_t socklen = sizeof(mreq);
		memset(&mreq,0,sizeof(mreq));
		mreq.mr_ifindex = addr.sll_ifindex;
		mreq.mr_type = PACKET_MR_PROMISC;
		if (setsockopt(FORMAT(libtrace->format_data)->fd,
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
	if (setsockopt(FORMAT(libtrace->format_data)->fd,
			SOL_SOCKET,
			SO_TIMESTAMPNS,
			&one,
			(socklen_t)sizeof(one))!=-1) {
		FORMAT(libtrace->format_data)->timestamptype = TS_TIMESPEC;
	}
	else
	/* DANGER: This is a dangling else to only do the next setsockopt() if we fail the first! */
#endif
	if (setsockopt(FORMAT(libtrace->format_data)->fd,
			SOL_SOCKET,
			SO_TIMESTAMP,
			&one,
			(socklen_t)sizeof(one))!=-1) {
		FORMAT(libtrace->format_data)->timestamptype = TS_TIMEVAL;
	}
	else 
		FORMAT(libtrace->format_data)->timestamptype = TS_NONE;

	/* Push BPF filter into the kernel. At this stage we can safely assume
	 * that the filterstring has been compiled, or the filter was supplied
	 * pre-compiled.
	 */
	if (filter != NULL) {
                /* Check if the filter was successfully compiled. If not,
                 * it is probably a bad filter and we should return an error
                 * before the caller tries to read any packets */
		if (filter->flag == 0) {
                        return -1;
                }
                
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
static inline int socket_to_packetmmap(	char * uridata, int ring_type, 
					int fd, 
					struct tpacket_req * req,
					char ** ring_location,
					uint32_t *max_order,
					char *error){
	int val;

	/* Switch to TPACKET header version 2, we only try support v2 because v1 had problems */

	val = TPACKET_V2;
	if (setsockopt(fd, 
			SOL_PACKET, 
			PACKET_VERSION, 
			&val, 
			sizeof(val)) == -1){
		strncpy(error, "TPACKET2 not supported", 2048);
		return -1;
	}

	/* Try switch to a ring buffer. If it fails we assume the the kernel  
	 * cannot allocate a block of that size, so decrease max_block and retry.
	 */
	while(1) {	
		if (*max_order <= 0) {
			strncpy(error,"Cannot allocate enough memory for ring buffer", 2048);
			return -1;
		}
		calculate_buffers(req, fd, uridata, *max_order);
		if (setsockopt(fd, 
				SOL_PACKET, 
				ring_type, 
				req, 
				sizeof(struct tpacket_req)) == -1) {
			if(errno == ENOMEM){
				(*max_order)--;
			} else {
				strncpy(error, "Error setting the ring buffer size", 2048);
				return -1;
			}

		} else break;
	}
	
	/* Map the ring buffer into userspace */
	*ring_location = mmap(NULL, 
					req->tp_block_size * req->tp_block_nr, 
					PROT_READ | PROT_WRITE, 
					MAP_SHARED, 
					fd, 0);
	if(*ring_location == MAP_FAILED){
		strncpy(error, "Failed to map memory for ring buffer", 2048);
		return -1;
	}
	return 0;
}
static int linuxring_start_input(libtrace_t *libtrace){

	char error[2048];	

	/* We set the socket up the same and then convert it to PACKET_MMAP */
	if(linuxnative_start_input(libtrace) != 0)
		return -1;

	strncpy(error, "No known error", 2048);

	/* Make it a packetmmap */
	if(socket_to_packetmmap(libtrace->uridata, PACKET_RX_RING, 
			FORMAT(libtrace->format_data)->fd,
		 	&FORMAT(libtrace->format_data)->req, 
			&FORMAT(libtrace->format_data)->rx_ring,
			&FORMAT(libtrace->format_data)->max_order,
			error) != 0){
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Initialisation of packet MMAP failed: %s", error);
		close(DATAOUT(libtrace)->fd);
		free(libtrace->format_data);
		libtrace->format_data = NULL;
		return -1;
	}

	return 0;
}

static int linuxnative_start_output(libtrace_out_t *libtrace)
{
	DATAOUT(libtrace)->fd =	socket(PF_PACKET, SOCK_RAW, 0);
	if (DATAOUT(libtrace)->fd==-1) {
		free(DATAOUT(libtrace));
		return -1;
	}	

	return 0;
}

static int linuxring_start_output(libtrace_out_t *libtrace)
{
	char error[2048];	
	/* We set the socket up the same and then convert it to PACKET_MMAP */
	if(linuxnative_start_output(libtrace) != 0)
		return -1;

	/* Make it a packetmmap */
	if(socket_to_packetmmap(libtrace->uridata, PACKET_TX_RING, 
			DATAOUT(libtrace)->fd,
		 	&DATAOUT(libtrace)->req, 
			&DATAOUT(libtrace)->tx_ring,
			&DATAOUT(libtrace)->max_order,
			error) != 0){
		trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "Initialisation of packet MMAP failed: %s", error);
		close(DATAOUT(libtrace)->fd);
		free(libtrace->format_data);
		libtrace->format_data = NULL;
		return -1;
	}
	
	DATAOUT(libtrace)->sock_hdr.sll_family = AF_PACKET;
	DATAOUT(libtrace)->sock_hdr.sll_protocol = 0;
	DATAOUT(libtrace)->sock_hdr.sll_ifindex = 
					if_nametoindex(libtrace->uridata);
	DATAOUT(libtrace)->sock_hdr.sll_hatype = 0;
	DATAOUT(libtrace)->sock_hdr.sll_pkttype = 0;
	DATAOUT(libtrace)->sock_hdr.sll_halen = 0;
	DATAOUT(libtrace)->queue = 0;	

	return 0;
}

static int linuxnative_pause_input(libtrace_t *libtrace)
{
	close(FORMAT(libtrace->format_data)->fd);
	FORMAT(libtrace->format_data)->fd=-1;

	return 0;
}
static int linuxring_pause_input(libtrace_t *libtrace)
{
	munmap(FORMAT(libtrace->format_data)->rx_ring, 
		FORMAT(libtrace->format_data)->req.tp_block_size *
			FORMAT(libtrace->format_data)->req.tp_block_nr);
	FORMAT(libtrace->format_data)->rx_ring = NULL;
	return linuxnative_pause_input(libtrace);
}

static int linuxnative_fin_input(libtrace_t *libtrace) 
{
	if (libtrace->format_data) {
		if (FORMAT(libtrace->format_data)->filter != NULL)
			free(FORMAT(libtrace->format_data)->filter);
		free(libtrace->format_data);
	}
	
	return 0;
}

static int linuxnative_fin_output(libtrace_out_t *libtrace)
{
	close(DATAOUT(libtrace)->fd);
	DATAOUT(libtrace)->fd=-1;
	free(libtrace->format_data);
	return 0;
}
static int linuxring_fin_output(libtrace_out_t *libtrace)
{
	/* Make sure any remaining frames get sent */
	sendto(DATAOUT(libtrace)->fd, 
		NULL, 
		0, 
		0, 
		(void *) &DATAOUT(libtrace)->sock_hdr, 
		sizeof(DATAOUT(libtrace)->sock_hdr));

	/* Unmap our data area */
	munmap(DATAOUT(libtrace)->tx_ring,
		DATAOUT(libtrace)->req.tp_block_size * 
			DATAOUT(libtrace)->req.tp_block_nr);

	return linuxnative_fin_output(libtrace);
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
				FORMAT(libtrace->format_data)->snaplen);

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

static int linuxring_prepare_packet(libtrace_t *libtrace UNUSED, 
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
					TP_TRACE_START(
					TO_TP_HDR(packet->header)->tp_mac, 
					TO_TP_HDR(packet->header)->tp_net, 
					TPACKET_HDRLEN);
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
static int linuxnative_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) 
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
			(int)FORMAT(libtrace->format_data)->snaplen);

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

        /* Use select to allow us to time out occasionally to check if someone
         * has hit Ctrl-C or otherwise wants us to stop reading and return
         * so they can exit their program.
         */

        while (1) {
                tout.tv_sec = 0;
                tout.tv_usec = 500000;
                FD_ZERO(&readfds);
                FD_SET(FORMAT(libtrace->format_data)->fd, &readfds);

                ret = select(FORMAT(libtrace->format_data)->fd + 1, &readfds,
                                NULL, NULL, &tout);
                if (ret < 0 && errno != EINTR) {
                        trace_set_err(libtrace, errno, "select");
                        return -1;
                } else if (ret < 0) {
                        continue;
                } 
                
                if (FD_ISSET(FORMAT(libtrace->format_data)->fd, &readfds)) {
                        /* There's something available for us to read */
                        break;
                }

                
                /* If we get here, we timed out -- check if we should halt */
                if (libtrace_halt)
                        return 0;
        }

        hdr->wirelen = recvmsg(FORMAT(libtrace->format_data)->fd, &msghdr, MSG_TRUNC);

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
		if (ioctl(FORMAT(libtrace->format_data)->fd, 
				  SIOCGSTAMP,&tv)==0) {
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

#define LIBTRACE_BETWEEN(test,a,b) ((test) >= (a) && (test) < (b))
static int linuxring_get_capture_length(const libtrace_packet_t *packet);
static int linuxring_get_framing_length(const libtrace_packet_t *packet);

/* Release a frame back to the kernel or free() if it's a malloc'd buffer 
 */
inline static void ring_release_frame(libtrace_t *libtrace, libtrace_packet_t *packet ){
	/* Free the old packet */
	if(packet->buffer == NULL)
		return;

	if(packet->buf_control == TRACE_CTRL_PACKET){
		free(packet->buffer);
		packet->buffer = NULL;
	}
	if(packet->buf_control == TRACE_CTRL_EXTERNAL) {
		struct linux_format_data_t *ftd = FORMAT(libtrace->format_data);
		
		/* Check it's within our buffer first */
		if(LIBTRACE_BETWEEN((char *) packet->buffer, 
				(char *) ftd->rx_ring,
				ftd->rx_ring
				+ ftd->req.tp_block_size * ftd->req.tp_block_nr)){
			TO_TP_HDR(packet->buffer)->tp_status = 0;
			packet->buffer = NULL;
		}
	}
}

static int linuxring_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {

	struct tpacket2_hdr *header;
	struct pollfd pollset;	
	int ret;
	unsigned int snaplen;
	
	ring_release_frame(libtrace, packet);
	
	packet->buf_control = TRACE_CTRL_EXTERNAL;
	packet->type = TRACE_RT_DATA_LINUX_RING;
	
	/* Fetch the current frame */
	header = GET_CURRENT_BUFFER(libtrace);
	assert((((unsigned long) header) & (pagesize - 1)) == 0);

	/* TP_STATUS_USER means that we can read the frame.
	 * When a slot does not have this flag set, the frame is not
	 * ready for consumption.
	 */
	while (!(header->tp_status & TP_STATUS_USER)) {
		pollset.fd = FORMAT(libtrace->format_data)->fd;
		pollset.events = POLLIN;
		pollset.revents = 0;
		/* Wait for more data */
		ret = poll(&pollset, 1, 500);
		if (ret < 0) {
			if (errno != EINTR)
				trace_set_err(libtrace,errno,"poll()");
			return -1;
		} else if (ret == 0) {
			/* Poll timed out - check if we should exit */
			if (libtrace_halt)
				return 0;
			continue;
		}
	}

	packet->buffer = header;

	/* If a snaplen was configured, automatically truncate the packet to
	 * the desired length.
	 */
	snaplen=LIBTRACE_MIN(
			(int)LIBTRACE_PACKET_BUFSIZE-(int)sizeof(*header),
			(int)FORMAT(libtrace->format_data)->snaplen);
	
	TO_TP_HDR(packet->buffer)->tp_snaplen = LIBTRACE_MIN((unsigned int)snaplen, TO_TP_HDR(packet->buffer)->tp_len);

	/* Move to next buffer */
  	FORMAT(libtrace->format_data)->rxring_offset++;
	FORMAT(libtrace->format_data)->rxring_offset %= FORMAT(libtrace->format_data)->req.tp_frame_nr;

	/* We just need to get prepare_packet to set all our packet pointers
	 * appropriately */
	if (linuxring_prepare_packet(libtrace, packet, packet->buffer,
				packet->type, 0))
		return -1;
	return  linuxring_get_framing_length(packet) + 
				linuxring_get_capture_length(packet);

}

/* Non-blocking read */
static libtrace_eventobj_t linuxring_event(libtrace_t *libtrace, libtrace_packet_t *packet) {
	struct tpacket2_hdr *header;
	libtrace_eventobj_t event = {0,0,0.0,0};

	/* We must free the old packet, otherwise select() will instantly return 
	 */
	ring_release_frame(libtrace, packet);

	/* Fetch the current frame */
	header = GET_CURRENT_BUFFER(libtrace);
	if(header->tp_status & TP_STATUS_USER){
		/* We have a frame waiting */
		event.size = trace_read_packet(libtrace, packet);
		event.type = TRACE_EVENT_PACKET;
	} else {
		/* Ok we don't have a packet waiting */
		event.type = TRACE_EVENT_IOWAIT;
		event.fd = FORMAT(libtrace->format_data)->fd;
	}

	return event;
}


static int linuxnative_write_packet(libtrace_out_t *trace, 
		libtrace_packet_t *packet) 
{
	struct sockaddr_ll hdr;
	int ret = 0;

	if (trace_get_link_type(packet) == TRACE_TYPE_NONDATA)
		return 0;

	hdr.sll_family = AF_PACKET;
	hdr.sll_protocol = 0;
	hdr.sll_ifindex = if_nametoindex(trace->uridata);
	hdr.sll_hatype = 0;
	hdr.sll_pkttype = 0;
	hdr.sll_halen = htons(6); /* FIXME */
	memcpy(hdr.sll_addr,packet->payload,(size_t)ntohs(hdr.sll_halen));

	/* This is pretty easy, just send the payload using sendto() (after
	 * setting up the sll header properly, of course) */
	ret = sendto(DATAOUT(trace)->fd,
			packet->payload,
			trace_get_capture_length(packet),
			0,
			(struct sockaddr*)&hdr, (socklen_t)sizeof(hdr));

	if (ret < 0) {
		trace_set_err_out(trace, errno, "sendto failed");
	}

	return ret;

}
static int linuxring_write_packet(libtrace_out_t *trace, 
		libtrace_packet_t *packet)
{
	struct tpacket2_hdr *header;
	struct pollfd pollset;
	struct socket_addr;
	int ret; 
	unsigned max_size;
	void * off;

	if (trace_get_link_type(packet) == TRACE_TYPE_NONDATA)
		return 0;

	max_size = DATAOUT(trace)->req.tp_frame_size - 
		 - TPACKET_HDRLEN + sizeof(struct sockaddr_ll);

	header = (void *) DATAOUT(trace)->tx_ring + 
	(DATAOUT(trace)->txring_offset * DATAOUT(trace)->req.tp_frame_size);

	while(header->tp_status != TP_STATUS_AVAILABLE){
		/* if none available: wait on more data */
		pollset.fd = DATAOUT(trace)->fd;
		pollset.events = POLLOUT;
		pollset.revents = 0;
		ret = poll(&pollset, 1, 1000);
		if (ret < 0 && errno != EINTR) {
       			perror("poll");
        		return -1;
		}
		if(ret == 0) 
			/* Timeout something has gone wrong - maybe the queue is
			 * to large so try issue another send command
			 */
			ret = sendto(DATAOUT(trace)->fd, 
				NULL, 
				0, 
				0, 
				(void *) &DATAOUT(trace)->sock_hdr, 
				sizeof(DATAOUT(trace)->sock_hdr));
			if (ret < 0) {
				trace_set_err_out(trace, errno, 
						"sendto after timeout failed");
				return -1;
			}
	}
	
	header->tp_len = trace_get_capture_length(packet);

	/* We cannot write the whole packet so just write part of it */
	if (header->tp_len > max_size)
		header->tp_len = max_size;

	/* Fill packet - no sockaddr_ll in header when writing to the TX_RING */
	off = ((void *) header) + (TPACKET_HDRLEN - sizeof(struct sockaddr_ll));
	memcpy(off, 
		(char *) packet->payload, 
		header->tp_len);
	
	/* 'Send it' and increase ring pointer to the next frame */
	header->tp_status = TP_STATUS_SEND_REQUEST;
	DATAOUT(trace)->txring_offset = (DATAOUT(trace)->txring_offset + 1) %  
						DATAOUT(trace)->req.tp_frame_nr;

	/* Notify kernel there are frames to send */
	DATAOUT(trace)->queue ++;
	DATAOUT(trace)->queue %= TX_MAX_QUEUE;
	if(DATAOUT(trace)->queue == 0){
		ret = sendto(DATAOUT(trace)->fd, 
				NULL, 
				0, 
				MSG_DONTWAIT, 
				(void *) &DATAOUT(trace)->sock_hdr, 
				sizeof(DATAOUT(trace)->sock_hdr));
		if (ret < 0) {
			trace_set_err_out(trace, errno, "sendto failed");
			return -1;
		}
	}
	return header->tp_len;

}
#endif /* HAVE_NETPACKET_PACKET_H */

static inline libtrace_linktype_t get_libtrace_link_type(uint16_t linktype){
	/* Convert the ARPHRD type into an appropriate libtrace link type */
	switch (linktype) {
		case LIBTRACE_ARPHRD_ETHER:
		case LIBTRACE_ARPHRD_LOOPBACK:
			return TRACE_TYPE_ETH;
		case LIBTRACE_ARPHRD_PPP:
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
static libtrace_linktype_t linuxnative_get_link_type(const struct libtrace_packet_t *packet) {
	uint16_t linktype=(((struct libtrace_linuxnative_header*)(packet->buffer))
				->hdr.sll_hatype);
	return get_libtrace_link_type(linktype);
}
static libtrace_linktype_t linuxring_get_link_type(const struct libtrace_packet_t *packet) {
	uint16_t linktype= GET_SOCKADDR_HDR(packet->buffer)->sll_hatype;
	return get_libtrace_link_type(linktype);
}

static inline libtrace_direction_t get_libtrace_direction(uint8_t pkttype){
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
static libtrace_direction_t linuxnative_get_direction(const struct libtrace_packet_t *packet) {
	return get_libtrace_direction(((struct libtrace_linuxnative_header*)(packet->buffer))->hdr.sll_pkttype);
}
static libtrace_direction_t linuxring_get_direction(const struct libtrace_packet_t *packet) {
	return get_libtrace_direction(GET_SOCKADDR_HDR(packet->buffer)->sll_pkttype);
}

static libtrace_direction_t set_direction(struct sockaddr_ll * skadr, libtrace_direction_t direction){
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
static libtrace_direction_t linuxnative_set_direction(
		libtrace_packet_t *packet,
		libtrace_direction_t direction) {
	return set_direction(&((struct libtrace_linuxnative_header*)(packet->buffer))->hdr, direction);
}
static libtrace_direction_t linuxring_set_direction(
		libtrace_packet_t *packet,
		libtrace_direction_t direction) {
	return set_direction(GET_SOCKADDR_HDR(packet->buffer), direction);
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
static struct timespec linuxring_get_timespec(const libtrace_packet_t *packet) 
{
	struct timespec ts;
	ts.tv_sec = TO_TP_HDR(packet->buffer)->tp_sec;
	ts.tv_nsec = TO_TP_HDR(packet->buffer)->tp_nsec;
	return ts;
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
static struct timeval linuxring_get_timeval(const libtrace_packet_t *packet) 
{
	struct timeval tv;
	tv.tv_sec = TO_TP_HDR(packet->buffer)->tp_sec;
	tv.tv_usec = TO_TP_HDR(packet->buffer)->tp_nsec / 1000;
	return tv;
}

static int linuxnative_get_capture_length(const libtrace_packet_t *packet)
{
	return ((struct libtrace_linuxnative_header*)(packet->buffer))->caplen;
}

static int linuxring_get_capture_length(const libtrace_packet_t *packet)
{
	return TO_TP_HDR(packet->buffer)->tp_snaplen;
}

static int linuxnative_get_wire_length(const libtrace_packet_t *packet) 
{

	int wirelen = ((struct libtrace_linuxnative_header*)(packet->buffer))->wirelen;

	/* Include the missing FCS */
	if (trace_get_link_type(packet) == TRACE_TYPE_ETH)
		wirelen += 4;

	return wirelen;
}

static int linuxring_get_wire_length(const libtrace_packet_t *packet) 
{
	int wirelen = TO_TP_HDR(packet->buffer)->tp_len;

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

static int linuxring_get_framing_length(const libtrace_packet_t *packet)
{	
	/* 
	 * Need to make frame_length + capture_length = complete capture length 
	 * so include alligment whitespace. So reverse calculate from packet.
	 */
	return (char *) packet->payload - (char *) packet->buffer;
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

static size_t linuxring_set_capture_length(libtrace_packet_t *packet, 
		size_t size) {
	assert(packet);
	if (size > trace_get_capture_length(packet)) {
		/* We should avoid making a packet larger */
		return trace_get_capture_length(packet);
	}
	
	/* Reset the cached capture length */
	packet->capture_length = -1;

	TO_TP_HDR(packet->buffer)->tp_snaplen = size;

	return trace_get_capture_length(packet);
}

static int linuxnative_get_fd(const libtrace_t *trace) {
	if (trace->format_data == NULL)
		return -1;
	return FORMAT(trace->format_data)->fd;
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

/* Number of packets that passed filtering */
static uint64_t linuxnative_get_captured_packets(libtrace_t *trace) {
	if (trace->format_data == NULL)
		return UINT64_MAX;
	if (FORMAT(trace->format_data)->fd == -1) {
		/* This is probably a 'dead' trace so obviously we can't query
		 * the socket for capture counts, can we? */
		return UINT64_MAX;
	}

#ifdef HAVE_NETPACKET_PACKET_H	
	if ((FORMAT(trace->format_data)->stats_valid & 1) 
			|| FORMAT(trace->format_data)->stats_valid == 0) {
		socklen_t len = sizeof(FORMAT(trace->format_data)->stats);
		getsockopt(FORMAT(trace->format_data)->fd, 
				SOL_PACKET,
				PACKET_STATISTICS,
				&FORMAT(trace->format_data)->stats,
				&len);
		FORMAT(trace->format_data)->stats_valid |= 1;
	}

	return FORMAT(trace->format_data)->stats.tp_packets;
#else
	return UINT64_MAX;
#endif
}

/* Number of packets that got past filtering and were then dropped because
 * of lack of space
 */
static uint64_t linuxnative_get_dropped_packets(libtrace_t *trace) {
	if (trace->format_data == NULL)
		return UINT64_MAX;
	if (FORMAT(trace->format_data)->fd == -1) {
		/* This is probably a 'dead' trace so obviously we can't query
		 * the socket for drop counts, can we? */
		return UINT64_MAX;
	}
	
#ifdef HAVE_NETPACKET_PACKET_H	
	if ((FORMAT(trace->format_data)->stats_valid & 2)
			|| (FORMAT(trace->format_data)->stats_valid==0)) {
		socklen_t len = sizeof(FORMAT(trace->format_data)->stats);
		getsockopt(FORMAT(trace->format_data)->fd, 
				SOL_PACKET,
				PACKET_STATISTICS,
				&FORMAT(trace->format_data)->stats,
				&len);
		FORMAT(trace->format_data)->stats_valid |= 2;
	}

	return FORMAT(trace->format_data)->stats.tp_drops;
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

static void linuxring_help(void) {
	printf("linuxring format module: $Revision: 1793 $\n");
	printf("Supported input URIs:\n");
	printf("\tring:eth0\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tring:eth0\n");
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
	NULL
};

static struct libtrace_format_t linuxring = {
	"ring",
	"$Id$",
	TRACE_FORMAT_LINUX_RING,
	linuxnative_probe_filename,	/* probe filename */
	NULL,				/* probe magic */
	linuxring_init_input,	 	/* init_input */
	linuxnative_config_input,	/* config_input */
	linuxring_start_input,	/* start_input */
	linuxring_pause_input,	/* pause_input */
	linuxring_init_output,	/* init_output */
	NULL,				/* config_output */
	linuxring_start_output,	/* start_ouput */
	linuxnative_fin_input,		/* fin_input */
	linuxring_fin_output,		/* fin_output */
	linuxring_read_packet,	/* read_packet */
	linuxring_prepare_packet,	/* prepare_packet */
	NULL,				/* fin_packet */
	linuxring_write_packet,	/* write_packet */
	linuxring_get_link_type,	/* get_link_type */
	linuxring_get_direction,	/* get_direction */
	linuxring_set_direction,	/* set_direction */
	NULL,				/* get_erf_timestamp */
	linuxring_get_timeval,	/* get_timeval */
	linuxring_get_timespec,	/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	linuxring_get_capture_length,	/* get_capture_length */
	linuxring_get_wire_length,	/* get_wire_length */
	linuxring_get_framing_length,	/* get_framing_length */
	linuxring_set_capture_length,	/* set_capture_length */
	NULL,				/* get_received_packets */
	linuxnative_get_filtered_packets,/* get_filtered_packets */
	linuxnative_get_dropped_packets,/* get_dropped_packets */
	linuxnative_get_captured_packets,/* get_captured_packets */
	linuxnative_get_fd,		/* get_fd */
	linuxring_event,		/* trace_event */
	linuxring_help,		/* help */
	NULL
};
#else
static void linuxnative_help(void) {
	printf("linuxnative format module: $Revision: 1793 $\n");
	printf("Not supported on this host\n");
}
static void linuxring_help(void) {
	printf("linuxring format module: $Revision: 1793 $\n");
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
	NULL
};

static struct libtrace_format_t linuxring = {
	"ring",
	"$Id$",
	TRACE_FORMAT_LINUX_RING,
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
	linuxring_prepare_packet,	/* prepare_packet */
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	linuxring_get_link_type,	/* get_link_type */
	linuxring_get_direction,	/* get_direction */
	linuxring_set_direction,	/* set_direction */
	NULL,				/* get_erf_timestamp */
	linuxring_get_timeval,		/* get_timeval */
	linuxring_get_timespec,		/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	linuxring_get_capture_length,	/* get_capture_length */
	linuxring_get_wire_length,	/* get_wire_length */
	linuxring_get_framing_length,	/* get_framing_length */
	linuxring_set_capture_length,	/* set_capture_length */
	NULL,				/* get_received_packets */
	linuxnative_get_filtered_packets,/* get_filtered_packets */
	linuxnative_get_dropped_packets,/* get_dropped_packets */
	linuxnative_get_captured_packets,/* get_captured_packets */
	linuxnative_get_fd,		/* get_fd */
	NULL,				/* trace_event */
	linuxring_help,			/* help */
	NULL
};

#endif /* HAVE_NETPACKET_PACKET_H */


void linuxnative_constructor(void) {
	/* TODO: once we're happy with ring:, it would be a good idea to 
	 * swap the order of these calls so that ring: is preferred over
	 * int: if the user just gives an interface name as an input without
	 * explicitly choosing a format.
	 */
	register_format(&linuxnative);
	register_format(&linuxring);
}
