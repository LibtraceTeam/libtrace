/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007-2015 The University of Waikato, Hamilton,
 * New Zealand.
 *
 * Author: Shane Alcock
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
 */

#include "config.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "data-struct/linked_list.h"

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#if HAVE_LIBNUMA
#include <numa.h>
#endif

#include <pthread.h>
#ifdef __FreeBSD__
#include <pthread_np.h>
#endif

#include <pfring.h>

struct pfring_format_data_t {
	libtrace_list_t *per_stream;	
	int8_t promisc;
	int snaplen;
	int8_t ringenabled;
	char *bpffilter;
};

struct pfring_per_stream_t {

	pfring *pd;
	int affinity;

} ALIGN_STRUCT(CACHE_LINE_SIZE);

#define ZERO_PFRING_STREAM {NULL, -1}

#define DATA(x) ((struct pfring_format_data_t *)x->format_data)
#define STREAM_DATA(x) ((struct pfring_per_stream_t *)x->data)

#define FORMAT_DATA DATA(libtrace)
#define FORMAT_DATA_HEAD FORMAT_DATA->per_stream->head
#define FORMAT_DATA_FIRST ((struct pfring_per_stream_t *)FORMAT_DATA_HEAD->data)


typedef union {
	uint32_t ipv4;
	uint8_t ipv6[16];
} ip_addr_union;

struct tunnelinfo {
	uint32_t id;
	uint8_t tunneledproto;
	ip_addr_union tunnel_src;
	ip_addr_union tunnel_dst;
	uint16_t tunnel_srcport;
	uint16_t tunnel_dstport;
};

struct pktoffset {
	int16_t ethoffset;
	int16_t vlanoffset;
	int16_t l3offset;
	int16_t l4offset;
	int16_t payloadoffset;
};

struct parsing_info {
	uint8_t dmac[ETH_ALEN];
	uint8_t smac[ETH_ALEN];
	uint16_t eth_type;
	uint16_t vlan_id;
	uint8_t ip_version;
	uint8_t l3_proto;
	uint8_t ip_tos;
	ip_addr_union ip_src;
	ip_addr_union ip_dst;
	uint16_t l4_src_port;
	uint16_t l4_dst_port;
	struct {
		uint8_t flags;
		uint32_t seqno;
		uint32_t ackno;
	} tcp;
	struct tunnelinfo tunnel;
	uint16_t last_matched_plugin;
	uint16_t last_matched_rule;
	struct pktoffset offset;

};

struct libtrace_pfring_extend {

	uint64_t ts_ns;
	uint32_t flags;
	uint8_t direction;
	int32_t if_index;
	uint32_t hash;
	struct {
		int bounce_iface;
		void *reserved;
	} tx;
	uint16_t parsed_hdr_len;
	struct parsing_info parsed;
};

struct local_pfring_header {
	struct timeval ts;
	uint32_t caplen;
	uint32_t wlen;
	struct libtrace_pfring_extend ext;	
	
};


struct libtrace_pfring_header {
	struct {
		uint64_t tv_sec;
		uint64_t tv_usec;
	} ts;
	uint32_t caplen;
	uint32_t wlen;
	struct libtrace_pfring_extend ext;	
	
};

static inline int pfring_start_input_stream(libtrace_t *libtrace,
		struct pfring_per_stream_t *stream) {

	int rc;

	if (FORMAT_DATA->bpffilter) {
		rc = pfring_set_bpf_filter(stream->pd, FORMAT_DATA->bpffilter);
		if (rc != 0) {
			trace_set_err(libtrace, TRACE_ERR_BAD_FILTER,
				"Failed to set BPF filter on pfring:");
			return -1;
		}
	}

	if ((rc = pfring_set_socket_mode(stream->pd, recv_only_mode)) != 0) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				"Failed to set recv only mode on pfring:");
		return -1;
	}

	if (pfring_enable_ring(stream->pd) != 0) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, 
			"Failed to enable the pfring");
		return -1;
	}
	
	return 0;

}

static int pfring_start_input(libtrace_t *libtrace) {
	struct pfring_per_stream_t *stream = FORMAT_DATA_FIRST;
	if (libtrace->uridata == NULL) {
		trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, 
				"Missing interface name from pfring: URI");
		return -1;
	}
	uint32_t flags = PF_RING_TIMESTAMP | PF_RING_LONG_HEADER;
	flags |= PF_RING_HW_TIMESTAMP;

	if (FORMAT_DATA->promisc > 0) 
		flags |= PF_RING_PROMISC;
	
	if (FORMAT_DATA->ringenabled) {
		trace_set_err(libtrace, TRACE_ERR_BAD_STATE,
			"Attempted to start a pfring: input that was already started!");
		return -1;
	}

	stream->pd = pfring_open(libtrace->uridata, FORMAT_DATA->snaplen, flags);

	return pfring_start_input_stream(libtrace, FORMAT_DATA_FIRST);
}

static int pfring_init_input(libtrace_t *libtrace) {

	struct pfring_per_stream_t stream_data = ZERO_PFRING_STREAM;

	libtrace->format_data = (struct pfring_format_data_t *)
		malloc(sizeof(struct pfring_format_data_t));
	assert(libtrace->format_data != NULL);

	FORMAT_DATA->promisc = -1;
	FORMAT_DATA->snaplen = LIBTRACE_PACKET_BUFSIZE;
	FORMAT_DATA->per_stream = libtrace_list_init(sizeof(stream_data));
	FORMAT_DATA->ringenabled = 0;
	FORMAT_DATA->bpffilter = NULL;

	libtrace_list_push_back(FORMAT_DATA->per_stream, &stream_data);

	return 0;
}

static int pfring_config_input(libtrace_t *libtrace, trace_option_t option,
		void *data) {

	switch (option) {
		case TRACE_OPTION_SNAPLEN:
			FORMAT_DATA->snaplen = *(int *)data;
			return 0;
		case TRACE_OPTION_PROMISC:
			FORMAT_DATA->promisc = *(int *)data;
			return 0;
		case TRACE_OPTION_FILTER:
			FORMAT_DATA->bpffilter = strdup((char *)data);
			return 0;
		case TRACE_OPTION_HASHER:
			/* We can do unidirectional hashing on hardware
			 * by default, but symmetric hash requires the
			 * extra ZC or DNA drivers. */
			switch (*((enum hasher_types *)data)) {
				case HASHER_UNIDIRECTIONAL:
					return 0;
				case HASHER_BALANCE:
				case HASHER_CUSTOM:
				case HASHER_BIDIRECTIONAL:
					return -1;
			}
			break;
		case TRACE_OPTION_META_FREQ:
			break;
		case TRACE_OPTION_EVENT_REALTIME:
			break;
	}
	return -1;
}

static int pfring_pause_input(libtrace_t *libtrace) {
	size_t i;

	for (i = 0; i < libtrace_list_get_size(FORMAT_DATA->per_stream); ++i) {
		struct pfring_per_stream_t *stream;
		stream = libtrace_list_get_index(FORMAT_DATA->per_stream, i)->data;
		pfring_disable_ring(stream->pd);	
		pfring_remove_bpf_filter(stream->pd);
		pfring_close(stream->pd);
	}

	FORMAT_DATA->ringenabled = 0;
	return 0;

}

static int pfring_fin_input(libtrace_t *libtrace) {

	if (libtrace->format_data) {
		if (FORMAT_DATA->bpffilter)
			free(FORMAT_DATA->bpffilter);
		if (FORMAT_DATA->per_stream) 
			libtrace_list_deinit(FORMAT_DATA->per_stream);
		free(libtrace->format_data);
	}
	return 0;
}


static int pfring_get_capture_length(const libtrace_packet_t *packet) {
	struct libtrace_pfring_header *phdr;
	phdr = (struct libtrace_pfring_header *)packet->header;

	if (packet->payload == NULL)
		return 0;
	if (ntohl(phdr->wlen) < ntohl(phdr->caplen))
		return ntohl(phdr->wlen);
	return ntohl(phdr->caplen);
	
}

static int pfring_get_wire_length(const libtrace_packet_t *packet) {
	struct libtrace_pfring_header *phdr;
	phdr = (struct libtrace_pfring_header *)packet->header;
	return ntohl(phdr->wlen);
}

static int pfring_get_framing_length(UNUSED const libtrace_packet_t *packet) {
	return sizeof(struct libtrace_pfring_header);
}

static int pfring_prepare_packet(libtrace_t *libtrace UNUSED, 
		libtrace_packet_t *packet, void *buffer, 
		libtrace_rt_types_t rt_type, uint32_t flags) {


	if (packet->buffer != buffer && packet->buf_control == 
			TRACE_CTRL_PACKET) {
		free(packet->buffer);
	}

	if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER) {
		packet->buf_control = TRACE_CTRL_PACKET;
	} else {
		packet->buf_control = TRACE_CTRL_EXTERNAL;
	}

	packet->type = rt_type;
	packet->buffer = buffer;
	packet->header = buffer;
	packet->payload = (buffer + sizeof(struct libtrace_pfring_header));

	return 0;
}

static int pfring_read_generic(libtrace_t *libtrace, libtrace_packet_t *packet,
		uint8_t block)
{

	struct pfring_per_stream_t *stream = FORMAT_DATA_FIRST;
	struct libtrace_pfring_header *hdr;
	struct local_pfring_header local;
	int rc;

	if (packet->buf_control == TRACE_CTRL_EXTERNAL || !packet->buffer) {
		packet->buffer = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
		if (!packet->buffer) {
			trace_set_err(libtrace, errno, 
				"Cannot allocate memory for packet buffer");
			return -1;
		}
	}

	hdr = (struct libtrace_pfring_header *)packet->buffer;
	if ((rc = pfring_recv(stream->pd, (u_char **)&packet->payload, 
			0, (struct pfring_pkthdr *)&local, block)) == -1)
	{
		trace_set_err(libtrace, errno, "Failed to read packet from pfring:");
		return -1;
	}

	/* We were asked not to block and there are no packets available */
	if (rc == 0)
		return 0;

	/* Convert the header fields to network byte order so we can
         * export them over RT safely. Also deal with 32 vs 64 bit
	 * timevals! */
	hdr->ts.tv_sec = bswap_host_to_le64((uint64_t)local.ts.tv_sec);
	hdr->ts.tv_usec = bswap_host_to_le64((uint64_t)local.ts.tv_usec);
	hdr->caplen = htonl(local.caplen);
	hdr->wlen = htonl(local.wlen);
	hdr->ts.tv_sec = htonl(local.ts.tv_sec);
	hdr->ts.tv_usec = htonl(local.ts.tv_usec);
	hdr->ext.ts_ns = bswap_host_to_le64(local.ext.ts_ns);
	hdr->ext.flags = htonl(local.ext.flags);
	hdr->ext.if_index = htonl(local.ext.if_index);
	hdr->ext.hash = htonl(local.ext.hash);
	hdr->ext.tx.bounce_iface = htonl(local.ext.tx.bounce_iface);
	hdr->ext.parsed_hdr_len = htons(local.ext.parsed_hdr_len);
	hdr->ext.direction = local.ext.direction;

	/* I think we can ignore parsed as it will only be populated if
	 * we call pfring_parse_pkt (?)
	 */

	packet->trace = libtrace;
	packet->type = TRACE_RT_DATA_PFRING;
	packet->header = packet->buffer;

	return pfring_get_capture_length(packet) + 
			pfring_get_framing_length(packet);

}

static int pfring_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet)
{
	return pfring_read_generic(libtrace, packet, 1);
}

static libtrace_linktype_t pfring_get_link_type(const libtrace_packet_t *packet UNUSED)
{
	return TRACE_TYPE_ETH;
}

static libtrace_direction_t lt_pfring_set_direction(libtrace_packet_t *packet,
		libtrace_direction_t dir) {

	struct libtrace_pfring_header *phdr;

	phdr = (struct libtrace_pfring_header *)packet->header;
	phdr->ext.direction = dir;
	return dir;	
}

static libtrace_direction_t pfring_get_direction(
		const libtrace_packet_t *packet) {

	struct libtrace_pfring_header *phdr;
	phdr = (struct libtrace_pfring_header *)packet->header;
	return phdr->ext.direction;
}

static uint64_t pfring_get_erf_timestamp(const libtrace_packet_t *packet) {
	uint64_t ts;
	struct libtrace_pfring_header *phdr;
	phdr = (struct libtrace_pfring_header *)packet->header;

	if (phdr->ext.ts_ns) {
		uint64_t tns = bswap_le_to_host64(phdr->ext.ts_ns);

		ts = ((tns / 1000000000) << 32);
		ts += ((tns % 1000000000) << 32) / 1000000000;
	} else {
		ts = (((uint64_t)ntohl(phdr->ts.tv_sec)) << 32);
		ts += (((uint64_t)(ntohl(phdr->ts.tv_usec)) << 32)/1000000);
	}
	return ts;
		

}
static size_t pfring_set_capture_length(libtrace_packet_t *packet, size_t size)
{
	struct libtrace_pfring_header *phdr;
	phdr = (struct libtrace_pfring_header *)packet->header;

	if (size > trace_get_capture_length(packet)) {
		/* Can't make a packet larger */
		return trace_get_capture_length(packet);
	}

	packet->capture_length = -1;
	phdr->caplen = htonl(size);
	return trace_get_capture_length(packet);
}

static void pfring_get_statistics(libtrace_t *libtrace, libtrace_stat_t *stat) {

	pfring_stat st;

	size_t i;

	for (i = 0; i < libtrace_list_get_size(FORMAT_DATA->per_stream); ++i) {
		struct pfring_per_stream_t *stream;
		stream = libtrace_list_get_index(FORMAT_DATA->per_stream, i)->data;

		if (pfring_stats(stream->pd, &st) != 0) {
			trace_set_err(libtrace, errno, "Failed to get statistics for pfring stream %u", (uint32_t)i);
			continue;
		}

		if (stat->dropped_valid) {
			stat->dropped += st.drop;
		} else {
			stat->dropped = st.drop;
			stat->dropped_valid = 1;
		}

		if (stat->received_valid) {
			stat->received += st.recv;
		} else {
			stat->received = st.recv;
			stat->received_valid = 1;
		}
	}

}

static libtrace_eventobj_t pfring_event(libtrace_t *libtrace,  
		libtrace_packet_t *packet) {

	libtrace_eventobj_t event = {0,0,0.0,0};
	int rc;

	rc = pfring_read_generic(libtrace, packet, 0);
	
	if (rc > 0) {
		event.size = rc;
		event.type = TRACE_EVENT_PACKET;
	} else if (rc == 0) {
		if (libtrace_halt) {
			event.type = TRACE_EVENT_TERMINATE;
		} else {
			event.type = TRACE_EVENT_SLEEP;
			event.seconds = 0.0001;
		}
	} else {
		event.type = TRACE_EVENT_TERMINATE;
	}
	return event;
}

static int pfring_pstart_input(libtrace_t *libtrace) {
	trace_set_err(libtrace, TRACE_ERR_UNSUPPORTED, "Haven't implemented parallel support for pfring yet!");
	return -1;
}

static int pfring_pread_packets(libtrace_t *libtrace,
		libtrace_thread_t *t UNUSED, libtrace_packet_t *packets[] UNUSED,
		UNUSED size_t nb_packets) {

	trace_set_err(libtrace, TRACE_ERR_UNSUPPORTED, "Haven't implemented parallel support for pfring yet!");
	return -1;
}



static struct libtrace_format_t pfringformat = {
	"pfring",
	"$Id$",
	TRACE_FORMAT_PFRING,
	NULL,                           /* probe filename */
        NULL,                           /* probe magic */
        pfring_init_input,                /* init_input */
        pfring_config_input,              /* config_input */
        pfring_start_input,               /* start_input */
        pfring_pause_input,               /* pause_input */
        NULL,               		/* init_output */
        NULL,                           /* config_output */
        NULL,                           /* start_output */
        pfring_fin_input,                 /* fin_input */
        NULL,                		/* fin_output */
        pfring_read_packet,               /* read_packet */
        pfring_prepare_packet,            /* prepare_packet */
        NULL,                           /* fin_packet */
        NULL,  			          /* write_packet */
        pfring_get_link_type,             /* get_link_type */
        pfring_get_direction,             /* get_direction */
        lt_pfring_set_direction,             /* set_direction */
        pfring_get_erf_timestamp,         /* get_erf_timestamp */
        NULL,               /* get_timeval */
        NULL,                           /* get_seconds */
        NULL,                           /* get_timespec */
        NULL,                           /* seek_erf */
        NULL,                           /* seek_timeval */
        NULL,                           /* seek_seconds */
        pfring_get_capture_length,        /* get_capture_length */
        pfring_get_wire_length,           /* get_wire_length */
        pfring_get_framing_length,        /* get_framing_length */
        pfring_set_capture_length,        /* set_capture_length */
        NULL,                           /* get_received_packets */
        NULL,                           /* get_filtered_packets */
        NULL,                           /* get_dropped_packets */
        pfring_get_statistics,          /* get_statistics */
        NULL,                           /* get_fd */
        pfring_event,              /* trace_event */
        NULL,                      /* help */
        NULL,                   /* next pointer */
	{true, -1},                     /* Live, no thread limit */
        pfring_pstart_input,         /* pstart_input */
        pfring_pread_packets,        /* pread_packets */
        pfring_pause_input,        /* ppause */
        pfring_fin_input,          /* p_fin */
        NULL,   		/* register thread XXX */ 
        NULL,                           /* unregister thread */
        NULL                            /* get thread stats */

};

void pfring_constructor(void) {
	register_format(&pfringformat);
}
