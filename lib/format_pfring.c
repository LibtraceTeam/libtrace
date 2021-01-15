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

#define _GNU_SOURCE
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
#include <pfring_zc.h>

struct pfring_format_data_t {
	libtrace_list_t *per_stream;	
	int8_t promisc;
	int snaplen;
	int8_t ringenabled;
	char *bpffilter;
};

struct pfringzc_per_thread {

	uint32_t lastbatch;
	uint32_t nextpacket;
	pfring_zc_pkt_buff ** buffers;
};


struct pfringzc_format_data_t {
	pfring_zc_cluster *cluster;
	pfring_zc_worker *hasher;
	pfring_zc_buffer_pool *pool;

	pfring_zc_queue **inqueues;
	pfring_zc_queue **outqueues;
	uint16_t clusterid;	
	int numthreads;

	struct pfringzc_per_thread *perthreads;

	int8_t promisc;
	int snaplen;
	char *bpffilter;
	enum hasher_types hashtype;

};

struct pfring_per_stream_t {

	pfring *pd;
	int affinity;

};

#define ZERO_PFRING_STREAM {NULL, -1}

#define DATA(x) ((struct pfring_format_data_t *)x->format_data)
#define ZCDATA(x) ((struct pfringzc_format_data_t *)x->format_data)
#define STREAM_DATA(x) ((struct pfring_per_stream_t *)x->data)

#define FORMAT_DATA DATA(libtrace)
#define ZC_FORMAT_DATA ZCDATA(libtrace)
#define FORMAT_DATA_HEAD FORMAT_DATA->per_stream->head
#define FORMAT_DATA_FIRST ((struct pfring_per_stream_t *)FORMAT_DATA_HEAD->data)

#define PFRINGZC_BATCHSIZE 10

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

#define PFRING_BYTEORDER_BIGENDIAN 0
#define PFRING_BYTEORDER_LITTLEENDIAN 1

#if __BYTE_ORDER == __BIG_ENDIAN
#define PFRING_MY_BYTEORDER PFRING_BYTEORDER_BIGENDIAN
#else
#define PFRING_MY_BYTEORDER PFRING_BYTEORDER_LITTLEENDIAN
#endif


struct libtrace_pfring_header {
	uint8_t byteorder;
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

static inline uint32_t pfring_flags(libtrace_t *libtrace) {
	uint32_t flags = PF_RING_TIMESTAMP | PF_RING_LONG_HEADER;
	flags |= PF_RING_HW_TIMESTAMP;
	flags |= PF_RING_DO_NOT_PARSE;

	if (FORMAT_DATA->promisc > 0) 
		flags |= PF_RING_PROMISC;
	return flags;
}	

static inline int pfringzc_init_queues(libtrace_t *libtrace, 
		struct pfringzc_format_data_t *fdata, int threads) {

	int i, j;
	char devname[4096];

	fdata->inqueues = calloc(threads, sizeof(pfring_zc_queue *));
	fdata->outqueues = calloc(threads, sizeof(pfring_zc_queue *));
	fdata->perthreads = calloc(threads, sizeof(struct pfringzc_per_thread));

	for (i = 0; i < threads; i++) {
		snprintf(devname, 4095, "zc:%s@%d", libtrace->uridata, i);
		
		fdata->perthreads[i].buffers = calloc(PFRINGZC_BATCHSIZE, sizeof(pfring_zc_pkt_buff *));
		fdata->perthreads[i].lastbatch = 0;
		fdata->perthreads[i].nextpacket = 0;

		for (j = 0; j < PFRINGZC_BATCHSIZE; j++) {
			fdata->perthreads[i].buffers[j] = pfring_zc_get_packet_handle(fdata->cluster);
		
			if (fdata->perthreads[i].buffers[j] == NULL) {
				trace_set_err(libtrace, errno, "Failed to create pfringzc packet handle");
				goto error;
			}
		}
		
		fdata->inqueues[i] = pfring_zc_open_device(fdata->cluster,
				devname, rx_only, 0);
		if (fdata->inqueues[i] == NULL) {
			trace_set_err(libtrace, errno, "Failed to create pfringzc in queue");
			goto error;
		}


		fdata->outqueues[i] = pfring_zc_create_queue(fdata->cluster,
				8192);
		if (fdata->outqueues[i] == NULL) {
			trace_set_err(libtrace, errno, "Failed to create pfringzc out queue");
			goto error;
		}

	}

	fdata->pool = pfring_zc_create_buffer_pool(fdata->cluster, 8);
	if (fdata->pool == NULL) {
		trace_set_err(libtrace, errno, "Failed to create pfringzc buffer pool");
		goto error;
	}

	return 0;

error:
	//pfringzc_destroy_queues(libtrace, fdata, threads);
	return -1;

}

UNUSED static int pfringzc_start_input(libtrace_t *libtrace) {

	if (ZC_FORMAT_DATA->cluster != NULL) {
		trace_set_err(libtrace, TRACE_ERR_BAD_STATE,
			"Attempted to start a pfringzc: input that was already started!");
		return -1;
	}

	if (libtrace->uridata == NULL) {
		trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, 
				"Missing interface name from pfringzc: URI");
		return -1;
	}

	ZC_FORMAT_DATA->cluster = pfring_zc_create_cluster(
			ZC_FORMAT_DATA->clusterid,
			1600,	/* TODO calculate */
			0,	/* meta-data length */
			8192 * 32687 + PFRINGZC_BATCHSIZE,  /* number of buffers */
			pfring_zc_numa_get_cpu_node(0), /* bind to core 0 */
			NULL,	/* auto hugetlb mountpoint */
                        0
			);
	if (ZC_FORMAT_DATA->cluster == NULL) {
		trace_set_err(libtrace, errno, "Failed to create pfringzc cluster");
		return -1;
	}

	if (pfringzc_init_queues(libtrace, ZC_FORMAT_DATA, 1) == -1)
		return -1;

	/* No hasher necessary, as we just have one thread */
	ZC_FORMAT_DATA->hasher = pfring_zc_run_balancer(
		ZC_FORMAT_DATA->inqueues, ZC_FORMAT_DATA->outqueues, 1, 1,
		ZC_FORMAT_DATA->pool, round_robin_bursts_policy, NULL,
		NULL, NULL, 1, 0);
	return 0;
}

static int pfring_start_input(libtrace_t *libtrace) {
	struct pfring_per_stream_t *stream = FORMAT_DATA_FIRST;
	int rc = 0;

	if (libtrace->uridata == NULL) {
		trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, 
				"Missing interface name from pfring: URI");
		return -1;
	}
	if (FORMAT_DATA->ringenabled) {
		trace_set_err(libtrace, TRACE_ERR_BAD_STATE,
			"Attempted to start a pfring: input that was already started!");
		return -1;
	}

	stream->pd = pfring_open(libtrace->uridata, FORMAT_DATA->snaplen, 
		pfring_flags(libtrace));
	if (stream->pd == NULL) {
		trace_set_err(libtrace, errno, "pfring_open failed: %s",
				strerror(errno));
		return -1;
	}

	rc = pfring_start_input_stream(libtrace, FORMAT_DATA_FIRST);
	if (rc < 0)
		return rc;	
	FORMAT_DATA->ringenabled = 1;
	return rc;
}

static int pfring_pstart_input(libtrace_t *libtrace) {
	pfring *ring[MAX_NUM_RX_CHANNELS];
	uint8_t channels;
	struct pfring_per_stream_t empty = ZERO_PFRING_STREAM;
	int i, iserror = 0;
	
	if (libtrace->uridata == NULL) {
		trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, 
				"Missing interface name from pfring: URI");
		return -1;
	}
	if (FORMAT_DATA->ringenabled) {
		trace_set_err(libtrace, TRACE_ERR_BAD_STATE,
			"Attempted to start a pfring: input that was already started!");
		return -1;
	}

	channels = pfring_open_multichannel(libtrace->uridata, 
			FORMAT_DATA->snaplen, pfring_flags(libtrace), ring);
	if (channels <= 0) {
		trace_set_err(libtrace, errno, 
				"pfring_open_multichannel failed: %s",
				strerror(errno));
		return -1;
	}

	printf("got %u channels\n", channels);

	if (libtrace->perpkt_thread_count < channels) {
		fprintf(stderr, "WARNING: pfring interface has %u channels, "
				"but this libtrace program has only enough "
				"threads to read the first %u channels.",
				channels, libtrace->perpkt_thread_count);
	}

	if (channels < libtrace->perpkt_thread_count)
		libtrace->perpkt_thread_count = channels;
	

	for (i = 0; i < channels; i++) {
		struct pfring_per_stream_t *stream;
		if (libtrace_list_get_size(FORMAT_DATA->per_stream)<=(size_t)i)
			libtrace_list_push_back(FORMAT_DATA->per_stream, &empty);

		stream = libtrace_list_get_index(FORMAT_DATA->per_stream, i)->data;
		stream->pd = ring[i];
		if (pfring_start_input_stream(libtrace, stream) != 0) {
			iserror = 1;
			break;
		}
	}

	if (iserror) {
		/* Error state: free any streams we managed to create */
		for (i = i - 1; i >= 0; i--) {
			struct pfring_per_stream_t *stream;
			stream = libtrace_list_get_index(FORMAT_DATA->per_stream, i)->data;

			pfring_disable_ring(stream->pd);	
			pfring_remove_bpf_filter(stream->pd);
			pfring_close(stream->pd);
		}
		return -1;
	}
	FORMAT_DATA->ringenabled = 1;
	return 0;
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

UNUSED static int pfringzc_init_input(libtrace_t *libtrace) {

	libtrace->format_data = (struct pfringzc_format_data_t *)
		malloc(sizeof(struct pfringzc_format_data_t));
	assert(libtrace->format_data != NULL);
	
	ZC_FORMAT_DATA->promisc = -1;
	ZC_FORMAT_DATA->snaplen = LIBTRACE_PACKET_BUFSIZE;
	ZC_FORMAT_DATA->bpffilter = NULL;

	ZC_FORMAT_DATA->cluster = NULL;
	ZC_FORMAT_DATA->inqueues = NULL;
	ZC_FORMAT_DATA->outqueues = NULL;
	ZC_FORMAT_DATA->pool = NULL;
	ZC_FORMAT_DATA->hasher = NULL;
	ZC_FORMAT_DATA->hashtype = HASHER_BIDIRECTIONAL;
	ZC_FORMAT_DATA->clusterid = (uint16_t)rand();

	return 0;
}

UNUSED static int pfringzc_config_input(libtrace_t *libtrace, trace_option_t option,
		void *data) {

	switch (option) {
		case TRACE_OPTION_SNAPLEN:
			ZC_FORMAT_DATA->snaplen = *(int *)data;
			return 0;
		case TRACE_OPTION_PROMISC:
			ZC_FORMAT_DATA->promisc = *(int *)data;
			return 0;
		case TRACE_OPTION_FILTER:
			ZC_FORMAT_DATA->bpffilter = strdup((char *)data);
			return 0;
		case TRACE_OPTION_HASHER:
			/* We can do bidirectional hashing on hardware
			 * by default, thanks to the ZC library */
			ZC_FORMAT_DATA->hashtype = *((enum hasher_types *)data);
			switch (*((enum hasher_types *)data)) {
				case HASHER_BIDIRECTIONAL:
				case HASHER_UNIDIRECTIONAL:
					return 0;
				case HASHER_BALANCE:
					return 0;		
				case HASHER_CUSTOM:
					return -1;
			}
			break;
		case TRACE_OPTION_META_FREQ:
		case TRACE_OPTION_EVENT_REALTIME:
		case TRACE_OPTION_REPLAY_SPEEDUP:
		case TRACE_OPTION_CONSTANT_ERF_FRAMING:
		case TRACE_OPTION_DISCARD_META:
		case TRACE_OPTION_XDP_HARDWARE_OFFLOAD:
		case TRACE_OPTION_XDP_DRV_MODE:
		case TRACE_OPTION_XDP_SKB_MODE:
		case TRACE_OPTION_XDP_ZERO_COPY_MODE:
		case TRACE_OPTION_XDP_COPY_MODE:
			break;
	}
	return -1;
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
		case TRACE_OPTION_EVENT_REALTIME:
		case TRACE_OPTION_REPLAY_SPEEDUP:
		case TRACE_OPTION_CONSTANT_ERF_FRAMING:
		case TRACE_OPTION_DISCARD_META:
		case TRACE_OPTION_XDP_HARDWARE_OFFLOAD:
		case TRACE_OPTION_XDP_DRV_MODE:
		case TRACE_OPTION_XDP_SKB_MODE:
		case TRACE_OPTION_XDP_ZERO_COPY_MODE:
		case TRACE_OPTION_XDP_COPY_MODE:
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

UNUSED static int pfringzc_pause_input(libtrace_t *libtrace) {

	/* hopefully this will clean up our buffers and queues? */
	pfring_zc_kill_worker(ZC_FORMAT_DATA->hasher);
	pfring_zc_destroy_cluster(ZC_FORMAT_DATA->cluster);
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


UNUSED static int pfringzc_fin_input(libtrace_t *libtrace) {
	if (libtrace->format_data) {
		if (ZC_FORMAT_DATA->bpffilter)
			free(ZC_FORMAT_DATA->bpffilter);
		free(libtrace->format_data);
	}
	return 0;

}

static int pfring_get_capture_length(const libtrace_packet_t *packet) {
	struct libtrace_pfring_header *phdr;
	uint32_t wlen, caplen;
	phdr = (struct libtrace_pfring_header *)packet->header;

	if (packet->payload == NULL)
		return 0;

	if (phdr->byteorder != PFRING_MY_BYTEORDER) {
		wlen = byteswap32(phdr->wlen);
		caplen = byteswap32(phdr->caplen);
	} else {
		wlen = phdr->wlen;
		caplen = phdr->caplen;
	}

	if (wlen < caplen)
		return wlen;
	return caplen;
	
}

static int pfring_get_wire_length(const libtrace_packet_t *packet) {
	struct libtrace_pfring_header *phdr;
	phdr = (struct libtrace_pfring_header *)packet->header;
	/* +4 : libtrace includes FCS in wirelen, pcap-like formats don't */
	if (phdr->byteorder != PFRING_MY_BYTEORDER) {
		return byteswap32(phdr->wlen) + 4;
	}
	return phdr->wlen + 4;
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

static int pfringzc_read_batch(libtrace_t *libtrace,
                struct pfringzc_per_thread *pzt, int oq, uint8_t block,
		libtrace_message_queue_t *queue) {

	int received;

	do {
		received = pfring_zc_recv_pkt_burst(
				ZC_FORMAT_DATA->outqueues[oq], 
				pzt->buffers,
				PFRINGZC_BATCHSIZE,
				0);
		
		if (received < 0) {
			trace_set_err(libtrace, errno, "Failed to read packet batch from pfringzc:");
			return -1;
		}

		if (received == 0) {
			if (queue && libtrace_message_queue_count(queue) > 0)
				return READ_MESSAGE;
			if (is_halted(libtrace) != -1) {
				return is_halted(libtrace);
			}
			continue;
		}

		pzt->lastbatch = received;
		pzt->nextpacket = 0;

	} while (block);
	return 0;
}

static int pfring_read_generic(libtrace_t *libtrace, libtrace_packet_t *packet,
		struct pfring_per_stream_t *stream, uint8_t block, 
		libtrace_message_queue_t *queue)
{

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
	do {
		if ((rc = pfring_recv(stream->pd, (u_char **)&packet->payload, 
			0, (struct pfring_pkthdr *)&local, 0)) == -1)
		{
			trace_set_err(libtrace, errno, "Failed to read packet from pfring:");
			return -1;
		}

		if (rc == 0) {
			if (queue && libtrace_message_queue_count(queue) > 0)
				return READ_MESSAGE;
			if (is_halted(libtrace) != -1) {
				return is_halted(libtrace);
			}
			continue;
		}
		break;
	} while (block);

	if (rc == 0)
		return 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	hdr->byteorder = PFRING_BYTEORDER_LITTLEENDIAN;
#else
	hdr->byteorder = PFRING_BYTEORDER_BIGENDIAN;
#endif

	hdr->caplen = (local.caplen);
	hdr->wlen = (local.wlen);
	hdr->ext.ts_ns = (local.ext.ts_ns);
	hdr->ext.flags = (local.ext.flags);
	hdr->ext.if_index = (local.ext.if_index);
	hdr->ext.hash = (local.ext.hash);
	hdr->ext.tx.bounce_iface = (local.ext.tx.bounce_iface);
	hdr->ext.parsed_hdr_len = (local.ext.parsed_hdr_len);
	hdr->ext.direction = local.ext.direction;


	/* I think we can ignore parsed as it will only be populated if
	 * we call pfring_parse_pkt (?)
	 */

	packet->trace = libtrace;
	packet->type = TRACE_RT_DATA_PFRING;
	packet->header = packet->buffer;
	packet->error = 1;

	return pfring_get_capture_length(packet) + 
			pfring_get_framing_length(packet);

}

UNUSED static int pfringzc_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet UNUSED)
{

	struct pfringzc_per_thread *pzt = &(ZC_FORMAT_DATA->perthreads[0]);

	if (pzt->nextpacket >= pzt->lastbatch) {
		/* Read a fresh batch of packets */
		if (pfringzc_read_batch(libtrace, pzt, 0, 1, NULL) < 0) {
			return -1;
		}
	}

	pfring_zc_pkt_buff *pbuf UNUSED = pzt->buffers[pzt->nextpacket];
	pzt->nextpacket ++;

	/* TODO... */
        fprintf(stderr, "pfringzc_read_packet() is not fully implemented yet\n");
        return -1;
}

static int pfring_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet)
{
	return pfring_read_generic(libtrace, packet, FORMAT_DATA_FIRST, 1, NULL);
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
		uint64_t tns;
		if (phdr->byteorder == PFRING_MY_BYTEORDER)
			tns = phdr->ext.ts_ns;
		else
			tns = byteswap64(phdr->ext.ts_ns);

		ts = ((tns / 1000000000) << 32);
		ts += ((tns % 1000000000) << 32) / 1000000000;
	} else {
		uint64_t sec, usec;
		if (phdr->byteorder == PFRING_MY_BYTEORDER) {
			sec = (uint64_t)(phdr->ts.tv_sec);
			usec = (uint64_t)(phdr->ts.tv_usec);
		} else {
			sec = (uint64_t)byteswap32(phdr->ts.tv_sec);
			usec = (uint64_t)byteswap32(phdr->ts.tv_usec);
		}

		ts = (sec << 32);
		ts += ((usec << 32)/1000000);
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

	packet->cached.capture_length = -1;
	if (phdr->byteorder != PFRING_MY_BYTEORDER) {
		phdr->caplen = byteswap32(size);
	} else {
		phdr->caplen = size;
	}
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

	rc = pfring_read_generic(libtrace, packet, FORMAT_DATA_FIRST, 0, NULL);
	
	if (rc > 0) {
		event.size = rc;
		event.type = TRACE_EVENT_PACKET;
	} else if (rc == 0) {
		if (libtrace_halt) {
			event.type = TRACE_EVENT_TERMINATE;
		} else {
			event.type = TRACE_EVENT_IOWAIT;
			event.fd = pfring_get_selectable_fd(FORMAT_DATA_FIRST->pd);
		}
	} else {
		event.type = TRACE_EVENT_TERMINATE;
	}
	return event;
}

static int pfring_pread_packets(libtrace_t *libtrace,
		libtrace_thread_t *t, 
		libtrace_packet_t *packets[],
		size_t nb_packets) {

	size_t readpackets = 0;
	int rc = 0;
	struct pfring_per_stream_t *stream = (struct pfring_per_stream_t *)t->format_data;
	uint8_t block = 1;

	/* Block for the first packet, then read up to nb_packets if they
         * are available. */
	do {
		rc = pfring_read_generic(libtrace, packets[readpackets], 
			stream, block, &t->messages);
		if (rc == READ_MESSAGE) {
			if (readpackets == 0) {
				return rc;
			}
			break;
		}
				
		if (rc == READ_ERROR)
			return rc;

		if (rc == 0)
			continue;
		
		block = 0;
		readpackets ++;
		if (readpackets >= nb_packets)
			break;

	} while (rc != 0);

	return readpackets;
}

static int pfring_pregister_thread(libtrace_t *libtrace, libtrace_thread_t *t,
		bool reading) {

	uint32_t cpus = trace_get_number_of_cores();

	if (reading) {
		struct pfring_per_stream_t *stream;
		int tid = 0;
		if (t->type == THREAD_PERPKT) {
			t->format_data = libtrace_list_get_index(FORMAT_DATA->per_stream, t->perpkt_num)->data;
			if (t->format_data == NULL) {
				trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
						"Too many threads registered");
				return -1;
			}
			tid = t->perpkt_num;
		} else {
			t->format_data = FORMAT_DATA_FIRST;
		}

		stream = t->format_data;
		if (cpus > 1) {
			cpu_set_t cpuset;
			uint32_t coreid;
			int s;

			coreid = (tid + 1) % cpus;
			CPU_ZERO(&cpuset);
			CPU_SET(coreid, &cpuset);
			if ((s = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset)) != 0) {
				trace_set_err(libtrace, errno, "Warning "
						"failed to set affinity for "
						"pfring thread");
				return -1;
			}
			stream->affinity = coreid;
		}
	}

	return 0;		

}

static struct libtrace_format_t pfringformat = {
	"pfring",
	"$Id$",
	TRACE_FORMAT_PFRING,
	NULL,                           /* probe filename */
        NULL,                           /* probe magic */
        pfring_init_input,              /* init_input */
        pfring_config_input,            /* config_input */
        pfring_start_input,             /* start_input */
        pfring_pause_input,             /* pause_input */
        NULL,               		/* init_output */
        NULL,                           /* config_output */
        NULL,                           /* start_output */
        pfring_fin_input,               /* fin_input */
        NULL,                		/* fin_output */
        pfring_read_packet,             /* read_packet */
        pfring_prepare_packet,          /* prepare_packet */
        NULL,                           /* fin_packet */
	NULL,                           /* can_hold_packet */
        NULL,  			        /* write_packet */
        NULL,                           /* flush_output */
        pfring_get_link_type,           /* get_link_type */
        pfring_get_direction,           /* get_direction */
        lt_pfring_set_direction,        /* set_direction */
        pfring_get_erf_timestamp,       /* get_erf_timestamp */
        NULL,                           /* get_timeval */
        NULL,                           /* get_timespec */
        NULL,                           /* get_seconds */
        NULL,                           /* get_all_meta */
        NULL,                           /* seek_erf */
        NULL,                           /* seek_timeval */
        NULL,                           /* seek_seconds */
        pfring_get_capture_length,      /* get_capture_length */
        pfring_get_wire_length,         /* get_wire_length */
        pfring_get_framing_length,      /* get_framing_length */
        pfring_set_capture_length,      /* set_capture_length */
        NULL,                           /* get_received_packets */
        NULL,                           /* get_filtered_packets */
        NULL,                           /* get_dropped_packets */
        pfring_get_statistics,          /* get_statistics */
        NULL,                           /* get_fd */
        pfring_event,                   /* trace_event */
        NULL,                           /* help */
        NULL,                           /* next pointer */
	{true, MAX_NUM_RX_CHANNELS},    /* Live, with thread limit */
        pfring_pstart_input,            /* pstart_input */
        pfring_pread_packets,           /* pread_packets */
        pfring_pause_input,             /* ppause */
        pfring_fin_input,               /* p_fin */
        pfring_pregister_thread,  	/* register thread */ 
        NULL,                           /* unregister thread */
        NULL                            /* get thread stats */

};

void pfring_constructor(void) {
	register_format(&pfringformat);
}
