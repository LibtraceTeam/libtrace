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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "data-struct/linked_list.h"
#include "format_linux_helpers.h"

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>

#if HAVE_LIBNUMA
#include <numa.h>
#endif

#include <pthread.h>
#ifdef __FreeBSD__
#include <pthread_np.h>
#endif

#include <pfring.h>
#include <pfring_zc.h>

#define PFRINGZC_MAX_CARD_RINGS 32768
#define PFRINGZC_BATCHSIZE 64

struct pfring_format_data_t {
	libtrace_list_t *per_stream;
	int8_t promisc;
	int snaplen;
	int8_t ringenabled;
	char *bpffilter;
        struct linux_dev_stats interface_stats;
};

struct pfringzc_per_thread {
	uint32_t lastbatch;
	uint32_t nextpacket;
	pfring_zc_queue *device;
	pfring_zc_pkt_buff *buffers[PFRINGZC_BATCHSIZE];
        uint64_t prev_sys_time;
};

struct pfringzc_format_data_t {
	pfring_zc_cluster *cluster;
	pfring_zc_queue **devices;
	uint16_t clusterid;
	struct pfringzc_per_thread *perthreads;
	int8_t promisc;
	int snaplen;
	char *bpffilter;
	enum hasher_types hashtype;
	struct linux_dev_stats interface_stats;
	bool zero_copy;
};

struct pfring_per_stream_t {
	pfring *pd;
	int affinity;
};

#define ZERO_STATS(x) {\
        x->dropped = 0; x->dropped_valid = 0;\
        x->received = 0; x->received_valid = 0;\
        x->captured = 0; x->captured_valid = 0;\
	x->errors = 0; x->errors_valid = 0;\
}

#define ZERO_PFRING_STREAM {NULL, -1}

#define PFRING_DATA(x) ((struct pfring_format_data_t *)x->format_data)
#define PFRINGZC_ZCDATA(x) ((struct pfringzc_format_data_t *)x->format_data)
#define STREAM_DATA(x) ((struct pfring_per_stream_t *)x->data)

#define FORMAT_DATA PFRING_DATA(libtrace)
#define ZC_FORMAT_DATA PFRINGZC_ZCDATA(libtrace)
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

/* Offset at which local_pfring_header *mostly* lines up with
 * libtrace_pfring_header pfring_header = 1
 *
 * *Mostly* because timeval will change size between 32-bit and 64-bit builds,
 * so instead we align to caplen.
 * The timestamp is easy to fix; first copy tv_sec then tv_usec across from the
 * local version to the libtrace version. This copy will be omitted for if
 * timeval is 64-bit.
 */
#define PFRING_LOCAL_STRUCT_OFFSET                                             \
        (offsetof(struct libtrace_pfring_header, caplen) -                     \
         offsetof(struct local_pfring_header, caplen))
ct_assert(PFRING_LOCAL_STRUCT_OFFSET > 0);

static inline char *pfring_ifname_from_uridata(char *uridata) {
        char *interface = strchr(uridata, ':');
        if (interface != NULL) {
                interface += 1;
        } else {
                interface = uridata;
        }
        return interface;
}

static inline bool pfring_ifname_is_zc(char *uridata) {
	return (strstr(uridata, "zc:") != NULL);
}

static inline uint64_t pfring_timespec_to_systime(pfring_zc_timespec *ts) {
        return (uint64_t)ts->tv_sec * 1000000000ull + (uint64_t) ts->tv_nsec;
}

static bool pfring_can_write(libtrace_packet_t *packet) {
    /* Get the linktype */
    libtrace_linktype_t ltype = trace_get_link_type(packet);

    if (ltype == TRACE_TYPE_CONTENT_INVALID) {
        return false;
    }
    if (ltype == TRACE_TYPE_NONDATA) {
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

        if (FORMAT_DATA->promisc != 0)
                flags |= PF_RING_PROMISC;
        return flags;
}

static inline int pfringzc_init_queues(const char *uridata, char *err, int errlen,
		struct pfringzc_format_data_t *fdata, int threads, pfring_zc_queue_mode queue_mode) {

	int i, j;
	char devname[200];
	fdata->devices = calloc(threads, sizeof(pfring_zc_queue *));
	fdata->perthreads = calloc(threads, sizeof(struct pfringzc_per_thread));

	for (i = 0; i < threads; i++) {
		for (j = 0; j < PFRINGZC_BATCHSIZE; j++) {
                        fdata->perthreads[i].buffers[j] = pfring_zc_get_packet_handle(fdata->cluster);
                        if (fdata->perthreads[i].buffers[j] == NULL) {
                                snprintf(err, errlen, "Failed to create pfringzc packet handle");
                                return -1;
                        }
                }

		snprintf(devname, sizeof(devname), "%s@%d", uridata, i);
		fdata->devices[i] = pfring_zc_open_device(fdata->cluster, devname, queue_mode,
			PF_RING_ZC_DEVICE_SW_TIMESTAMP |
			PF_RING_ZC_DEVICE_HW_TIMESTAMP |
			PF_RING_ZC_DEVICE_NOT_REPROGRAM_RSS);
		if (fdata->devices[i] == NULL) {
                        snprintf(err, errlen, "Failed to open pfringzc device: %s", devname);
                        return -1;
		}
		fdata->perthreads[i].device = fdata->devices[i];

		if (fdata->bpffilter != NULL) {
			if (pfring_zc_set_bpf_filter(fdata->devices[i], fdata->bpffilter) != 0) {
                                snprintf(err, errlen, "Failed to set pfringzc BPF filter: %s", fdata->bpffilter);
				return -1;
			}
		}
	}

	return 0;
}

static int pfringzc_max_packet_length(char *device) {
	pfring *ring;
	pfring_card_settings settings;
	uint32_t mtu;
	ring = pfring_open(device, 1536, PF_RING_ZC_NOT_REPROGRAM_RSS);
	if (ring == NULL)
		return 1536;
	pfring_get_card_settings(ring, &settings);
	mtu = pfring_get_mtu_size(ring);
	if (settings.max_packet_size < mtu + 14 /* eth */)
		settings.max_packet_size = mtu + 14 /* eth */ + 4 /* vlan */;
	pfring_close(ring);
	return settings.max_packet_size;
}

static int pfringzc_configure_interface(char *uridata,
                                        int threads,
                                        bool dedicated_hasher,
                                        struct pfringzc_format_data_t *fdata,
                                        char *err,
                                        int errlen) {
	char *interface = pfring_ifname_from_uridata(uridata);
	if (threads == 0 || dedicated_hasher) {
		threads = 1;
        }
	// check if ZC is used
	fdata->zero_copy = pfring_ifname_is_zc(uridata);
	// check interface exists
	if (if_nametoindex(interface) == 0) {
                snprintf(err, errlen, "Invalid interface name: %s", interface);
		errno = TRACE_ERR_BAD_FORMAT;
                return -1;
	}
	// set nic queues to match number of threads
	if (linux_get_nic_queues(interface) != threads) {
		if (linux_set_nic_queues(interface, threads) != threads) {
                        fprintf(stderr, "Unable to set number of NIC queues to match the "
                                "number of processing threads: %d, packets may be lost", threads);
			//errno = TRACE_ERR_INIT_FAILED;
                        //return -1;
		}
	}
        // get initial interface statistics (this only actually works when not doing ZC)
        if (linux_get_dev_statistics(interface, &(fdata->interface_stats)) != 0) {
                fdata->interface_stats.if_name[0] = 0;
        }
        return threads;
}

static int pfringzc_start_input(libtrace_t *libtrace) {
        char err[500];
        int threads;
        if (ZC_FORMAT_DATA->cluster != NULL) {
                trace_set_err(libtrace, TRACE_ERR_BAD_STATE,
                        "Attempted to start a pfringzc input that was already started!");
                return -1;
        }
        if ((threads = pfringzc_configure_interface(libtrace->uridata,
                                                    libtrace->perpkt_thread_count,
                                                    trace_has_dedicated_hasher(libtrace),
                                                    ZC_FORMAT_DATA,
                                                    err,
                                                    sizeof(err))) == -1) {
                trace_set_err(libtrace, errno, "%s", err);
                return -1;
        }
	if ((ZC_FORMAT_DATA->cluster = pfring_zc_create_cluster(ZC_FORMAT_DATA->clusterid,
                                                                pfringzc_max_packet_length(libtrace->uridata),
                                                                sizeof(struct libtrace_pfring_header),
                                                                PFRINGZC_MAX_CARD_RINGS * threads,
                                                                pfring_zc_numa_get_cpu_node(0),
                                                                NULL,
                                                                0)) == NULL) {
		trace_set_err(libtrace, errno, "Failed to create pfringzc cluster");
		return -1;
	}
	if (pfringzc_init_queues(libtrace->uridata, err, sizeof(err), ZC_FORMAT_DATA, threads, rx_only) == -1) {
                trace_set_err(libtrace, errno, "%s", err);
		return -1;
        }

	return 0;
}

static int pfringzc_start_output(libtrace_out_t *libtrace) {
        char err[500];
        int threads;
        if (ZC_FORMAT_DATA->cluster != NULL) {
                trace_set_err_out(libtrace, TRACE_ERR_BAD_STATE,
                        "Attempted to start a pfringzc: input that was already started!");
                return -1;
        }
        if ((threads = pfringzc_configure_interface(libtrace->uridata,
                                                    1,
                                                    0,
                                                    ZC_FORMAT_DATA,
                                                    err,
                                                    sizeof(err))) == -1) {
                trace_set_err_out(libtrace, errno, "%s", err);
                return -1;
        }
        if ((ZC_FORMAT_DATA->cluster = pfring_zc_create_cluster(ZC_FORMAT_DATA->clusterid,
                                                                pfringzc_max_packet_length(libtrace->uridata),
                                                                0,
                                                                PFRINGZC_MAX_CARD_RINGS * threads,
                                                                pfring_zc_numa_get_cpu_node(0),
                                                                NULL,
                                                                0)) == NULL) {
                trace_set_err_out(libtrace, errno, "Failed to create pfringzc cluster");
                return -1;
        }
        if (pfringzc_init_queues(libtrace->uridata, err, sizeof(err), ZC_FORMAT_DATA, threads, tx_only) == -1) {
                trace_set_err_out(libtrace, errno, "%s", err);
                return -1;
        }

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

        // get initial interface statistics
        if (linux_get_dev_statistics(pfring_ifname_from_uridata(libtrace->uridata),
                                     &(FORMAT_DATA->interface_stats)) != 0) {
                FORMAT_DATA->interface_stats.if_name[0] = 0;
        }

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

        // get initial interface statistics
        if (linux_get_dev_statistics(pfring_ifname_from_uridata(libtrace->uridata),
                                     &(FORMAT_DATA->interface_stats)) != 0) {
                FORMAT_DATA->interface_stats.if_name[0] = 0;
        }

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

static int pfringzc_init_input(libtrace_t *libtrace) {

	libtrace->format_data = (struct pfringzc_format_data_t *)
		malloc(sizeof(struct pfringzc_format_data_t));
	assert(libtrace->format_data != NULL);

	ZC_FORMAT_DATA->promisc = -1;
	ZC_FORMAT_DATA->snaplen = LIBTRACE_PACKET_BUFSIZE;
	ZC_FORMAT_DATA->bpffilter = NULL;
	ZC_FORMAT_DATA->devices = NULL;
	ZC_FORMAT_DATA->cluster = NULL;
	ZC_FORMAT_DATA->hashtype = HASHER_BIDIRECTIONAL;
	ZC_FORMAT_DATA->clusterid = (uint16_t)rand();
	ZC_FORMAT_DATA->perthreads = NULL;
	ZC_FORMAT_DATA->zero_copy = 0;

	return 0;
}

static int pfringzc_init_output(libtrace_out_t *libtrace) {

        libtrace->format_data = (struct pfringzc_format_data_t *)
                malloc(sizeof(struct pfringzc_format_data_t));

        ZC_FORMAT_DATA->cluster = NULL;
        ZC_FORMAT_DATA->devices = NULL;
        ZC_FORMAT_DATA->clusterid = (uint16_t)rand();
        ZC_FORMAT_DATA->perthreads = NULL;
        ZC_FORMAT_DATA->promisc = -1;
        ZC_FORMAT_DATA->snaplen = LIBTRACE_PACKET_BUFSIZE;
        ZC_FORMAT_DATA->bpffilter = NULL;
        ZC_FORMAT_DATA->hashtype = HASHER_BIDIRECTIONAL;
	ZC_FORMAT_DATA->zero_copy = 0;

        return 0;
}

static int pfringzc_config_input(libtrace_t *libtrace, trace_option_t option,
		void *data) {

	int ret;

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
			ZC_FORMAT_DATA->hashtype = *((enum hasher_types *)data);
			switch (*((enum hasher_types *)data)) {
				case HASHER_BIDIRECTIONAL:
				case HASHER_UNIDIRECTIONAL:
				case HASHER_BALANCE:
					// Set RSS hash key on NIC
					if (linux_set_nic_hasher(pfring_ifname_from_uridata(libtrace->uridata),
								 ZC_FORMAT_DATA->hashtype) != 0) {
						fprintf(stderr, "Couldn't configure RSS hashing! "
							"falling back to software hashing: %s\n",
                                                        pfring_ifname_from_uridata(libtrace->uridata));
						return -1;
					}
					// check for any flow director rules
					if ((ret = linux_get_nic_flow_rule_count(
                                                pfring_ifname_from_uridata(libtrace->uridata))) > 0) {

						fprintf(stderr, "%d flow director rules detected on interface %s, "
							"RSS hashing may not work correctly!\n", ret,
                                                        pfring_ifname_from_uridata(libtrace->uridata));
					}
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

static int pfringzc_pause_input(libtrace_t *libtrace) {
	pfring_zc_destroy_cluster(ZC_FORMAT_DATA->cluster);
        ZC_FORMAT_DATA->cluster = NULL;
	if (libtrace->format_data) {
		if (ZC_FORMAT_DATA->devices) {
			free(ZC_FORMAT_DATA->devices);
                        ZC_FORMAT_DATA->devices = NULL;
                }
		if (ZC_FORMAT_DATA->perthreads) {
			free(ZC_FORMAT_DATA->perthreads);
                        ZC_FORMAT_DATA->perthreads = NULL;
                }
	}
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

static int pfringzc_fin_input(libtrace_t *libtrace) {
	if (libtrace->format_data) {
		if (ZC_FORMAT_DATA->bpffilter) {
			free(ZC_FORMAT_DATA->bpffilter);
                        ZC_FORMAT_DATA->bpffilter = NULL;
                }
		free(libtrace->format_data);
	}
	return 0;
}

static int pfringzc_fin_output(libtrace_out_t *libtrace) {
        pfring_zc_destroy_cluster(ZC_FORMAT_DATA->cluster);
        ZC_FORMAT_DATA->cluster = NULL;
        if (libtrace->format_data) {
                if (ZC_FORMAT_DATA->devices) {
                        free(ZC_FORMAT_DATA->devices);
                        ZC_FORMAT_DATA->devices = NULL;
                }
                if (ZC_FORMAT_DATA->perthreads) {
                        free(ZC_FORMAT_DATA->perthreads);
                        ZC_FORMAT_DATA->perthreads = NULL;
                }
                if (ZC_FORMAT_DATA->bpffilter) {
                        free(ZC_FORMAT_DATA->bpffilter);
                        ZC_FORMAT_DATA->bpffilter = NULL;
                }
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
			       libtrace_packet_t *packet[],
			       libtrace_message_queue_t *msg,
			       struct pfringzc_per_thread *stream,
			       size_t nb_packets,
			       bool blocking) {

	int received = 0;

	if (nb_packets > PFRINGZC_BATCHSIZE)
		nb_packets = PFRINGZC_BATCHSIZE;

	while (received < 1) {

		received = pfring_zc_recv_pkt_burst(
				stream->device,
				stream->buffers,
				nb_packets,
				0);

		if (received < 0) {
			trace_set_err(libtrace, errno, "Failed to read packet batch from pfringzc:");
			return -1;
		}

		if (received == 0) {
			if (msg && libtrace_message_queue_count(msg) > 0)
				return READ_MESSAGE;
			if (is_halted(libtrace) != -1) {
				return is_halted(libtrace);
			}
			continue;
		}

		if (!blocking && received == 0)
			return 0;
	}

	for (int i = 0; i < received; i++) {

		u_char *pkt_buf = pfring_zc_pkt_buff_data(stream->buffers[i], stream->device);

		packet[i]->buf_control = TRACE_CTRL_EXTERNAL;
		packet[i]->type = TRACE_RT_DATA_PFRING;
		packet[i]->buffer = stream->buffers[i];
		packet[i]->header = stream->buffers[i]->user;
		packet[i]->payload = pkt_buf;
		packet[i]->trace = libtrace;
		packet[i]->error = 1;
                packet[i]->order = pfring_timespec_to_systime(&stream->buffers[i]->ts);
                if (packet[i]->order <= stream->prev_sys_time) {
                    packet[i]->order += 1;
                }

		struct libtrace_pfring_header *hdr = (struct libtrace_pfring_header *)stream->buffers[i]->user;
#if __BYTE_ORDER == __LITTLE_ENDIAN
		hdr->byteorder = PFRING_BYTEORDER_LITTLEENDIAN;
#else
		hdr->byteorder = PFRING_BYTEORDER_BIGENDIAN;
#endif
		hdr->caplen = LIBTRACE_MIN((unsigned int)ZC_FORMAT_DATA->snaplen,
					   (unsigned int)stream->buffers[i]->len);
		hdr->wlen = stream->buffers[i]->len;
		hdr->ts.tv_sec = stream->buffers[i]->ts.tv_sec;
		hdr->ts.tv_usec = stream->buffers[i]->ts.tv_nsec / 1000;
		hdr->ext.ts_ns = 0;

                stream->prev_sys_time = packet[i]->order;
	}

	return received;
}

static int pfring_read_generic(libtrace_t *libtrace, libtrace_packet_t *packet,
		struct pfring_per_stream_t *stream, uint8_t block, 
		libtrace_message_queue_t *queue)
{

        struct libtrace_pfring_header *hdr;
        struct local_pfring_header *local;
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
        /* pfring_recv fills a local_pfring_header, we line this up with
         * the libtrace_pfring_header to avoid extra memory copies */
        local = (struct local_pfring_header *)(((char *)hdr) +
                                               PFRING_LOCAL_STRUCT_OFFSET);

	do {
		if ((rc = pfring_recv(stream->pd, (u_char **)&packet->payload,
			0, (struct pfring_pkthdr *)local, 0)) == -1) {
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

        /* Convert timespec to 64-bit, if it is not already */
        hdr->ts.tv_sec = local->ts.tv_sec;
        hdr->ts.tv_usec = local->ts.tv_usec;

	packet->trace = libtrace;
	packet->type = TRACE_RT_DATA_PFRINGOLD;
	packet->header = packet->buffer;
	packet->error = 1;

	return pfring_get_capture_length(packet) + 
			pfring_get_framing_length(packet);

}

static int pfringzc_read_packet(libtrace_t *libtrace,
				libtrace_packet_t *packet) {

	struct pfringzc_per_thread *stream =
		&(ZC_FORMAT_DATA->perthreads[0]);

	return pfringzc_read_batch(libtrace,
                                   &packet,
                                   NULL,
                                   stream,
                                   1,
                                   1);
}

static int pfringzc_pread_packets(libtrace_t *libtrace,
				  libtrace_thread_t *thread,
				  libtrace_packet_t **packets,
				  size_t nb_packets) {

	struct pfringzc_per_thread *stream =
		(struct pfringzc_per_thread *)thread->format_data;

	return pfringzc_read_batch(libtrace,
				   packets,
				   &thread->messages,
				   stream,
				   nb_packets,
				   1);
}

static int pfringzc_write_packet(libtrace_out_t *libtrace,
                                 libtrace_packet_t *packet) {
        if (!pfring_can_write(packet)) {
            return 0;
        }
        struct pfringzc_per_thread *stream =
                &(ZC_FORMAT_DATA->perthreads[0]);
        u_char *buffer = pfring_zc_pkt_buff_data(stream->buffers[0], stream->device);
        uint32_t capture_length = trace_get_capture_length(packet);
        stream->buffers[0]->len = capture_length;
        memcpy(buffer, (char *)packet->payload, capture_length);
        pfring_zc_send_pkt(stream->device, &stream->buffers[0], 0);
        return capture_length;
}

static int pfringzc_flush_output(libtrace_out_t *libtrace) {
        struct pfringzc_per_thread *stream =
                &(ZC_FORMAT_DATA->perthreads[0]);
        pfring_zc_sync_queue(stream->device, tx_only);
        return 0;
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
        struct linux_dev_stats dev_stats;
	size_t i;
        ZERO_STATS(stat);

	for (i = 0; i < libtrace_list_get_size(FORMAT_DATA->per_stream); ++i) {
		struct pfring_per_stream_t *stream;
		stream = libtrace_list_get_index(FORMAT_DATA->per_stream, i)->data;

		if (pfring_stats(stream->pd, &st) != 0) {
			trace_set_err(libtrace, errno, "Failed to get statistics for pfring stream %u", (uint32_t)i);
			continue;
		}

                // dropped between pfring and libtrace?
		stat->dropped += st.drop;
	}

        if (FORMAT_DATA->interface_stats.if_name[0] != 0) {
                if (linux_get_dev_statistics(pfring_ifname_from_uridata(libtrace->uridata),
                                             &dev_stats) == 0) {

                        // add card drops
                        stat->dropped += (dev_stats.rx_drops - FORMAT_DATA->interface_stats.rx_drops);
                        stat->dropped_valid = 1;

                        // calculate recieved packets by the card, this includes dropped packets but not errored
                        stat->received = (dev_stats.rx_packets - FORMAT_DATA->interface_stats.rx_packets);
                        stat->received += (dev_stats.rx_drops - FORMAT_DATA->interface_stats.rx_drops);
                        stat->received_valid = 1;

                        // add card errors
                        stat->errors = (dev_stats.rx_errors - FORMAT_DATA->interface_stats.rx_errors);
                        stat->errors_valid = 1;
                }
        }

        if (stat->received_valid && stat->dropped_valid) {
               stat->captured = stat->received - stat->dropped;
               stat->captured_valid = 1;
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

static libtrace_eventobj_t pfringzc_event(libtrace_t *libtrace, libtrace_packet_t *packet) {
	libtrace_eventobj_t event = {0,0,0.0,0};
	struct pfringzc_per_thread *stream = &(ZC_FORMAT_DATA->perthreads[0]);
	int rc = pfringzc_read_batch(libtrace, &packet, NULL, stream, 1, 0);
	if (rc > 0) {
		event.type = TRACE_EVENT_PACKET;
		event.size = trace_get_payload_length(packet);
	} else {
		event.type = TRACE_EVENT_SLEEP;
		event.seconds = 0.0001;
		event.size = 0;
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

static void pfringzc_get_stats(libtrace_t *libtrace,
			       libtrace_stat_t *stats) {
	int threads, i;
	pfring_zc_stat zcstats;
	struct linux_dev_stats dev_stats;
        ZERO_STATS(stats);

	if (libtrace->perpkt_thread_count == 0 || trace_has_dedicated_hasher(libtrace)) {
		threads = 1;
	} else {
		threads = libtrace->perpkt_thread_count;
	}

	for (i = 0; i < threads; i++) {
                struct pfringzc_per_thread *stream = &(ZC_FORMAT_DATA->perthreads[i]);
                if (pfring_zc_stats(stream->device, &zcstats) != 0) {
                        trace_set_err(libtrace, errno, "Failed to get statistics for pfring\n");
                        return;
                }

		// libtrace received includes dropped
	        stats->received += zcstats.recv + zcstats.drop;
	        stats->received_valid = 1;

                stats->dropped += zcstats.drop;
                stats->dropped_valid = 1;
        }

	// when using zero copy stats from pfring_zc_stats are correct however when not in zero copy we
	// need to get stats from the card
	if (!(ZC_FORMAT_DATA->zero_copy)) {
		stats->received_valid = 0;
                stats->dropped_valid = 0;
		if (ZC_FORMAT_DATA->interface_stats.if_name[0] != 0) {
                	if (linux_get_dev_statistics(pfring_ifname_from_uridata(libtrace->uridata),
                                                     &dev_stats) == 0) {

                        	// add card drops
                        	stats->dropped += (dev_stats.rx_drops - ZC_FORMAT_DATA->interface_stats.rx_drops);
                        	stats->dropped_valid = 1;

                        	// calculate recieved packets by the card, this includes dropped packets but not errored
                        	stats->received = (dev_stats.rx_packets - ZC_FORMAT_DATA->interface_stats.rx_packets);
                        	stats->received += (dev_stats.rx_drops - ZC_FORMAT_DATA->interface_stats.rx_drops);
                        	stats->received_valid = 1;

                        	// add card errors
                        	stats->errors = (dev_stats.rx_errors - ZC_FORMAT_DATA->interface_stats.rx_errors);
                        	stats->errors_valid = 1;
			}
        	}
	}

	if (stats->received_valid && stats->dropped_valid) {
                stats->captured = stats->received - stats->dropped;
        	stats->captured_valid = 1;
        }
}

static void pfringzc_get_thread_stats(libtrace_t *libtrace,
				      libtrace_thread_t *thread,
				      libtrace_stat_t *stats) {
	pfring_zc_stat zcstats;
	struct linux_dev_stats dev_stats;
	ZERO_STATS(stats);
	struct pfringzc_per_thread *stream;

	stream = (struct pfringzc_per_thread *)thread->format_data;
	if (stream != NULL) {
		if (pfring_zc_stats(stream->device, &zcstats) != 0) {
			trace_set_err(libtrace, errno, "Failed to get pfring thread statistics\n");
			return;
		}

		// libtrace received includes dropped
                stats->received += zcstats.recv + zcstats.drop;
                stats->received_valid = 1;

                stats->dropped += zcstats.drop;
                stats->dropped_valid = 1;
	}

	// when using zero copy stats from pfring_zc_stats are correct however when not in zero copy we
        // need to get stats from the card
        if (!(ZC_FORMAT_DATA->zero_copy)) {
                if (ZC_FORMAT_DATA->interface_stats.if_name[0] != 0) {
                        if (linux_get_dev_statistics(pfring_ifname_from_uridata(libtrace->uridata),
                                                     &dev_stats) == 0) {

                                // add card drops
                                stats->dropped += (dev_stats.rx_drops - ZC_FORMAT_DATA->interface_stats.rx_drops);
                                stats->dropped_valid = 1;

                                // calculate recieved packets by the card, this includes dropped packets but not errored
                                stats->received = (dev_stats.rx_packets - ZC_FORMAT_DATA->interface_stats.rx_packets);
                                stats->received += (dev_stats.rx_drops - ZC_FORMAT_DATA->interface_stats.rx_drops);
                                stats->received_valid = 1;

                                // add card errors
                                stats->errors = (dev_stats.rx_errors - ZC_FORMAT_DATA->interface_stats.rx_errors);
                                stats->errors_valid = 1;
                        }
                }
        }

	if (stats->received_valid && stats->dropped_valid) {
               stats->captured = stats->received - stats->dropped;
               stats->captured_valid = 1;
        }
}

static int pfringzc_pregister_thread(libtrace_t *libtrace,
				     libtrace_thread_t *t,
				     bool reading) {
	if (reading) {
		if (t->type == THREAD_PERPKT) {
			struct pfringzc_per_thread *stream = &(ZC_FORMAT_DATA->perthreads[t->perpkt_num]);
			t->format_data = stream;
			if (t->format_data == NULL) {
				trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Too many threads registered");
				return -1;
			}
		}
	}
	return 0;
}

static struct libtrace_format_t pfringoldformat = {
	"pfringold",
	"$Id$",
	TRACE_FORMAT_PFRINGOLD,
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

static struct libtrace_format_t pfringformat = {
        "pfring",
        "$Id$",
        TRACE_FORMAT_PFRING,
        NULL,                           /* probe filename */
        NULL,                           /* probe magic */
        pfringzc_init_input,            /* init_input */
        pfringzc_config_input,          /* config_input */
        pfringzc_start_input,           /* start_input */
        pfringzc_pause_input,           /* pause_input */
        pfringzc_init_output,           /* init_output */
        NULL,                           /* config_output */
        pfringzc_start_output,          /* start_output */
        pfringzc_fin_input,             /* fin_input */
        pfringzc_fin_output,            /* fin_output */
        pfringzc_read_packet,           /* read_packet */
        pfring_prepare_packet,          /* prepare_packet */
        NULL,                           /* fin_packet */
        NULL,                           /* can_hold_packet */
        pfringzc_write_packet,          /* write_packet */
        pfringzc_flush_output,          /* flush_output */
        pfring_get_link_type,           /* get_link_type */
        NULL,                           /* get_direction */
        NULL,                           /* set_direction */
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
        NULL,                           /* set_capture_length */
        NULL,                           /* get_received_packets */
        NULL,                           /* get_filtered_packets */
        NULL,                           /* get_dropped_packets */
        pfringzc_get_stats,             /* get_statistics */
        NULL,                           /* get_fd */
        pfringzc_event,                 /* trace_event */
        NULL,                           /* help */
        NULL,                           /* next pointer */
        {true, -1},
	pfringzc_start_input,           /* pstart_input */
	pfringzc_pread_packets,         /* pread_packets */
	pfringzc_pause_input,           /* ppause */
	pfringzc_fin_input,             /* p_fin */
	pfringzc_pregister_thread,      /* register thread */
	NULL,                           /* unregister thread */
	pfringzc_get_thread_stats       /* get thread stats */
};

void pfringold_constructor(void) {
	register_format(&pfringoldformat);
}

void pfring_constructor(void) {
        register_format(&pfringformat);
}
