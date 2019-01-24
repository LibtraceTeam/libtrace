
#include "config.h"
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "format_erf.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "format_dpdk.h"
#include "format_ndag.h"

static struct libtrace_format_t dpdkndag;

typedef struct capstream {

        uint16_t port;
        uint32_t expectedseq;
        uint64_t recordcount;
} capstream_t;

typedef struct perthread {
        capstream_t *capstreams;
        uint16_t streamcount;
        uint64_t dropped_upstream;
        uint64_t missing_records;
        uint64_t received_packets;

	libtrace_packet_t *dpdkpkt;
        char *ndagheader;
        char *nextrec;
        uint32_t ndagsize;

        pthread_mutex_t ndag_lock;
	dpdk_per_stream_t *dpdkstreamdata;
        int burstsize;
        int burstoffset;
        struct rte_mbuf* burstspace[40];

} perthread_t;


typedef struct dpdkndag_format_data {
        libtrace_t *dpdkrecv;

        struct addrinfo *multicastgroup;
        char *localiface;

	perthread_t *threaddatas;

} dpdkndag_format_data_t;

#define FORMAT_DATA ((dpdkndag_format_data_t *)libtrace->format_data)

static inline int seq_cmp(uint32_t seq_a, uint32_t seq_b) {

        /* Calculate seq_a - seq_b, taking wraparound into account */
        if (seq_a == seq_b) return 0;

        if (seq_a > seq_b) {
                return (int) (seq_a - seq_b);
        }

        /* -1 for the wrap and another -1 because we don't use zero */
        return (int) (0xffffffff - ((seq_b - seq_a) - 2));
}


static int dpdkndag_init_input(libtrace_t *libtrace) {

	char *scan = NULL;
	char *next = NULL;
	char dpdkuri[1280];
        struct addrinfo hints, *result;

        libtrace->format_data = (dpdkndag_format_data_t *)malloc(
                        sizeof(dpdkndag_format_data_t));

	if (!libtrace->format_data) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable to allocate memory for "
			"format data inside dpdkndag_init_input()");
		return -1;
	}

        FORMAT_DATA->localiface = NULL;
        FORMAT_DATA->threaddatas = NULL;
        FORMAT_DATA->dpdkrecv = NULL;

        scan = strchr(libtrace->uridata, ',');
        if (scan == NULL) {
                trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT,
                        "Bad dpdkndag URI. Should be dpdkndag:<interface>,<multicast group>");
                return -1;
        }
        FORMAT_DATA->localiface = strndup(libtrace->uridata,
                        (size_t)(scan - libtrace->uridata));
        next = scan + 1;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;
        hints.ai_protocol = 0;

        if (getaddrinfo(next, NULL, &hints, &result) != 0) {
                perror("getaddrinfo");
                trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT,
                        "Invalid multicast address: %s", next);
                return -1;
        }

        FORMAT_DATA->multicastgroup = result;

	snprintf(dpdkuri, 1279, "dpdk:%s", FORMAT_DATA->localiface);
	FORMAT_DATA->dpdkrecv = trace_create(dpdkuri);

	if (trace_is_err(FORMAT_DATA->dpdkrecv)) {
		libtrace_err_t err = trace_get_err(FORMAT_DATA->dpdkrecv);
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err.problem);
		free(libtrace->format_data);
		libtrace->format_data = NULL;
		return -1;
	}

	return 0;
}

static int dpdkndag_config_input (libtrace_t *libtrace, trace_option_t option,
		void *data) {

	return dpdk_config_input(FORMAT_DATA->dpdkrecv, option, data);
}

static int dpdkndag_init_threads(libtrace_t *libtrace, uint32_t maxthreads) {

	uint32_t i;
	if (FORMAT_DATA->threaddatas == NULL) {
		FORMAT_DATA->threaddatas = (perthread_t *)malloc(
				sizeof(perthread_t) * maxthreads);
	}

	for (i = 0; i < maxthreads; i++) {
		FORMAT_DATA->threaddatas[i].capstreams = NULL;
		FORMAT_DATA->threaddatas[i].streamcount = 0;
		FORMAT_DATA->threaddatas[i].dropped_upstream = 0;
		FORMAT_DATA->threaddatas[i].received_packets = 0;
		FORMAT_DATA->threaddatas[i].missing_records = 0;
		FORMAT_DATA->threaddatas[i].dpdkstreamdata = NULL;
		FORMAT_DATA->threaddatas[i].dpdkpkt = trace_create_packet();
		FORMAT_DATA->threaddatas[i].ndagheader = NULL;
		FORMAT_DATA->threaddatas[i].nextrec = NULL;
		FORMAT_DATA->threaddatas[i].burstsize = 0;
		FORMAT_DATA->threaddatas[i].burstoffset = 0;
                memset(FORMAT_DATA->threaddatas[i].burstspace, 0,
                                sizeof(struct rte_mbuf *) * 40);
                pthread_mutex_init(&(FORMAT_DATA->threaddatas[i].ndag_lock),
                                NULL);
	}
	return maxthreads;
}

static int dpdkndag_start_input(libtrace_t *libtrace) {
        enum hasher_types hash = HASHER_UNIDIRECTIONAL;
        int snaplen = 9000;

        if (dpdk_config_input(FORMAT_DATA->dpdkrecv, TRACE_OPTION_HASHER,
                                &hash) == -1) {
		libtrace_err_t err = trace_get_err(FORMAT_DATA->dpdkrecv);
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err.problem);
		return -1;
	}

        if (dpdk_config_input(FORMAT_DATA->dpdkrecv, TRACE_OPTION_SNAPLEN,
                                &snaplen) == -1) {
		libtrace_err_t err = trace_get_err(FORMAT_DATA->dpdkrecv);
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err.problem);
		return -1;
	}

	if (dpdk_start_input(FORMAT_DATA->dpdkrecv) == -1) {
		libtrace_err_t err = trace_get_err(FORMAT_DATA->dpdkrecv);
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err.problem);
		return -1;
	}

	dpdkndag_init_threads(libtrace, 1);

	return 0;
}

static int dpdkndag_pstart_input(libtrace_t *libtrace) {

        enum hasher_types hash = HASHER_UNIDIRECTIONAL;
        int snaplen = 9000;
        FORMAT_DATA->dpdkrecv->perpkt_thread_count = libtrace->perpkt_thread_count;
        if (dpdk_config_input(FORMAT_DATA->dpdkrecv, TRACE_OPTION_HASHER,
                                &hash) == -1) {
		libtrace_err_t err = trace_get_err(FORMAT_DATA->dpdkrecv);
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err.problem);
		return -1;
	}

        if (dpdk_config_input(FORMAT_DATA->dpdkrecv, TRACE_OPTION_SNAPLEN,
                                &snaplen) == -1) {
		libtrace_err_t err = trace_get_err(FORMAT_DATA->dpdkrecv);
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err.problem);
		return -1;
	}
	if (dpdk_pstart_input(FORMAT_DATA->dpdkrecv) == -1) {
		libtrace_err_t err = trace_get_err(FORMAT_DATA->dpdkrecv);
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err.problem);
		return -1;
	}
	dpdkndag_init_threads(libtrace, libtrace->perpkt_thread_count);
	return 0;
}

static void clear_threaddata(perthread_t *pt) {

        int i;

        if (pt->dpdkpkt) {
                trace_destroy_packet(pt->dpdkpkt);
        }
        pt->dpdkpkt = NULL;

	if (pt->capstreams) {
	        free(pt->capstreams);
        }

        for (i = 0; i < 40; i++) {
                if (pt->burstspace[i]) {
                        rte_pktmbuf_free(pt->burstspace[i]);
                }
        }
        pthread_mutex_destroy(&(pt->ndag_lock));
}

static int dpdkndag_pause_input(libtrace_t *libtrace) {

        int i;
	/* Pause DPDK receive */
	dpdk_pause_input(FORMAT_DATA->dpdkrecv);

	/* Clear the threaddatas */
	for (i = 0; i < libtrace->perpkt_thread_count; i++) {
		clear_threaddata(&(FORMAT_DATA->threaddatas[i]));
	}
	return 0;
}

static int dpdkndag_fin_input(libtrace_t *libtrace) {

	if (FORMAT_DATA->dpdkrecv) {
		trace_destroy(FORMAT_DATA->dpdkrecv);
	}

	if (FORMAT_DATA->threaddatas) {
		free(FORMAT_DATA->threaddatas);
	}

	if (FORMAT_DATA->localiface) {
		free(FORMAT_DATA->localiface);
	}

	if (FORMAT_DATA->multicastgroup) {
		freeaddrinfo(FORMAT_DATA->multicastgroup);
	}

	free(FORMAT_DATA);
	return 0;
}

static int dpdkndag_pregister_thread(libtrace_t *libtrace, libtrace_thread_t *t,
		bool reader) {

	perthread_t *pt;

	if (!reader || t->type != THREAD_PERPKT) {
		return 0;
	}

	if (dpdk_pregister_thread(FORMAT_DATA->dpdkrecv, t, reader) == -1) {
		libtrace_err_t err = trace_get_err(FORMAT_DATA->dpdkrecv);
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err.problem);
		return -1;
	}

	/* t->format_data now contains our dpdk stream data */
	pt = &(FORMAT_DATA->threaddatas[t->perpkt_num]);
	pt->dpdkstreamdata = t->format_data;
	t->format_data = pt;

	return 0;
}

static void dpdkndag_punregister_thread(libtrace_t *libtrace, libtrace_thread_t *t) {

	dpdk_punregister_thread(libtrace, t);
}

static void dpdkndag_get_thread_stats(libtrace_t *libtrace, libtrace_thread_t *t,
		libtrace_stat_t *stat) {

	perthread_t *pt = (perthread_t *)t->format_data;

	if (libtrace == NULL) {
		return;
	}

	        /* TODO Is this thread safe */
        stat->dropped_valid = 1;
        stat->dropped = pt->dropped_upstream;

        stat->received_valid = 1;
        stat->received = pt->received_packets;

        stat->missing_valid = 1;
        stat->missing = pt->missing_records;
}

static void dpdkndag_get_statistics(libtrace_t *libtrace, libtrace_stat_t *stat) {
        int i;

        libtrace_stat_t *dpdkstat;

        stat->dropped_valid = 1;
        stat->dropped = 0;
        stat->received_valid = 1;
        stat->received = 0;
        stat->missing_valid = 1;
        stat->missing = 0;

        dpdkstat = trace_create_statistics();
        dpdk_get_stats(FORMAT_DATA->dpdkrecv, dpdkstat);

        if (dpdkstat->dropped_valid) {
                stat->errors_valid = 1;
                stat->errors = dpdkstat->dropped;
        }

        /* TODO Is this thread safe? */
        for (i = 0; i < libtrace->perpkt_thread_count; i++) {
                pthread_mutex_lock(&(FORMAT_DATA->threaddatas[i].ndag_lock));
                stat->dropped += FORMAT_DATA->threaddatas[i].dropped_upstream;
                stat->received += FORMAT_DATA->threaddatas[i].received_packets;
                stat->missing += FORMAT_DATA->threaddatas[i].missing_records;
                pthread_mutex_unlock(&(FORMAT_DATA->threaddatas[i].ndag_lock));
        }
        free(dpdkstat);
}

static int is_ndag_packet(libtrace_packet_t *packet, perthread_t *pt) {

	void *trans = NULL;
	uint32_t rem = 0;
	uint8_t proto;
	char *payload;

	trans = trace_get_transport(packet, &proto, &rem);
	if (trans == NULL) {
		return 0;
	}

	if (proto != TRACE_IPPROTO_UDP) {
		return 0;
	}

	payload = (char *)trace_get_payload_from_udp((libtrace_udp_t *)trans,
                        &rem);

	if (payload == NULL) {
		return 0;
	}

	if (rem < 4) {
		return 0;
	}

	if (payload[0] == 'N' && payload[1] == 'D' && payload[2] == 'A'
                        && payload[3] == 'G') {
                pt->ndagsize = rem;
                pt->ndagheader = payload;
                return 1;
        }

        return 0;

}

static int sockaddr_same(struct sockaddr *a, struct sockaddr *b) {

        if (a->sa_family != b->sa_family) {
                return 0;
        }

        if (a->sa_family == AF_INET) {
                struct sockaddr_in *ain = (struct sockaddr_in *)a;
                struct sockaddr_in *bin = (struct sockaddr_in *)b;

                if (ain->sin_addr.s_addr != bin->sin_addr.s_addr) {
                        return 0;
                }
                return 1;
        } else if (a->sa_family == AF_INET6) {
                struct sockaddr_in6 *ain6 = (struct sockaddr_in6 *)a;
                struct sockaddr_in6 *bin6 = (struct sockaddr_in6 *)b;

                if (memcmp(ain6->sin6_addr.s6_addr, bin6->sin6_addr.s6_addr,
                                sizeof(ain6->sin6_addr.s6_addr)) != 0) {
                        return 0;
                }
                return 1;
        }
        return 0;
}

static int process_fresh_packet(perthread_t *pt, struct addrinfo *expectedaddr) {

        ndag_common_t *header = (ndag_common_t *)pt->ndagheader;
        ndag_encap_t *encaphdr = (ndag_encap_t *)(pt->ndagheader +
                        sizeof(ndag_common_t));
        uint16_t targetport;
        struct sockaddr_storage targetaddr;
        struct sockaddr *p;
        capstream_t *cap = NULL;
        int i;

        memset((&targetaddr), 0, sizeof(targetaddr));
        if (header->type != NDAG_PKT_ENCAPERF) {
                pt->nextrec = NULL;
                pt->ndagsize = 0;
                pt->ndagheader = NULL;
                return 1;
        }

        if ((p = trace_get_destination_address(pt->dpdkpkt,
                        (struct sockaddr *)(&targetaddr))) == NULL) {
                pt->nextrec = NULL;
                pt->ndagsize = 0;
                pt->ndagheader = NULL;
                return 1;
        }

        if (!(sockaddr_same(p, expectedaddr->ai_addr))) {
                pt->nextrec = NULL;
                pt->ndagsize = 0;
                pt->ndagheader = NULL;
                return 1;
        }

        targetport = trace_get_destination_port(pt->dpdkpkt);
        if (pt->streamcount == 0) {
                pt->capstreams = (capstream_t *)malloc(sizeof(capstream_t));
                pt->streamcount = 1;
                pt->capstreams[0].port = targetport;
                pt->capstreams[0].expectedseq = 0;
                pt->capstreams[0].recordcount = 0;
                cap = pt->capstreams;

        } else {
                for (i = 0; i < pt->streamcount; i++) {
                        if (pt->capstreams[i].port == targetport) {
                                cap = (&pt->capstreams[i]);
                                break;
                        }
                }

                if (cap == NULL) {
                        uint16_t next = pt->streamcount;
                        pt->capstreams = (capstream_t *)realloc(pt->capstreams,
                                    sizeof(capstream_t) * (pt->streamcount + 1));
                        pt->streamcount += 1;
                        pt->capstreams[next].port = targetport;
                        pt->capstreams[next].expectedseq = 0;
                        pt->capstreams[next].recordcount = 0;
                        cap = &(pt->capstreams[next]);
                }
        }
        if (cap->expectedseq != 0) {
                pthread_mutex_lock(&pt->ndag_lock);
                pt->missing_records += seq_cmp(
                                ntohl(encaphdr->seqno), cap->expectedseq);
                pthread_mutex_unlock(&pt->ndag_lock);
        }
        cap->expectedseq = ntohl(encaphdr->seqno) + 1;
        if (cap->expectedseq == 0) {
                cap->expectedseq ++;
        }
        cap->recordcount ++;

        pt->nextrec = ((char *)header) + sizeof(ndag_common_t) +
                        sizeof(ndag_encap_t);

        return 1;
}

static int ndagrec_to_libtrace_packet(libtrace_t *libtrace, perthread_t *pt,
                libtrace_packet_t *packet) {

	/* This is mostly borrowed from ndag_prepare_packet_stream, minus
	 * the ndag socket-specific stuff */

        dag_record_t *erfptr;
        ndag_encap_t *encaphdr;

        if (pt->nextrec == NULL) {
                return -1;
        }

        if (pt->nextrec - pt->ndagheader >= pt->ndagsize) {
                return -1;
        }

	packet->buf_control = TRACE_CTRL_EXTERNAL;

        packet->trace = libtrace;
        packet->buffer = pt->nextrec;
        packet->header = pt->nextrec;
        packet->type = TRACE_RT_DATA_ERF;

        erfptr = (dag_record_t *)packet->header;

        if (erfptr->flags.rxerror == 1) {
                packet->payload = NULL;
                erfptr->rlen = htons(erf_get_framing_length(packet));
        } else {
                packet->payload = (char *)packet->buffer +
                                erf_get_framing_length(packet);
        }

        /* Update upstream drops using lctr */

        if (erfptr->type == TYPE_DSM_COLOR_ETH) {
                /* TODO */
        } else {
                pthread_mutex_lock(&(pt->ndag_lock));
                if (pt->received_packets > 0) {
                        pt->dropped_upstream += ntohs(erfptr->lctr);
                }
                pthread_mutex_unlock(&(pt->ndag_lock));
        }

        pthread_mutex_lock(&(pt->ndag_lock));
	pt->received_packets ++;
        pthread_mutex_unlock(&(pt->ndag_lock));
	encaphdr = (ndag_encap_t *)(pt->ndagheader + sizeof(ndag_common_t));

	if ((ntohs(encaphdr->recordcount) & 0x8000) != 0) {
		/* Record was truncated */
		erfptr->rlen = htons(pt->ndagsize - (pt->nextrec -
				pt->ndagheader));
	}

	pt->nextrec += ntohs(erfptr->rlen);

	if (pt->nextrec - pt->ndagheader >= pt->ndagsize) {
		pt->ndagheader = NULL;
		pt->nextrec = NULL;
		pt->ndagsize = 0;
	}

	packet->order = erf_get_erf_timestamp(packet);
	packet->error = packet->payload ? ntohs(erfptr->rlen) :
			erf_get_framing_length(packet);
	return ntohs(erfptr->rlen);
}

static int dpdkndag_pread_packets(libtrace_t *libtrace,
                                    libtrace_thread_t *t,
                                    libtrace_packet_t **packets,
                                    size_t nb_packets) {

	perthread_t *pt = (perthread_t *)t->format_data;
	size_t read_packets = 0;
        int ret;

        while (pt->nextrec == NULL) {
                trace_fin_packet(pt->dpdkpkt);

                if (pt->burstsize > 0 && pt->burstsize != pt->burstoffset) {
                        pt->dpdkpkt->buffer = pt->burstspace[pt->burstoffset];
                        pt->dpdkpkt->trace = FORMAT_DATA->dpdkrecv;
                        dpdk_prepare_packet(FORMAT_DATA->dpdkrecv, pt->dpdkpkt,
                                        pt->dpdkpkt->buffer,
                                        TRACE_RT_DATA_DPDK, 0);
                        pt->burstoffset ++;
                } else {
                        ret = dpdk_read_packet_stream(FORMAT_DATA->dpdkrecv,
                                        pt->dpdkstreamdata,
                                        &t->messages,
                                        pt->burstspace,
                                        40);
                        if (ret <= 0) {
                                return ret;
                        }

                        pt->dpdkpkt->buffer = pt->burstspace[0];
                        pt->dpdkpkt->trace = FORMAT_DATA->dpdkrecv;
                        dpdk_prepare_packet(FORMAT_DATA->dpdkrecv, pt->dpdkpkt,
                                        pt->dpdkpkt->buffer,
                                        TRACE_RT_DATA_DPDK, 0);
                        pt->burstsize = ret;
                        pt->burstoffset = 1;
                }

                if (!is_ndag_packet(pt->dpdkpkt, pt)) {
                        continue;
                }

                ret = process_fresh_packet(pt, FORMAT_DATA->multicastgroup);
                if (ret <= 0) {
                        return ret;
                }
        }

        while (pt->nextrec != NULL) {
                if (read_packets == nb_packets) {
                        break;
                }

                if (packets[read_packets]->buf_control == TRACE_CTRL_PACKET) {
                        free(packets[read_packets]->buffer);
                        packets[read_packets]->buffer = NULL;
                }
                ret = ndagrec_to_libtrace_packet(libtrace, pt,
                                packets[read_packets]);
                if (ret < 0) {
                        return ret;
                }
                read_packets ++;

        }

	return read_packets;
}

static int dpdkndag_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {

	perthread_t *pt = &(FORMAT_DATA->threaddatas[0]);
	int ret;

	if (packet->buf_control == TRACE_CTRL_PACKET) {
		free(packet->buffer);
		packet->buffer = NULL;
	}

	while (pt->nextrec == NULL) {
                trace_fin_packet(pt->dpdkpkt);

		ret = dpdk_read_packet(FORMAT_DATA->dpdkrecv, pt->dpdkpkt);
		if (ret <= 0) {
			return ret;
		}

		if (!is_ndag_packet(pt->dpdkpkt, pt)) {
			continue;
		}

		ret = process_fresh_packet(pt, FORMAT_DATA->multicastgroup);
		if (ret <= 0) {
			return ret;
		}
	}

	return ndagrec_to_libtrace_packet(libtrace, pt, packet);
}

static libtrace_eventobj_t trace_event_dpdkndag(libtrace_t *libtrace,
                libtrace_packet_t *packet) {


        libtrace_eventobj_t event;
        int ret;
        perthread_t *pt = &(FORMAT_DATA->threaddatas[0]);

	if (packet->buf_control == TRACE_CTRL_PACKET) {
		free(packet->buffer);
		packet->buffer = NULL;
	}

        while (pt->nextrec == NULL) {

                event = dpdk_trace_event(libtrace, pt->dpdkpkt);

                if (event.type != TRACE_EVENT_PACKET) {
                        return event;
                }

		if (!is_ndag_packet(pt->dpdkpkt, pt)) {
			continue;
		}

		ret = process_fresh_packet(pt, FORMAT_DATA->multicastgroup);
		if (ret <= 0) {
			event.type = TRACE_EVENT_TERMINATE;
                        return event;
		}
        }

        ret = ndagrec_to_libtrace_packet(libtrace, pt, packet);
        if (ret < 0) {
                event.type = TRACE_EVENT_TERMINATE;
        } else {
                event.type = TRACE_EVENT_PACKET;
                event.size = 1;
        }
        return event;
}

static struct libtrace_format_t dpdkndag = {

        "dpdkndag",
        "",
        TRACE_FORMAT_DPDK_NDAG,
        NULL,                   /* probe filename */
        NULL,                   /* probe magic */
        dpdkndag_init_input,        /* init_input */
        dpdkndag_config_input,      /* config_input */
        dpdkndag_start_input,       /* start_input */
        dpdkndag_pause_input,       /* pause_input */
        NULL,                   /* init_output */
        NULL,                   /* config_output */
        NULL,                   /* start_output */
        dpdkndag_fin_input,         /* fin_input */
        NULL,                   /* fin_output */
        dpdkndag_read_packet,   /* read_packet */
        NULL,			/* prepare_packet */
        NULL,                   /* fin_packet */
        NULL,                   /* write_packet */
        NULL,                   /* flush_output */
        erf_get_link_type,      /* get_link_type */
        erf_get_direction,      /* get_direction */
        erf_set_direction,      /* set_direction */
        erf_get_erf_timestamp,  /* get_erf_timestamp */
        NULL,                   /* get_timeval */
        NULL,                   /* get_seconds */
        NULL,                   /* get_timespec */
        NULL,                   /* seek_erf */
        NULL,                   /* seek_timeval */
        NULL,                   /* seek_seconds */
	NULL,                   /* get_meta_section */
        erf_get_capture_length, /* get_capture_length */
        erf_get_wire_length,    /* get_wire_length */
        erf_get_framing_length, /* get_framing_length */
        erf_set_capture_length, /* set_capture_length */
        NULL,                   /* get_received_packets */
        NULL,                   /* get_filtered_packets */
        NULL,                   /* get_dropped_packets */
        dpdkndag_get_statistics,    /* get_statistics */
        NULL,                   /* get_fd */
        trace_event_dpdkndag,       /* trace_event */
        NULL,                   /* help */
        NULL,                   /* next pointer */
        {true, 0},              /* live packet capture */
        dpdkndag_pstart_input,      /* parallel start */
        dpdkndag_pread_packets,     /* parallel read */
        dpdkndag_pause_input,       /* parallel pause */
        NULL,
        dpdkndag_pregister_thread,  /* register thread */
        dpdkndag_punregister_thread,
        dpdkndag_get_thread_stats   /* per-thread stats */
};

void dpdkndag_constructor(void) {
        register_format(&dpdkndag);
}
