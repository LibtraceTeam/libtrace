/*
 *
 * Copyright (c) 2007-2020 The University of Waikato, Hamilton, New Zealand.
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

/* Given a single live capture input, e.g. 'ring:' or 'dpdk:', this tool
 * will create multicast groups that will re-transmit the packets received
 * from that input to any interested clients that can join the group. The
 * resulting multicast traffic is produced to match the expected format
 * for an 'ndag:' client, so you can use libtrace to receive the multicast
 * packets and process them as you normally would if you read from the source
 * directly.
 *
 * Effectively, this tool is intended to provide a means of multiplexing
 * a capture source to multiple clients so that you can run multiple libtrace
 * tools against the same live feed simultaneously.
 *
 * Inspired by (and borrowing somewhat from) the DAG multicaster tool that
 * I developed for the STARDUST project. The DAG multicaster is optimised
 * for use with a DAG card only. It is highly recommended if you are using a
 * DAG card for your initial capture *and* your use case is academic and
 * non-commercial.
 *
 * tracemcast is generalised for use with other live capture formats and
 * therefore loses some of the optimizations that come from being DAG-specific.
 * It is also licensed under the LGPL, so can be used for commercial purposes
 * (provided the terms of the LGPL are met).
 */

#include "config.h"

#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include <libtrace_parallel.h>
#include <libtrace.h>
#include "lib/format_erf.h"
#include "lib/format_ndag.h"
#include "lib/lt_bswap.h"

#ifndef HAVE_DAG_API
#include "lib/dagformat.h"
#endif

#include "lib/libtrace_int.h"

struct libtrace_t *currenttrace = NULL;

struct global_params {

    uint16_t monitorid ;
    char *mcastaddr ;
    char *srcaddr ;
    uint64_t starttime;
    uint16_t firstport;
    int readercount;
    uint16_t mtu;
};

struct beacon_params {
    uint16_t beaconport;
    struct global_params *gparams;
    uint32_t frequency;
};

typedef struct read_thread_data {
    int threadid;
    uint16_t mcastport;
    int mcastfd;

    uint8_t *pbuffer;
    ndag_encap_t *encaphdr;
    uint8_t *writeptr;
    uint32_t seqno;
    uint16_t reccount;
    struct addrinfo *target;
    uint32_t lastsend;

} read_thread_data_t;

volatile int halted = 0;

static void cleanup_signal(int signal UNUSED) {
    if (currenttrace) {
        trace_pstop(currenttrace);
    }
    halted = 1;
}

static int create_multicast_socket(uint16_t port, char *groupaddr,
        char *srcaddr, struct addrinfo **targetinfo) {

	struct addrinfo hints;
    struct addrinfo *gotten;
    struct addrinfo *source;
    char portstr[16];
    int sock;
    uint32_t ttlopt = 1;
    int bufsize;

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;

    snprintf(portstr, 15, "%u", port);

    if (getaddrinfo(groupaddr, portstr, &hints, &gotten) != 0) {
        fprintf(stderr, "tracemcast: Call to getaddrinfo failed for %s:%s -- %s\n",
                groupaddr, portstr, strerror(errno));
        return -1;
    }
    *targetinfo = gotten;

    if (getaddrinfo(srcaddr, NULL, &hints, &source) != 0) {
        fprintf(stderr, "tracemcast: Call to getaddrinfo failed for %s:NULL -- %s\n",
                srcaddr, strerror(errno));
        return -1;
    }

    sock = socket(gotten->ai_family, gotten->ai_socktype, 0);
    if (sock < 0) {
        fprintf(stderr,
                "tracemcast: Failed to create multicast socket for %s:%s -- %s\n",
                groupaddr, portstr, strerror(errno));
        goto sockcreateover;
    }

    if (setsockopt(sock,
            gotten->ai_family == PF_INET6 ? IPPROTO_IPV6: IPPROTO_IP,
            gotten->ai_family == PF_INET6 ? IPV6_MULTICAST_HOPS :
                    IP_MULTICAST_TTL,
            (char *)&ttlopt, sizeof(ttlopt)) != 0) {
        fprintf(stderr,
                "tracemcast: Failed to configure multicast TTL of %u for %s:%s -- %s\n",
                ttlopt, groupaddr, portstr, strerror(errno));
        close(sock);
        sock = -1;
        goto sockcreateover;
    }

	if (setsockopt(sock,
            source->ai_family == PF_INET6 ? IPPROTO_IPV6: IPPROTO_IP,
            source->ai_family == PF_INET6 ? IPV6_MULTICAST_IF: IP_MULTICAST_IF,
            source->ai_addr, source->ai_addrlen) != 0) {
        fprintf(stderr,
                "tracemcast: Failed to set outgoing multicast interface %s -- %s\n",
                srcaddr, strerror(errno));
        close(sock);
        sock = -1;
        goto sockcreateover;
    }


	bufsize = 16 * 1024 * 1024;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize,
				(socklen_t)sizeof(int)) != 0) {
		fprintf(stderr,
				"tracemcast: Failed to increase buffer size on multicast interface %s -- %s\n",
				srcaddr, strerror(errno));
		close(sock);
		sock = -1;
		goto sockcreateover;
	}


sockcreateover:
    freeaddrinfo(source);
    return sock;
}

static inline char *fill_common_header(char *bufstart, uint16_t monitorid,
        uint8_t pkttype) {

    ndag_common_t *hdr = (ndag_common_t *)bufstart;

    hdr->magic = htonl(NDAG_MAGIC_NUMBER);
    hdr->version = NDAG_EXPORT_VERSION;
    hdr->type = pkttype;
    hdr->monitorid = htons(monitorid);

    return bufstart + sizeof(ndag_common_t);
}

static void *init_reader_thread(libtrace_t *trace UNUSED,
        libtrace_thread_t *t, void *global) {

    read_thread_data_t *rdata = NULL;
    struct global_params *gparams = (struct global_params *)global;

    rdata = calloc(1, sizeof(read_thread_data_t));
    rdata->threadid = trace_get_perpkt_thread_id(t);
    rdata->mcastport = gparams->firstport + rdata->threadid;
    rdata->mcastfd = -1;
    rdata->pbuffer = calloc(gparams->mtu, sizeof(uint8_t));
    rdata->writeptr = rdata->pbuffer;
    rdata->seqno = 1;
    rdata->target = NULL;
    rdata->lastsend = 0;
    rdata->encaphdr = NULL;
    rdata->reccount = 0;

    rdata->mcastfd = create_multicast_socket(rdata->mcastport,
			gparams->mcastaddr, gparams->srcaddr, &(rdata->target));

    if (rdata->mcastfd == -1) {
        fprintf(stderr, "tracemcast: failed to create multicast socket for reader thread %d\n", rdata->threadid);
    } else if (rdata->target == NULL) {
        fprintf(stderr, "tracemcast: failed to get addrinfo for reader socket %d\n", rdata->threadid);
        close(rdata->mcastfd);
        rdata->mcastfd = -1;
    }

    return rdata;
}

static void send_ndag_packet(read_thread_data_t *rdata) {

    rdata->encaphdr->recordcount = ntohs(rdata->reccount);

    if (sendto(rdata->mcastfd, rdata->pbuffer,
            (rdata->writeptr - rdata->pbuffer), 0, rdata->target->ai_addr,
            rdata->target->ai_addrlen) < 0) {
        fprintf(stderr, "tracemcast: thread %d failed to send multicast ERF packet: %s\n",
                rdata->threadid, strerror(errno));
    }

    rdata->writeptr = rdata->pbuffer;
    rdata->encaphdr = NULL;
    rdata->reccount = 0;

}

static void halt_reader_thread(libtrace_t *trace UNUSED,
        libtrace_thread_t *t UNUSED, void *global UNUSED, void *tls) {

    read_thread_data_t *rdata = (read_thread_data_t *)tls;

    if (rdata->writeptr > rdata->pbuffer) {
        send_ndag_packet(rdata);
    }

    if (rdata->pbuffer) {
        free(rdata->pbuffer);
    }
    if (rdata->target) {
        freeaddrinfo(rdata->target);
    }
    if (rdata->mcastfd != -1) {
        close(rdata->mcastfd);
    }
    free(rdata);
}

static uint16_t construct_erf_header(read_thread_data_t *rdata,
        libtrace_packet_t *packet, libtrace_linktype_t ltype, uint32_t rem,
        uint64_t erfts) {

    uint16_t framing = 0;
    dag_record_t *drec = (dag_record_t *)(rdata->writeptr);

    drec->ts = bswap_host_to_le64(erfts);

    if (ltype == TRACE_TYPE_ETH) {
        drec->type = TYPE_ETH;
    } else if (ltype == TRACE_TYPE_NONE) {
        drec->type = TYPE_IPV4;         // sorry if you're using IPv6 raw */
    } else {
        drec->type = 255;
    }

    if (drec->type == TYPE_ETH) {
        framing = dag_record_size + 2;
    } else {
        framing = dag_record_size;
    }
    drec->rlen = htons(rem + framing);
    drec->wlen = htons(trace_get_wire_length(packet));
    drec->lctr = htons(0);
    memset(&(drec->flags), 0, sizeof(drec->flags));

    if (trace_get_direction(packet) != TRACE_DIR_UNKNOWN) {
        drec->flags.iface = trace_get_direction(packet);
    } else {
        drec->flags.iface = 0;
    }

    return framing;
}

static void tick_reader_thread(libtrace_t *trace UNUSED,
        libtrace_thread_t *t UNUSED, void *global UNUSED, void *tls,
        uint64_t order) {

    read_thread_data_t *rdata = (read_thread_data_t *)tls;

    if (rdata->writeptr > rdata->pbuffer &&
            (order >> 32) >= rdata->lastsend + 3) {

        send_ndag_packet(rdata);
        rdata->lastsend = (order >> 32);
    }
}

static libtrace_packet_t *packet_reader_thread(libtrace_t *trace UNUSED,
        libtrace_thread_t *t UNUSED, void *global, void *tls,
        libtrace_packet_t *packet) {

    read_thread_data_t *rdata = (read_thread_data_t *)tls;
    struct global_params *gparams = (struct global_params *)global;
    libtrace_linktype_t ltype;
    uint32_t rem;
    void *l2;
    uint64_t erfts;

    if (IS_LIBTRACE_META_PACKET(packet)) {
        return packet;
    }

    /* first, check if there is going to be space in the buffer for this
     * packet + an ERF header */
    l2 = trace_get_layer2(packet, &ltype, &rem);
    erfts = trace_get_erf_timestamp(packet);

    if (gparams->mtu - (rdata->writeptr - rdata->pbuffer) <
            rem + dag_record_size) {

        /* if not and if there is already something in the buffer, send it then
         * create a new one.
         */
        if (rdata->writeptr > rdata->pbuffer + sizeof(ndag_common_t) +
                sizeof(ndag_encap_t)) {

            send_ndag_packet(rdata);
            rdata->lastsend = (erfts >> 32);
        }
    }

    /* append this packet to the buffer (truncate if necessary) */

    /* if the buffer is empty, put on a common and encap header on the
     * front, before adding any packets */
    if (rdata->writeptr == rdata->pbuffer) {
        rdata->encaphdr = (ndag_encap_t *)(fill_common_header(
                (char *)rdata->writeptr,
                gparams->monitorid, NDAG_PKT_ENCAPERF));
        rdata->writeptr = ((uint8_t *)rdata->encaphdr) + sizeof(ndag_encap_t);

        rdata->encaphdr->started = gparams->starttime;
        rdata->encaphdr->seqno = htonl(rdata->seqno);
        rdata->encaphdr->streamid = htons(rdata->threadid);
        rdata->encaphdr->recordcount = 0;

        rdata->reccount = 0;
    }

    if (rem > gparams->mtu - (rdata->writeptr - rdata->pbuffer)
            - (dag_record_size + 2)) {
        rem = gparams->mtu - (rdata->writeptr - rdata->pbuffer);
        rem -= (dag_record_size + 2);
    }

    /* put an ERF header in at writeptr */
    rdata->writeptr += construct_erf_header(rdata, packet, ltype, rem, erfts);

    /* copy packet contents into writeptr */
    memcpy(rdata->writeptr, l2, rem);
    rdata->writeptr += rem;
    rdata->reccount ++;

    /* if the buffer is close to full, just send the buffer anyway */
    if (gparams->mtu - (rdata->writeptr - rdata->pbuffer) -
            (dag_record_size + 2) < 64) {
        send_ndag_packet(rdata);
        rdata->lastsend = (erfts >> 32);
    }

    return packet;
}

static void start_libtrace_reader(struct global_params *gparams, char *uri,
        char *filterstring) {


    libtrace_filter_t *filt = NULL;
    libtrace_callback_set_t *pktcbs = NULL;

    currenttrace = trace_create(uri);
    if (trace_is_err(currenttrace)) {
        trace_perror(currenttrace, "trace_create");
        goto failmode;
    }

    trace_set_perpkt_threads(currenttrace, gparams->readercount);

    pktcbs = trace_create_callback_set();
    trace_set_starting_cb(pktcbs, init_reader_thread);
    trace_set_stopping_cb(pktcbs, halt_reader_thread);
    trace_set_packet_cb(pktcbs, packet_reader_thread);
    trace_set_tick_interval_cb(pktcbs, tick_reader_thread);

    if (trace_get_information(currenttrace)->live) {
        trace_set_tick_interval(currenttrace, 1000);
    } else {
        trace_set_tracetime(currenttrace, true);
    }

    if (filterstring) {
        filt = trace_create_filter(filterstring);

        if (trace_config(currenttrace, TRACE_OPTION_FILTER, filt) < 0) {
            trace_perror(currenttrace, "Failed to configure filter");
            goto failmode;
        }
    }


    if (trace_pstart(currenttrace, gparams, pktcbs, NULL) == -1) {
        trace_perror(currenttrace, "Failed to start trace");
        goto failmode;
    }

    trace_join(currenttrace);

    if (trace_is_err(currenttrace)) {
        trace_perror(currenttrace, "Reading packets");
    }

failmode:
    if (filt) {
        trace_destroy_filter(filt);
    }
    if (currenttrace) {
        trace_destroy(currenttrace);
    }
    if (pktcbs) {
        trace_destroy_callback_set(pktcbs);
    }

}


static uint32_t form_beacon(char **buffer, struct beacon_params *bparams) {

    uint32_t bsize = sizeof(ndag_common_t) + (sizeof(uint16_t) *
            (bparams->gparams->readercount + 1));
    char *bptr;
    uint16_t *next;
    int i;

    if (bsize > bparams->gparams->mtu) {
        fprintf(stderr, "tracemcast: beacon is too large to fit in a single datagram, either increase MTU or reduce number of threads\n");
        return 0;
    }

    bptr = (char *)malloc(bsize);
    next = (uint16_t *)(fill_common_header(bptr, bparams->gparams->monitorid,
            NDAG_PKT_BEACON));

    *next = htons(bparams->gparams->readercount);
    next ++;

    for (i = 0; i < bparams->gparams->readercount; i++) {
        *next = htons(bparams->gparams->firstport + (i));
        next ++;
    }

    *buffer = bptr;
    return bsize;
}

static void *beaconer_thread(void *tdata) {

    struct beacon_params *bparams = (struct beacon_params *)tdata;
    int sock;
    char *beaconpacket = NULL;
    uint32_t beaconsize;
	struct addrinfo *targetinfo = NULL;

	sock = create_multicast_socket(bparams->beaconport,
			bparams->gparams->mcastaddr, bparams->gparams->srcaddr,
			&targetinfo);

    if (sock == -1) {
        fprintf(stderr, "tracemcast: failed to create multicast socket for beaconer thread\n");
        halted = 1;
    } else if (targetinfo == NULL) {
        fprintf(stderr, "tracemcast: failed to get addrinfo for beaconer socket\n");
        halted = 1;
    }

    beaconsize = form_beacon(&beaconpacket, bparams);

    if (beaconsize <= 0 || beaconpacket == NULL) {
        halted = 1;
    }

    while (!halted) {
        if (sendto(sock, beaconpacket, beaconsize, 0, targetinfo->ai_addr,
                targetinfo->ai_addrlen) != beaconsize) {
            fprintf(stderr, "tracemcast: failed to send a beacon packet: %s\n",
                    strerror(errno));
            break;
        }
        usleep(1000 * bparams->frequency);
    }

    if (beaconpacket) {
        free(beaconpacket);
    }
    if (targetinfo) {
        free(targetinfo);
    }
    if (sock >= 0) {
        close(sock);
    }

    pthread_exit(NULL);

}

static void usage(char *prog) {
    fprintf(stderr, "Usage:\n"
            "%s [ options ] libtraceURI\n\n", prog);
    fprintf(stderr, "Options:\n"
            "   -f --filter=bpffilter   Only emit packets that match this BPF filter\n"
            "   -m --monitorid=idnum     Tag all multicast packets with the given identifier\n"
            "   -g --mcastaddr=address  Use this multicast address for emitting packets\n"
            "   -p --beaconport=port    Send multicast beacons on this port number\n"
            "   -s --srcaddr=address    Send multicast on the interface for this IP address\n"
            "   -M --mtu=bytes          Limit multicast message size to this number of bytes\n"
            "   -t --threads=count      Use this number of packet processing threads\n"
            "   -h --help               Show this usage statement\n");
}


int main(int argc, char *argv[]) {
    struct sigaction sigact;
    char *filterstring = NULL;
    uint16_t beaconport = 9999;
    struct global_params gparams;
    struct beacon_params bparams;
    int threads = 1;
    struct timeval tv;
    uint16_t mtu = NDAG_MAX_DGRAM_SIZE;
    pthread_t beacontid = 0;
    sigset_t sig_before, sig_block_all;

    gparams.monitorid = 0;
    gparams.mcastaddr = NULL;
    gparams.srcaddr = NULL;

    while (1) {
        int optindex;
        struct option long_options[] = {
            { "filter",     1, 0, 'f' },
            { "monitorid",  1, 0, 'm' },
            { "mcastaddr",  1, 0, 'g' },
            { "beaconport", 1, 0, 'p' },
            { "srcaddr",    1, 0, 's' },
            { "threads",    1, 0, 't' },
            { "mtu",        1, 0, 'M' },
            { "help",       0, 0, 'h' },
            { NULL,         0, 0, 0 },
        };

        int c = getopt_long(argc, argv, "M:t:f:m:g:p:s:h", long_options,
                &optindex);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'f':
                filterstring = optarg;
                break;
            case 'M':
                mtu = (uint16_t)strtoul(optarg, NULL, 0);
                break;
            case 'm':
                gparams.monitorid = (uint16_t)strtoul(optarg, NULL, 0);
                break;
            case 'g':
                gparams.mcastaddr = optarg;
                break;
            case 's':
                gparams.srcaddr = optarg;
                break;
            case 'p':
                beaconport = (uint16_t)strtoul(optarg, NULL, 0);
                break;
            case 't':
                threads = (int)strtoul(optarg, NULL, 0);
                break;
            case 'h':
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        fprintf(stderr,
                "tracemcast: No URI specified as an input source. Exiting\n");
        return 1;
    }

    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    if (gparams.mcastaddr == NULL) {
        gparams.mcastaddr = "225.100.0.1";
    }
    if (gparams.srcaddr == NULL) {
        gparams.srcaddr = "0.0.0.0";
    }
    if (mtu >= NDAG_MAX_DGRAM_SIZE) {
        mtu = NDAG_MAX_DGRAM_SIZE;
    } else if (mtu < 536) {
        mtu = 536;
    }


    gettimeofday(&tv, NULL);
    gparams.starttime = bswap_host_to_le64(((tv.tv_sec - 1509494400) * 1000) +
            (tv.tv_usec / 1000.0));
    gparams.readercount = threads;
    gparams.mtu = mtu;

    gparams.firstport = 10000 + (rand() % 52000);

    fprintf(stderr, "Multicasting %s on %s:%u from %s\n",
            argv[optind], gparams.mcastaddr, beaconport, gparams.srcaddr);
    fprintf(stderr, "Monitor ID is set to %u\n", gparams.monitorid);

    /* Start up the beaconing */
    bparams.beaconport = beaconport;
    bparams.gparams = &(gparams);
    bparams.frequency = 1000;

    sigemptyset(&sig_block_all);
    if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
        fprintf(stderr, "Unable to disable signals before starting beaconer.\n");
        goto endmcast;
    }

    if (pthread_create(&beacontid, NULL, beaconer_thread, &bparams) != 0) {
        fprintf(stderr, "Error while creating beaconer thread: %s",
                strerror(errno));
        goto endmcast;
    }

    if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL)) {
        fprintf(stderr, "Unable to re-enable signals after beaconer creation.\n");
        goto endmcast;
    }

    start_libtrace_reader(&gparams, argv[optind], filterstring);

endmcast:
    halted = 1;

    if (beacontid != 0) {
        pthread_join(beacontid, NULL);
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
