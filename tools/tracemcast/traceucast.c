/*
 *
 * Copyright (c) 2023 Shane Alcock.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * Libtrace was originally developed by the University of Waikato WAND
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

/* Author: Shane Alcock, SearchLight  <salcock@searchlight.nz> */

/* Given a single live capture input, e.g. 'ring:' or 'dpdk:', this tool
 * will re-transmit the packets received across a network to a listening
 * host. The resulting traffic stream matches the expected format
 * for an 'ndagtcp:' client, so you can use libtrace to receive the
 * packets and process them as if you had captured from the source
 * directly.
 *
 * Effectively, this tool is intended to provide a means of pushing packets
 * from a capture source to a secondary client so that you can run libtrace
 * tools and programs on a remote host. Unlike tracemcast, traceucast uses
 * TCP to ensure the packets reach their destination but, as a result, can
 * only support a single recipient.
 *
 * Inspired by (and borrowing somewhat from) the DAG multicaster tool that
 * I developed for the STARDUST project. The DAG multicaster is optimised
 * for use with a DAG card only. It is highly recommended if you are using a
 * DAG card for your initial capture *and* your use case is academic and
 * non-commercial.
 *
 * traceucast is generalised for use with other live capture formats and
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
    char *clientaddr ;
    uint64_t starttime;
    uint16_t firstport;
    int readercount;
};

struct beacon_params {
    uint16_t beaconport;
    struct global_params *gparams;
    uint32_t frequency;
};

typedef struct read_thread_data {
    int threadid;
    uint16_t streamport;
    int streamfd;

    uint8_t *pbuffer;
    uint32_t bufsize;
    ndag_encap_t *encaphdr;
    uint8_t *writeptr;
    uint32_t seqno;
    uint16_t reccount;
    struct addrinfo *target;
    uint32_t lastsend;

    bool livesource;
    uint8_t failed;

} read_thread_data_t;

#define MAX_PACKET_SIZE 10000

volatile int halted = 0;

static void cleanup_signal(int signal UNUSED) {
    if (currenttrace) {
        trace_interrupt();
    }
    halted = 1;
}

static int create_stream_socket(uint16_t port, char *clientaddr,
        struct addrinfo **targetinfo, uint8_t block) {

	struct addrinfo hints;
    struct addrinfo *gotten;
    char portstr[16];
    int sock;
    int bufsize, reuse=1, connected = 0;

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;

    snprintf(portstr, 15, "%u", port);

    if (getaddrinfo(clientaddr, portstr, &hints, &gotten) != 0) {
        fprintf(stderr,
                "traceucast: Call to getaddrinfo failed for %s:%s -- %s\n",
                clientaddr, portstr, strerror(errno));
        return -1;
    }
    if (targetinfo) {
        if (*targetinfo) {
            free(*targetinfo);
        }
        *targetinfo = gotten;
    }

    sock = socket(gotten->ai_family, gotten->ai_socktype, 0);
    if (sock < 0) {
        fprintf(stderr,
                "traceucast: Failed to create TCP socket for %s:%s -- %s\n",
                clientaddr, portstr, strerror(errno));
        goto sockcreateover;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))
            < 0) {

        fprintf(stderr, "traceucast: Failed to configure socket for %s:%s -- %s\n",
                clientaddr, portstr, strerror(errno));

		close(sock);
		sock = -1;
        goto sockcreateover;
    }

	bufsize = 32 * 1024 * 1024;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize,
				(socklen_t)sizeof(int)) != 0) {
		fprintf(stderr,
				"traceucast: Failed to increase buffer size on streaming interface %s:%s -- %s\n",
				clientaddr, portstr, strerror(errno));
		close(sock);
		sock = -1;
		goto sockcreateover;
	}


    while (!halted) {
        if (connect(sock, gotten->ai_addr, gotten->ai_addrlen) == -1) {
            if (errno == ECONNREFUSED) {
                if (block) {
                    sleep(1);
                    continue;
                } else {
                    close(sock);
                    sock = 0;
                    break;
                }
            }
            fprintf(stderr,
                    "traceucast: Failed to connect to %s:%s -- %s\n",
                    clientaddr, portstr, strerror(errno));
            close(sock);
            sock = -1;
            break;
        } else {
            fprintf(stderr, "traceucast connected to %s:%s\n", clientaddr,
                    portstr);
            connected = 1;
            break;
        }
    }
    if (!connected && sock > 0) {
        close(sock);
        sock = -1;
    }

sockcreateover:
    if (targetinfo == NULL) {
        freeaddrinfo(gotten);
    }
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

static void *init_reader_thread(libtrace_t *trace,
        libtrace_thread_t *t, void *global) {

    read_thread_data_t *rdata = NULL;
    struct global_params *gparams = (struct global_params *)global;
    libtrace_info_t *info = trace_get_information(trace);

    rdata = calloc(1, sizeof(read_thread_data_t));
    if (info) {
        rdata->livesource = info->live;
    } else {
        rdata->livesource = false;
    }
    rdata->threadid = trace_get_perpkt_thread_id(t);
    rdata->streamport = gparams->firstport + rdata->threadid;
    rdata->streamfd = -1;
    rdata->pbuffer = calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
    rdata->bufsize = MAX_PACKET_SIZE;
    rdata->writeptr = rdata->pbuffer;
    rdata->seqno = 1;
    rdata->target = NULL;
    rdata->lastsend = 0;
    rdata->encaphdr = NULL;
    rdata->reccount = 0;
    rdata->failed = 0;

    rdata->streamfd = -1;

    return rdata;
}

static int connect_stream_fd(read_thread_data_t *rdata,
                             struct global_params *gparams)
{

        int fd;
        uint8_t block;

        if (rdata->livesource) {
                block = 0;
        } else {
                block = 1;
        }
        fd = create_stream_socket(rdata->streamport, gparams->clientaddr,
                                  &(rdata->target), block);

        if (fd == 0) {
                return 0;
        }

        if (fd == -1) {
                if (errno != ECONNREFUSED) {
                        fprintf(stderr,
                                "traceucast: failed to create TCP socket for "
                                "reader thread %d: %s\n",
                                rdata->threadid, strerror(errno));
                        return -1;
                } else {
                        return 0;
                }
        } else if (rdata->target == NULL) {
                fprintf(
                    stderr,
                    "traceucast: failed to get addrinfo for reader socket %d\n",
                    rdata->threadid);
                close(rdata->streamfd);
                rdata->streamfd = -1;
                return -1;
        }
        rdata->streamfd = fd;
        return fd;
}

#define HANDLE_SEND_ERROR                                                      \
        if (s < 0) {                                                           \
                if ((errno == EAGAIN || errno == EWOULDBLOCK) &&               \
                    attempts < 20) {                                           \
                        attempts++;                                            \
                        usleep(backoff);                                       \
                        backoff = backoff * 2;                                 \
                        if (backoff > 1000000) {                               \
                                backoff = 1000000;                             \
                        }                                                      \
                        continue;                                              \
                }                                                              \
                fprintf(stderr,                                                \
                        "traceucast: thread %d failed to send streamed ERF "   \
                        "packet: %s\n",                                        \
                        rdata->threadid, strerror(errno));                     \
                close(rdata->streamfd);                                        \
                rdata->streamfd = -1;                                          \
                usleep(200000);                                                \
                continue;                                                      \
        }

static int send_ndag_packet(read_thread_data_t *rdata,
                            struct global_params *gparams)
{

        int s, r;
        int rem = (rdata->writeptr - rdata->pbuffer);
        int sentsofar = 0;
        int attempts = 0;
        int backoff = 5000;

        int firstsend = 0;
        int fs_amount = 0;

        rdata->encaphdr->recordcount = ntohs(rdata->reccount);

        while (rem > 0 && !halted) {
                if (rdata->streamfd == -1) {
                        if ((r = connect_stream_fd(rdata, gparams)) < 0) {
                                rdata->failed = 1;
                                trace_interrupt();
                                return -1;
                        }
                        if (r == 0) {
                                if (rdata->livesource) {
                                        return 0;
                                }
                                sleep(1);
                                continue;
                        }
                        fprintf(stderr,
                                "traceucast: streaming thread %d established "
                                "connection\n",
                                rdata->threadid);
                }

                if (firstsend == 0 && rem > 8) {
                        /* try to detect a broken pipe by attempting a "canary"
                         * send of 8 bytes so that the main send is more likely
                         * to trigger EPIPE
                         */
                        s = send(rdata->streamfd, rdata->pbuffer, 8,
                                 MSG_DONTWAIT | MSG_NOSIGNAL);
                        HANDLE_SEND_ERROR
                        fs_amount = s;

                        s = send(rdata->streamfd, rdata->pbuffer + fs_amount,
                                 rem - fs_amount, MSG_DONTWAIT | MSG_NOSIGNAL);
                        HANDLE_SEND_ERROR
                        sentsofar += (s + fs_amount);
                        rem -= (s + fs_amount);
                        firstsend = 1;
                } else {
                        s = send(rdata->streamfd, rdata->pbuffer + sentsofar,
                                 rem, MSG_DONTWAIT | MSG_NOSIGNAL);
                        HANDLE_SEND_ERROR
                        sentsofar += s;
                        rem -= s;
                }
        }

        rdata->writeptr = rdata->pbuffer;
        rdata->encaphdr = NULL;
        rdata->reccount = 0;
        return sentsofar;
}

static void halt_reader_thread(libtrace_t *trace UNUSED,
                               libtrace_thread_t *t UNUSED, void *global,
                               void *tls)
{

        read_thread_data_t *rdata = (read_thread_data_t *)tls;
        struct global_params *gparams = (struct global_params *)global;

        if (rdata->writeptr > rdata->pbuffer) {
                send_ndag_packet(rdata, gparams);
        }

        if (rdata->pbuffer) {
                free(rdata->pbuffer);
        }
        if (rdata->target) {
                freeaddrinfo(rdata->target);
        }
        if (rdata->streamfd != -1) {
                close(rdata->streamfd);
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
                               libtrace_thread_t *t UNUSED, void *global,
                               void *tls, uint64_t order)
{

        read_thread_data_t *rdata = (read_thread_data_t *)tls;
        struct global_params *gparams = (struct global_params *)global;

        if (rdata->writeptr > rdata->pbuffer &&
            (order >> 32) >= rdata->lastsend + 3) {

                if (send_ndag_packet(rdata, gparams) < 0) {
                        rdata->failed = 1;
                }
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
    int r;

    if (rdata->failed) {
        trace_interrupt();
        return packet;
    }

    if (IS_LIBTRACE_META_PACKET(packet)) {
        return packet;
    }

    /* first, check if there is going to be space in the buffer for this
     * packet + an ERF header */
    l2 = trace_get_layer2(packet, &ltype, &rem);
    erfts = trace_get_erf_timestamp(packet);

    if (MAX_PACKET_SIZE - (rdata->writeptr - rdata->pbuffer) <
            rem + dag_record_size) {

        /* if not and if there is already something in the buffer, send it then
         * create a new one.
         */
        if (rdata->writeptr > rdata->pbuffer + sizeof(ndag_common_t) +
                sizeof(ndag_encap_t)) {
                if ((r = send_ndag_packet(rdata, gparams)) < 0) {
                        rdata->failed = 1;
                        close(rdata->streamfd);
                        rdata->streamfd = -1;
                        return packet;
                } else if (r == 0) {
                        return packet;
                }
            rdata->lastsend = (erfts >> 32);
        }
    }

    /* extend the buffer size if we happen to be working with very large
     * packets
     */
    while (rem + dag_record_size + sizeof(ndag_encap_t) + sizeof(ndag_common_t)
            > rdata->bufsize) {
        int writeoff = rdata->writeptr - rdata->pbuffer;
        int encapoff = ((uint8_t *)rdata->encaphdr) - rdata->pbuffer;

        rdata->pbuffer = realloc(rdata->pbuffer,
                rdata->bufsize + MAX_PACKET_SIZE);
        rdata->bufsize += MAX_PACKET_SIZE;
        rdata->writeptr = rdata->pbuffer + writeoff;
        rdata->encaphdr = (ndag_encap_t *)(rdata->pbuffer + encapoff);
    }

    /* append this packet to the buffer */

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
        rdata->seqno ++;
    }

    /* put an ERF header in at writeptr */
    rdata->writeptr += construct_erf_header(rdata, packet, ltype, rem, erfts);

    /* copy packet contents into writeptr */
    memcpy(rdata->writeptr, l2, rem);
    rdata->writeptr += rem;
    rdata->reccount ++;

    /* if the buffer is close to full, just send the buffer anyway */
    if (MAX_PACKET_SIZE - (rdata->writeptr - rdata->pbuffer) -
            (dag_record_size + 2) < 64) {
            if ((r = send_ndag_packet(rdata, gparams)) < 0) {
                    rdata->failed = 1;
            } else if (r != 0) {
                    rdata->lastsend = (erfts >> 32);
            }
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

    if (bsize > MAX_PACKET_SIZE) {
        fprintf(stderr, "traceucast: beacon is too large to fit in a single datagram, either increase MTU or reduce number of threads\n");
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
    int sock = -1;
    char *beaconpacket = NULL;
    uint32_t beaconsize;
	struct addrinfo *targetinfo = NULL;

    beaconsize = form_beacon(&beaconpacket, bparams);

    if (beaconsize <= 0 || beaconpacket == NULL) {
        halted = 1;
    }

    while (!halted) {
            if (sock == -1) {
                    sock = create_stream_socket(bparams->beaconport,
                                                bparams->gparams->clientaddr,
                                                &targetinfo, 1);
            }

            if (sock == 0) {
                    sleep(1);
                    continue;
            }

            if (sock == -1) {
                    if (errno != ECONNREFUSED) {
                            fprintf(stderr, "traceucast: failed to create TCP "
                                            "socket for beacon thread: %s\n",
                                            strerror(errno));
                            halted = 1;
                            break;
                    } else {
                            sleep(1);
                            continue;
                    }
            } else if (targetinfo == NULL) {
                    fprintf(stderr, "traceucast: failed to get addrinfo for "
                                    "beaconer socket\n");
                    halted = 1;
                    break;
            }

            if (send(sock, beaconpacket, beaconsize, MSG_NOSIGNAL) !=
                beaconsize) {
                    fprintf(stderr,
                            "traceucast: failed to send a beacon packet: %s\n",
                            strerror(errno));
                    close(sock);
                    sock = -1;
                    usleep(200000);
                    continue;
            }
        usleep(1000 * bparams->frequency);
    }

    if (beaconpacket) {
        free(beaconpacket);
    }
    if (targetinfo) {
        free(targetinfo);
    }
    if (sock > 0) {
            close(sock);
    }

    pthread_exit(NULL);

}

static void usage(char *prog) {
    fprintf(stderr, "Usage:\n"
            "%s [ options ] libtraceURI\n\n", prog);
    fprintf(stderr, "Options:\n"
            "   -f --filter=bpffilter   Only emit packets that match this BPF filter\n"
            "   -m --monitorid=idnum     Tag all streamed packets with the given identifier\n"
            "   -c --clientaddr=address  Connect to a ndagtcp receiver at this address/hostname\n"
            "   -p --beaconport=port    Send beacons to the receiver on this port number\n"
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
    pthread_t beacontid = 0;
    sigset_t sig_before, sig_block_all;

    gparams.monitorid = 0;
    gparams.clientaddr = NULL;

    while (1) {
        int optindex;
        struct option long_options[] = {
            { "filter",     1, 0, 'f' },
            { "monitorid",  1, 0, 'm' },
            { "clientaddr",  1, 0, 'c' },
            { "beaconport", 1, 0, 'p' },
            { "threads",    1, 0, 't' },
            { "help",       0, 0, 'h' },
            { NULL,         0, 0, 0 },
        };

        int c = getopt_long(argc, argv, "t:f:m:c:p:h", long_options,
                &optindex);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'f':
                filterstring = optarg;
                break;
            case 'm':
                gparams.monitorid = (uint16_t)strtoul(optarg, NULL, 0);
                break;
            case 'c':
                gparams.clientaddr = optarg;
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
                "traceucast: No URI specified as an input source. Exiting\n");
        return 1;
    }

    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    if (gparams.clientaddr == NULL) {
        fprintf(stderr,
                "traceucast: no client address specified to receive our streams. Exiting\n");
        return 1;
    }

    gettimeofday(&tv, NULL);
    gparams.starttime = bswap_host_to_le64(((tv.tv_sec - 1509494400) * 1000) +
            (tv.tv_usec / 1000.0));
    gparams.readercount = threads;

    gparams.firstport = 10000 + (rand() % 52000);

    fprintf(stderr, "Streaming %s to %s:%u \n",
            argv[optind], gparams.clientaddr, beaconport);
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
