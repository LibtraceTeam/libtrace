/*
 *
 * Copyright (c) 2007-2017 The University of Waikato, Hamilton, New Zealand.
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

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif

#include "config.h"
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "format_erf.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "format_ndag.h"

#define NDAG_IDLE_TIMEOUT (600)
#define ENCAP_BUFSIZE (65536)
#define CTRL_BUF_SIZE (10000)
#define ENCAP_BUFFERS (1000)

#define RECV_BATCH_SIZE (50)

#define FORMAT_DATA ((ndag_format_data_t *)libtrace->format_data)

static struct libtrace_format_t ndag;

volatile int ndag_paused = 0;

enum {
    NDAG_SOCKET_TYPE_MULTICAST,
    NDAG_SOCKET_TYPE_TCP,
};

typedef struct monitor {
    uint16_t monitorid;
    uint64_t laststart;
} ndag_monitor_t;

typedef struct streamsource {
    uint16_t monitor;
    char *groupaddr;
    char *localiface;
    uint16_t port;
} streamsource_t;

typedef struct streamsock {
    uint8_t socktype;
    char *groupaddr;
    int sock;
    struct addrinfo *srcaddr;
    uint16_t port;
    uint32_t expectedseq;
    ndag_monitor_t *monitorptr;
    char **saved;
    char *nextread;
    int nextreadind;
    int nextwriteind;
    uint16_t nextrlen;
    int savedsize[ENCAP_BUFFERS];
    int expectedreccount;
    uint8_t rectype;
    uint64_t nextts;
    uint32_t startidle;
    uint64_t total_recordcount;

    int reccount;
    int bufavail;
    int bufwaiting;

#if HAVE_DECL_RECVMMSG
    struct mmsghdr mmsgbufs[RECV_BATCH_SIZE];
#endif
    struct msghdr singlemsg;

} streamsock_t;

typedef struct recvstream {
    streamsock_t *sources;
    uint16_t sourcecount;
    libtrace_message_queue_t mqueue;
    int threadindex;
    ndag_monitor_t *knownmonitors;
    uint16_t monitorcount;

    uint64_t dropped_upstream;
    uint64_t missing_records;
    uint64_t received_packets;

    int maxfd;
    uint8_t halted;
} recvstream_t;

typedef struct ndag_format_data {
    char *multicastgroup;
    char *portstr;
    char *localiface;
    uint16_t nextthreadid;
    recvstream_t *receivers;
    int receiver_cnt;
    uint8_t socktype;

    pthread_t controlthread;
    libtrace_message_queue_t controlqueue;
    int consterfframing;
} ndag_format_data_t;

enum {
    NDAG_CLIENT_HALT = 0x01,
    NDAG_CLIENT_RESTARTED = 0x02, // redundant
    NDAG_CLIENT_NEWGROUP = 0x03
};

typedef struct ndagreadermessage {
    uint8_t type;
    streamsource_t contents;
} ndag_internal_message_t;

#define NEXT_BUFFER(ssock, nr)                                                 \
    ssock->savedsize[nr] = 0;                                                  \
    ssock->bufwaiting++;                                                       \
    nr++;                                                                      \
    if (nr == ENCAP_BUFFERS) {                                                 \
        nr = 0;                                                                \
    }                                                                          \
    ssock->nextread = ssock->saved[nr];                                        \
    ssock->nextreadind = nr;

static inline int seq_cmp(uint32_t seq_a, uint32_t seq_b)
{

    /* Calculate seq_a - seq_b, taking wraparound into account */
    if (seq_a == seq_b)
        return 0;

    if (seq_a > seq_b) {
        return (int)(seq_a - seq_b);
    }

    /* -1 for the wrap and another -1 because we don't use zero */
    return (int)(0xffffffff - ((seq_b - seq_a) - 2));
}

static uint8_t check_ndag_header(char *msgbuf, uint32_t msgsize)
{
    ndag_common_t *header = (ndag_common_t *)msgbuf;

    if (msgsize < sizeof(ndag_common_t)) {
        fprintf(stderr, "nDAG message does not have a complete nDAG header.\n");
        return 0;
    }

    if (ntohl(header->magic) != NDAG_MAGIC_NUMBER) {
        fprintf(stderr, "nDAG message does not have a valid magic number.\n");
        return 0;
    }

    if (header->version > NDAG_EXPORT_VERSION || header->version == 0) {
        fprintf(stderr, "nDAG message has an invalid header version: %u\n",
                header->version);
        return 0;
    }

    return header->type;
}

static inline void reset_expected_seqs(recvstream_t *rt, ndag_monitor_t *mon)
{

    int i;
    for (i = 0; i < rt->sourcecount; i++) {
        if (rt->sources[i].monitorptr == mon) {
            rt->sources[i].expectedseq = 0;
        }
    }
}

static int join_multicast_group(char *groupaddr, char *localiface,
                                char *portstr, uint16_t portnum,
                                struct addrinfo **srcinfo)
{

    struct addrinfo hints;
    struct addrinfo *gotten;
    struct addrinfo *group;
    unsigned int interface;
    char pstr[16];
    struct group_req greq;
    int bufsize, val;
    uint32_t ttlopt = 4; // TODO, add config option for this?

    int sock;

    if (portstr == NULL) {
        snprintf(pstr, 15, "%u", portnum);
        portstr = pstr;
    }

    interface = if_nametoindex(localiface);
    if (interface == 0) {
        fprintf(stderr, "Failed to lookup interface %s -- %s\n", localiface,
                strerror(errno));
        return -1;
    }

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;

    if (getaddrinfo(groupaddr, portstr, &hints, &gotten) != 0) {
        fprintf(stderr, "Call to getaddrinfo failed for %s:%s -- %s\n",
                groupaddr, portstr, strerror(errno));
        return -1;
    }

    if (getaddrinfo(groupaddr, NULL, &hints, &group) != 0) {
        fprintf(stderr, "Call to getaddrinfo failed for %s -- %s\n", groupaddr,
                strerror(errno));
        return -1;
    }

    if (srcinfo) {
        *srcinfo = gotten;
    }

    sock = socket(gotten->ai_family, gotten->ai_socktype, 0);
    if (sock < 0) {
        fprintf(stderr, "Failed to create multicast socket for %s:%s -- %s\n",
                groupaddr, portstr, strerror(errno));
        goto sockcreateover;
    }

    if (setsockopt(sock,
                   gotten->ai_family == PF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP,
                   gotten->ai_family == PF_INET6 ? IPV6_MULTICAST_HOPS
                                                 : IP_MULTICAST_TTL,
                   (char *)&ttlopt, sizeof(ttlopt)) != 0) {
        fprintf(stderr, "Failed to set TTL socket option for %s:%s -- %s\n",
                groupaddr, portstr, strerror(errno));
        goto sockcreateover;
    }

    val = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
        fprintf(stderr,
                "Failed to set REUSEADDR socket option for %s:%s -- %s\n",
                groupaddr, portstr, strerror(errno));
        goto sockcreateover;
    }

    if (bind(sock, (struct sockaddr *)gotten->ai_addr, gotten->ai_addrlen) <
        0) {
        fprintf(stderr, "Failed to bind to multicast socket %s:%s -- %s\n",
                groupaddr, portstr, strerror(errno));
        sock = -1;
        goto sockcreateover;
    }

    memset(&greq, 0, sizeof(greq));
    greq.gr_interface = interface;
    memcpy(&(greq.gr_group), group->ai_addr, group->ai_addrlen);

    if (setsockopt(sock, IPPROTO_IP, MCAST_JOIN_GROUP, &greq, sizeof(greq)) <
        0) {
        fprintf(stderr, "Failed to join multicast group %s:%s -- %s\n",
                groupaddr, portstr, strerror(errno));
        close(sock);
        sock = -1;
        goto sockcreateover;
    }

    bufsize = 16 * 1024 * 1024;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize,
                   (socklen_t)sizeof(int)) < 0) {

        fprintf(
            stderr,
            "Failed to increase buffer size for multicast group %s:%s -- %s\n",
            groupaddr, portstr, strerror(errno));
        close(sock);
        sock = -1;
        goto sockcreateover;
    }

sockcreateover:
    if (!srcinfo) {
        freeaddrinfo(gotten);
    }
    freeaddrinfo(group);
    return sock;
}

static int ndag_init_input(libtrace_t *libtrace)
{

    char *scan = NULL;
    char *next = NULL;

    libtrace->format_data =
        (ndag_format_data_t *)malloc(sizeof(ndag_format_data_t));

    if (!libtrace->format_data) {
        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
                      "Unable to allocate memory for "
                      "format data inside ndag_init_input()");
        return -1;
    }

    FORMAT_DATA->multicastgroup = NULL;
    FORMAT_DATA->portstr = NULL;
    FORMAT_DATA->localiface = NULL;
    FORMAT_DATA->nextthreadid = 0;
    FORMAT_DATA->receivers = NULL;
    FORMAT_DATA->receiver_cnt = 0;
    FORMAT_DATA->consterfframing = -1;

    scan = strchr(libtrace->uridata, ',');
    if (scan == NULL) {
        trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT,
                      "Bad ndag URI. Should be ndag:<interface>,<multicast "
                      "group>,<port number>");
        return -1;
    }
    FORMAT_DATA->localiface =
        strndup(libtrace->uridata, (size_t)(scan - libtrace->uridata));
    next = scan + 1;

    scan = strchr(next, ',');
    if (scan == NULL) {
        FORMAT_DATA->portstr = strdup("9001");
        FORMAT_DATA->multicastgroup = strdup(next);
    } else {
        FORMAT_DATA->multicastgroup = strndup(next, (size_t)(scan - next));

        FORMAT_DATA->portstr = strdup(scan + 1);
    }
    return 0;
}

static int ndag_config_input(libtrace_t *libtrace, trace_option_t option,
                             void *value)
{

    switch (option) {
    case TRACE_OPTION_CONSTANT_ERF_FRAMING:
        FORMAT_DATA->consterfframing = *(int *)value;
        break;
    case TRACE_OPTION_EVENT_REALTIME:
    case TRACE_OPTION_SNAPLEN:
    case TRACE_OPTION_PROMISC:
    case TRACE_OPTION_FILTER:
    case TRACE_OPTION_META_FREQ:
    default:
        trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                      "Unsupported option %d", option);
        return -1;
    }

    return 0;
}

static void new_group_alert(libtrace_t *libtrace, uint16_t threadid,
                            uint16_t portnum, uint16_t monid)
{

    ndag_internal_message_t alert;

    memset(&alert, 0, sizeof(alert));
    alert.type = NDAG_CLIENT_NEWGROUP;
    alert.contents.groupaddr = FORMAT_DATA->multicastgroup;
    alert.contents.localiface = FORMAT_DATA->localiface;
    alert.contents.port = portnum;
    alert.contents.monitor = monid;

    libtrace_message_queue_put(&(FORMAT_DATA->receivers[threadid].mqueue),
                               (void *)&alert);
}

static int ndag_parse_control_message(libtrace_t *libtrace, char *msgbuf,
                                      int msgsize, uint16_t *ptmap)
{

    int i;
    ndag_common_t *ndaghdr = (ndag_common_t *)msgbuf;
    uint8_t msgtype;

    msgtype = check_ndag_header(msgbuf, (uint32_t)msgsize);
    if (msgtype == 0) {
        return -1;
    }

    msgsize -= sizeof(ndag_common_t);
    if (msgtype == NDAG_PKT_BEACON) {
        /* If message is a beacon, make sure every port included in the
         * beacon is assigned to a receive thread.
         */
        uint16_t *ptr, numstreams;

        if ((uint32_t)msgsize < sizeof(uint16_t)) {
            fprintf(stderr, "Malformed beacon (missing number of streams).\n");
            return -1;
        }

        ptr = (uint16_t *)(msgbuf + sizeof(ndag_common_t));
        numstreams = ntohs(*ptr);
        ptr++;

        if ((uint32_t)msgsize < ((numstreams + 1) * sizeof(uint16_t))) {
            fprintf(
                stderr,
                "Malformed beacon (length doesn't match number of streams).\n");
            fprintf(stderr, "%u %u\n", msgsize, numstreams);
            return -1;
        }

        for (i = 0; i < numstreams; i++) {
            uint16_t streamport = ntohs(*ptr);

            if (ptmap[streamport] == 0xffff) {
                new_group_alert(libtrace, FORMAT_DATA->nextthreadid, streamport,
                                ntohs(ndaghdr->monitorid));

                ptmap[streamport] = FORMAT_DATA->nextthreadid;

                if (libtrace->perpkt_thread_count == 0) {
                    FORMAT_DATA->nextthreadid = 0;
                } else {
                    FORMAT_DATA->nextthreadid =
                        ((FORMAT_DATA->nextthreadid + 1) %
                         libtrace->perpkt_thread_count);
                }
            }

            ptr++;
        }
    } else {
        fprintf(stderr, "Unexpected message type on control channel: %u\n",
                msgtype);
        return -1;
    }

    return 0;
}

static inline int select_on_sock(int sock)
{
    int r;
    fd_set read_fds;
    struct timeval timeout;

    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    timeout.tv_sec = 0;
    timeout.tv_usec = 500000;

    r = select(sock + 1, &read_fds, NULL, NULL, &timeout);
    if (r == -1) {
        return -1;
    }
    if (!FD_ISSET(sock, &read_fds)) {
        return 0;
    }

    return 1;
}

static int accept_ndagtcp_connection(libtrace_t *libtrace, char *ipstr,
                                     char *portstr)
{

    struct addrinfo hints, *listenai;
    int sock, consock = -1, reuse = 1, r;
    struct sockaddr_storage sa;
    socklen_t addrsize;

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;

    sock = -1;
    listenai = NULL;
    if (getaddrinfo(ipstr, portstr, &hints, &listenai) != 0) {
        fprintf(stderr, "Call to getaddrinfo failed for %s:%s -- %s\n", ipstr,
                portstr, strerror(errno));
        goto failed;
    }

    sock = socket(listenai->ai_family, listenai->ai_socktype, 0);
    if (sock < 0) {
        fprintf(stderr, "Failed to create socket for %s:%s -- %s\n", ipstr,
                portstr, strerror(errno));
        goto failed;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {

        fprintf(stderr, "Failed to configure socket for %s:%s -- %s\n", ipstr,
                portstr, strerror(errno));

        goto failed;
    }

    if (bind(sock, (struct sockaddr *)listenai->ai_addr, listenai->ai_addrlen) <
        0) {

        fprintf(stderr, "Failed to bind socket for %s:%s -- %s\n", ipstr,
                portstr, strerror(errno));
        goto failed;
    }

    if (listen(sock, 10) < 0) {
        fprintf(stderr, "Failed to listen on socket for %s:%s -- %s\n", ipstr,
                portstr, strerror(errno));
        goto failed;
    }

    freeaddrinfo(listenai);
    listenai = NULL;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    while (is_halted(libtrace) == -1 && !ndag_paused) {
        r = select_on_sock(sock);
        if (r < 0) {
            fprintf(stderr,
                    "Error in select while accepting connection on socket for "
                    "%s:%s -- %s\n",
                    ipstr, portstr, strerror(errno));
            consock = -1;
            break;
        } else if (r == 0) {
            consock = 0;
            continue;
        }
        addrsize = sizeof(struct sockaddr_storage);
        consock = accept(sock, (struct sockaddr *)&sa, &addrsize);
        if (consock < 0) {
            fprintf(stderr,
                    "Failed to accept connection on socket for %s:%s -- %s\n",
                    ipstr, portstr, strerror(errno));
            goto failed;
        }
        break;
    }

failed:
    if (sock >= 0) {
        close(sock);
    }
    if (listenai) {
        freeaddrinfo(listenai);
    }
    return consock;
}

static void _ndag_controller_run(libtrace_t *libtrace, int sock)
{
    uint16_t ptmap[65536];
    int ret;

    /* ptmap is a dirty hack to allow us to quickly check if we've already
     * assigned a stream to a thread.
     */
    memset(ptmap, 0xff, 65536 * sizeof(uint16_t));

    ndag_paused = 0;
    while ((is_halted(libtrace) == -1) && !ndag_paused) {
        char buf[CTRL_BUF_SIZE];

        ret = select_on_sock(sock);
        if (ret < 0) {
            fprintf(stderr,
                    "Error while waiting for nDAG control messages: %s\n",
                    strerror(errno));
            break;
        } else if (ret == 0) {
            continue;
        }

        ret = recvfrom(sock, buf, CTRL_BUF_SIZE, 0, NULL, NULL);
        if (ret < 0) {
            fprintf(stderr, "Error while receiving nDAG control message: %s\n",
                    strerror(errno));
            break;
        }

        if (ret == 0) {
            break;
        }

        if (ndag_parse_control_message(libtrace, buf, ret, ptmap) < 0) {
            fprintf(stderr, "Error while parsing nDAG control message.\n");
            continue;
        }
    }

    if (sock >= 0) {
        close(sock);
    }

    /* Control channel has fallen over, should probably encourage libtrace
     * to halt the receiver threads as well.
     */
    if (ret < 0 && is_halted(libtrace) == -1) {
        trace_interrupt();
    }
}

static void *ndagtcp_controller_run(void *tdata)
{
    libtrace_t *libtrace = (libtrace_t *)tdata;
    int sock = -1;

    while (is_halted(libtrace) == -1 && !ndag_paused) {
        sock = accept_ndagtcp_connection(libtrace, FORMAT_DATA->multicastgroup,
                                         FORMAT_DATA->portstr);
        if (sock == -1) {
            trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
                          "Unable to setup control channel for nDAG TCP");
            trace_interrupt();
        } else if (sock == 0) {
            continue;
        } else {
            _ndag_controller_run(libtrace, sock);
        }
    }

    pthread_exit(NULL);
}

static void *ndag_controller_run(void *tdata)
{

    libtrace_t *libtrace = (libtrace_t *)tdata;
    int sock = -1;

    sock = join_multicast_group(FORMAT_DATA->multicastgroup,
                                FORMAT_DATA->localiface, FORMAT_DATA->portstr,
                                0, NULL);
    if (sock == -1) {
        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
                      "Unable to setup control channel for nDAG TCP");
        trace_interrupt();
    } else {
        _ndag_controller_run(libtrace, sock);
    }

    pthread_exit(NULL);
}

static int ndag_start_threads(libtrace_t *libtrace, uint32_t maxthreads,
                              uint8_t socktype)
{
    int ret;
    uint32_t i;
    /* Configure the set of receiver threads */

    if (FORMAT_DATA->receivers == NULL) {
        /* What if the number of threads changes between a pause and
         * a restart? Can this happen? */
        FORMAT_DATA->receivers =
            (recvstream_t *)malloc(sizeof(recvstream_t) * maxthreads);
    }

    for (i = 0; i < maxthreads; i++) {
        FORMAT_DATA->receivers[i].sources = NULL;
        FORMAT_DATA->receivers[i].sourcecount = 0;
        FORMAT_DATA->receivers[i].halted = 0;
        FORMAT_DATA->receivers[i].knownmonitors = NULL;
        FORMAT_DATA->receivers[i].monitorcount = 0;
        FORMAT_DATA->receivers[i].threadindex = i;
        FORMAT_DATA->receivers[i].dropped_upstream = 0;
        FORMAT_DATA->receivers[i].received_packets = 0;
        FORMAT_DATA->receivers[i].missing_records = 0;
        FORMAT_DATA->receivers[i].maxfd = -1;

        libtrace_message_queue_init(&(FORMAT_DATA->receivers[i].mqueue),
                                    sizeof(ndag_internal_message_t));
    }
    FORMAT_DATA->receiver_cnt = maxthreads;

    /* Start the controller thread */
    /* TODO consider affinity of this thread? */

    if (socktype == NDAG_SOCKET_TYPE_MULTICAST) {
        ret = pthread_create(&(FORMAT_DATA->controlthread), NULL,
                             ndag_controller_run, libtrace);
    } else if (socktype == NDAG_SOCKET_TYPE_TCP) {
        ret = pthread_create(&(FORMAT_DATA->controlthread), NULL,
                             ndagtcp_controller_run, libtrace);
    } else {
        ret = -1;
    }

    if (ret != 0) {
        return -1;
    }
    return maxthreads;
}

static int ndag_start_input(libtrace_t *libtrace)
{
    FORMAT_DATA->socktype = NDAG_SOCKET_TYPE_MULTICAST;
    return ndag_start_threads(libtrace, 1, NDAG_SOCKET_TYPE_MULTICAST);
}

static int ndagtcp_start_input(libtrace_t *libtrace)
{
    FORMAT_DATA->socktype = NDAG_SOCKET_TYPE_TCP;
    return ndag_start_threads(libtrace, 1, NDAG_SOCKET_TYPE_TCP);
}

static int ndag_pstart_input(libtrace_t *libtrace)
{
    FORMAT_DATA->socktype = NDAG_SOCKET_TYPE_MULTICAST;
    if (ndag_start_threads(libtrace, libtrace->perpkt_thread_count,
                           NDAG_SOCKET_TYPE_MULTICAST) ==
        libtrace->perpkt_thread_count) {
        return 0;
    }
    return -1;
}

static int ndagtcp_pstart_input(libtrace_t *libtrace)
{
    FORMAT_DATA->socktype = NDAG_SOCKET_TYPE_TCP;
    if (ndag_start_threads(libtrace, libtrace->perpkt_thread_count,
                           NDAG_SOCKET_TYPE_TCP) ==
        libtrace->perpkt_thread_count) {
        return 0;
    }
    return -1;
}

static void free_streamsock_data(streamsock_t *src)
{
    int j;
    if (src->saved) {
        for (j = 0; j < ENCAP_BUFFERS; j++) {
            if (src->saved[j]) {
                free(src->saved[j]);
            }
        }
        free(src->saved);
    }

#if HAVE_DECL_RECVMMSG
    for (j = 0; j < RECV_BATCH_SIZE; j++) {
        if (src->mmsgbufs[j].msg_hdr.msg_iov) {
            free(src->mmsgbufs[j].msg_hdr.msg_iov);
        }
    }
#endif
    if (src->singlemsg.msg_iov) {
        free(src->singlemsg.msg_iov);
    }

    if (src->srcaddr) {
        freeaddrinfo(src->srcaddr);
    }

    if (src->sock != -1) {
        close(src->sock);
    }
}

static void halt_ndag_receiver(recvstream_t *receiver)
{
    int i;

    receiver->halted = 1;
    usleep(200000);

    libtrace_message_queue_destroy(&(receiver->mqueue));

    if (receiver->sources == NULL)
        return;
    for (i = 0; i < receiver->sourcecount; i++) {
        streamsock_t *src = &(receiver->sources[i]);
        free_streamsock_data(src);
    }
    if (receiver->knownmonitors) {
        free(receiver->knownmonitors);
    }

    if (receiver->sources) {
        free(receiver->sources);
    }
}

static int ndag_pause_input(libtrace_t *libtrace)
{
    int i;

    ndag_paused = 1;
    pthread_join(FORMAT_DATA->controlthread, NULL);
    /* Close the existing receiver sockets */
    for (i = 0; i < FORMAT_DATA->receiver_cnt; i++) {
        halt_ndag_receiver(&(FORMAT_DATA->receivers[i]));
    }
    return 0;
}

static int ndag_fin_input(libtrace_t *libtrace)
{

    if (FORMAT_DATA->receivers) {
        free(FORMAT_DATA->receivers);
    }
    if (FORMAT_DATA->multicastgroup) {
        free(FORMAT_DATA->multicastgroup);
    }
    if (FORMAT_DATA->portstr) {
        free(FORMAT_DATA->portstr);
    }
    if (FORMAT_DATA->localiface) {
        free(FORMAT_DATA->localiface);
    }

    free(libtrace->format_data);
    return 0;
}

static int ndag_get_framing_length(const libtrace_packet_t *packet)
{

    libtrace_t *libtrace = packet->trace;

    if (packet->type == TRACE_RT_DATA_ERF) {
        if (FORMAT_DATA->consterfframing >= 0) {
            return FORMAT_DATA->consterfframing;
        }
        return erf_get_framing_length(packet);
    }

    if (packet->type == TRACE_RT_DATA_CORSARO_TAGGED) {
        return sizeof(corsaro_tagged_packet_header_t) -
               sizeof(corsaro_packet_tags_t);
    }

    return 0;
}

static int got_complete_packet(streamsock_t *ssock)
{
    unsigned int required, available;
    int nr = ssock->nextreadind;
    int next;

    if (ssock->rectype == NDAG_PKT_ENCAPERF ||
        ssock->rectype == NDAG_PKT_CORSAROTAG) {
        required = ssock->nextrlen;
    } else {
        required = 0;
    }
    if (required == 0) {
        return 0;
    }

    next = ssock->nextreadind;
    available = ssock->savedsize[nr] - (ssock->nextread - ssock->saved[nr]);
    while (required > available) {
        next = ((next + 1) % ENCAP_BUFFERS);
        if (ssock->savedsize[next] == 0) {
            /* no more data available */
            return 0;
        }
        available += ssock->savedsize[next];
    }
    return 1;
}

static unsigned int copy_tmp_buffer(streamsock_t *ssock, char *tmpbuf,
                                    unsigned int required)
{

    char *ptr = tmpbuf;
    int next, first = 1;
    unsigned int available;
    int nr = ssock->nextreadind;

    next = ssock->nextreadind;
    available = ssock->savedsize[nr] - (ssock->nextread - ssock->saved[nr]);

    while (required > available) {

        if (first && available > 0) {
            memcpy(ptr, ssock->nextread, available);
            ptr += available;
            first = 0;
        }
        next = ((next + 1) % ENCAP_BUFFERS);
        if (ssock->savedsize[next] == 0) {
            /* no more data available */
            return 0;
        }
        memcpy(ptr, ssock->saved[next], ssock->savedsize[next]);
        available += ssock->savedsize[next];
    }
    return available;
}

static inline void consume_streamsock_data(streamsock_t *ssock,
                                           unsigned int required)
{

    int nr = ssock->nextreadind;
    unsigned int available =
        (ssock->savedsize[nr] - (ssock->nextread - ssock->saved[nr]));

    while (available < required) {
        required -= available;
        NEXT_BUFFER(ssock, nr)
        nr = ssock->nextreadind;
        available = ssock->savedsize[nr];
        assert(available > 0);
    }
    ssock->nextread += required;
    /* handle the case where we use up the current buffer exactly */
    if (ssock->nextread - ssock->saved[nr] >= ssock->savedsize[nr]) {
        NEXT_BUFFER(ssock, ssock->nextreadind);
    }
}

static int process_ndag_encap_headers(streamsock_t *ssock, recvstream_t *rt)
{

    ndag_encap_t *encaphdr;
    ndag_monitor_t *mon;
    uint8_t rectype;

    int nr;
    unsigned int available, required;
    char tmpbuf[ENCAP_BUFSIZE * 2];
    char *usebuf;

    nr = ssock->nextreadind;
    available = ssock->savedsize[nr] - (ssock->nextread - ssock->saved[nr]);
    required = sizeof(ndag_common_t) + sizeof(ndag_encap_t);

    usebuf = ssock->nextread;
    if (available < required) {
        available = copy_tmp_buffer(ssock, tmpbuf, required);
        if (available == 0) {
            return 0;
        }
        usebuf = tmpbuf;
    }

    rectype = check_ndag_header(usebuf, available);
    if (rectype == NDAG_PKT_KEEPALIVE) {
        consume_streamsock_data(ssock, required);
        return process_ndag_encap_headers(ssock, rt);
    } else if (rectype != NDAG_PKT_ENCAPERF && rectype != NDAG_PKT_CORSAROTAG) {
        fprintf(stderr, "Received invalid record on the channel for %s:%u.\n",
                ssock->groupaddr, ssock->port);
        return -1;
    }

    ssock->rectype = rectype;
    encaphdr = (ndag_encap_t *)(usebuf + sizeof(ndag_common_t));
    ssock->expectedreccount = ntohs(encaphdr->recordcount);
    mon = ssock->monitorptr;

    if (mon->laststart == 0) {
        mon->laststart = bswap_be_to_host64(encaphdr->started);
    } else if (mon->laststart != bswap_be_to_host64(encaphdr->started)) {
        mon->laststart = bswap_be_to_host64(encaphdr->started);
        reset_expected_seqs(rt, mon);
    }
    if (ssock->expectedseq != 0) {
        rt->missing_records +=
            seq_cmp(ntohl(encaphdr->seqno), ssock->expectedseq);
    }
    ssock->expectedseq = ntohl(encaphdr->seqno) + 1;
    if (ssock->expectedseq == 0) {
        ssock->expectedseq++;
    }
    consume_streamsock_data(ssock, required);
    return 1;
}

static int process_ndag_corsaro_header(streamsock_t *ssock,
                                       recvstream_t *rt UNUSED)
{

    corsaro_tagged_packet_header_t *taghdr;

    int nr;
    unsigned int available, required;
    char tmpbuf[ENCAP_BUFSIZE * 2];
    char *usebuf;

    nr = ssock->nextreadind;

    if (ssock->savedsize[nr] == 0) {
        /* no data available? I don't think we should be able to
         * get here in that case... */
        return 0;
    }

    assert(ssock->expectedreccount != 0);
    available = ssock->savedsize[nr] - (ssock->nextread - ssock->saved[nr]);
    required = sizeof(corsaro_tagged_packet_header_t);
    usebuf = ssock->nextread;

    if (available < required) {
        available = copy_tmp_buffer(ssock, tmpbuf, required);
        if (available == 0) {
            return 0;
        }
        usebuf = tmpbuf;
    }

    taghdr = (corsaro_tagged_packet_header_t *)usebuf;

    ssock->nextrlen =
        ntohs(taghdr->pktlen) + sizeof(corsaro_tagged_packet_header_t);
    ssock->nextts = ((uint64_t)ntohl(taghdr->ts_sec)) << 32;
    ssock->nextts += (((uint64_t)ntohl(taghdr->ts_usec)) << 32) / 1000000;
    return 1;
}

static int process_ndag_erf_headers(streamsock_t *ssock, recvstream_t *rt)
{

    dag_record_t *erfptr;

    int nr;
    unsigned int available, required;
    char tmpbuf[ENCAP_BUFSIZE * 2];
    char *usebuf;

    nr = ssock->nextreadind;

    if (ssock->savedsize[nr] == 0) {
        /* no data available? I don't think we should be able to
         * get here in that case... */
        return 0;
    }

    assert(ssock->expectedreccount != 0);
    available = ssock->savedsize[nr] - (ssock->nextread - ssock->saved[nr]);
    required = dag_record_size;
    usebuf = ssock->nextread;

    if (available < required) {
        available = copy_tmp_buffer(ssock, tmpbuf, required);
        if (available == 0) {
            return 0;
        }
        usebuf = tmpbuf;
    }

    erfptr = (dag_record_t *)usebuf;

    ssock->nextts = bswap_le_to_host64(erfptr->ts);
    ssock->nextrlen = ntohs(erfptr->rlen);
    assert(ssock->nextrlen != 0);
    if (rt->received_packets > 0) {
        rt->dropped_upstream += ntohs(erfptr->lctr);
    }

    /* don't consume the erf header, we'll need it later on */

    return 1;
}

static int ndag_prepare_packet_stream_encaperf(
    libtrace_t *restrict libtrace, recvstream_t *restrict rt,
    streamsock_t *restrict ssock, libtrace_packet_t *restrict packet)
{

    /* XXX flags is constant, so we can tell the compiler to not
     * bother copying over the parameter
     */
    char tmpbuf[ENCAP_BUFSIZE * 2];
    int nr, rlen;
    unsigned int available;
    char *usebuf = ssock->nextread;
    dag_record_t *erfptr;

    nr = ssock->nextreadind;
    available = ssock->savedsize[nr] - (ssock->nextread - ssock->saved[nr]);

    if (ssock->nextrlen == 0) {
        return -1;
    }

    if (available < ssock->nextrlen) {
        if (copy_tmp_buffer(ssock, tmpbuf, ssock->nextrlen) == 0) {
            return 0;
        }
        usebuf = tmpbuf;
    }

    if (packet->buf_control != TRACE_CTRL_PACKET || !packet->buffer) {
        packet->buf_control = TRACE_CTRL_PACKET;
        packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
    }
    packet->trace = libtrace;
    memcpy(packet->buffer, usebuf, ssock->nextrlen);
    packet->header = packet->buffer;
    packet->type = TRACE_RT_DATA_ERF;
    packet->error = ssock->nextrlen;

    erfptr = (dag_record_t *)packet->header;

    if (erfptr->flags.rxerror == 1) {
        packet->payload = NULL;
        if (FORMAT_DATA->consterfframing >= 0) {
            erfptr->rlen = htons(FORMAT_DATA->consterfframing & 0xffff);
        } else {
            erfptr->rlen = htons(erf_get_framing_length(packet));
        }
    } else {
        if (FORMAT_DATA->consterfframing >= 0) {
            packet->payload =
                (char *)packet->buffer + FORMAT_DATA->consterfframing;
        } else {
            packet->payload =
                (char *)packet->buffer + erf_get_framing_length(packet);
        }
    }

    rt->received_packets++;
    ssock->total_recordcount += 1;

    consume_streamsock_data(ssock, ssock->nextrlen);

    rlen = ssock->nextrlen;

    ssock->nextts = 0;
    ssock->reccount++;
    ssock->nextrlen = 0;

    if (ssock->reccount >= ssock->expectedreccount) {
        ssock->expectedreccount = 0;
        ssock->reccount = 0;
        ssock->rectype = 0;
    }

    packet->order = erf_get_erf_timestamp(packet);
    packet->cached.link_type = erf_get_link_type(packet);
    return rlen;
}

static int ndag_prepare_packet_stream_corsarotag(
    libtrace_t *restrict libtrace, recvstream_t *restrict rt,
    streamsock_t *restrict ssock, libtrace_packet_t *restrict packet)
{

    corsaro_tagged_packet_header_t *taghdr;
    char tmpbuf[ENCAP_BUFSIZE * 2];
    int nr, rlen;
    unsigned int available;
    char *usebuf = ssock->nextread;

    nr = ssock->nextreadind;
    available = ssock->savedsize[nr] - (ssock->nextread - ssock->saved[nr]);

    if (ssock->nextrlen == 0) {
        return -1;
    }

    if (available < ssock->nextrlen) {
        if (copy_tmp_buffer(ssock, tmpbuf, ssock->nextrlen) == 0) {
            return 0;
        }
        usebuf = tmpbuf;
    }

    if (packet->buf_control != TRACE_CTRL_PACKET || !packet->buffer) {
        packet->buf_control = TRACE_CTRL_PACKET;
        packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
    }
    packet->trace = libtrace;
    memcpy(packet->buffer, usebuf, ssock->nextrlen);
    packet->header = packet->buffer;
    packet->type = TRACE_RT_DATA_CORSARO_TAGGED;
    packet->error = ssock->nextrlen;

    taghdr = (corsaro_tagged_packet_header_t *)packet->header;

    packet->payload = &(taghdr->tags);
    packet->order = ((uint64_t)ntohl(taghdr->ts_sec)) << 32;
    packet->order += (((uint64_t)ntohl(taghdr->ts_usec)) << 32) / 1000000;
    packet->cached.link_type = TRACE_TYPE_CORSAROTAG;

    rt->received_packets++;
    ssock->total_recordcount += 1;

    consume_streamsock_data(ssock, ssock->nextrlen);

    rlen = ssock->nextrlen;

    ssock->nextts = 0;
    ssock->reccount++;
    ssock->nextrlen = 0;

    if (ssock->reccount >= ssock->expectedreccount) {
        ssock->expectedreccount = 0;
        ssock->reccount = 0;
        ssock->rectype = 0;
    }

    return rlen;
}

static int ndag_prepare_packet_stream(libtrace_t *restrict libtrace,
                                      recvstream_t *restrict rt,
                                      streamsock_t *restrict ssock,
                                      libtrace_packet_t *restrict packet,
                                      uint32_t flags UNUSED)
{

    if (ssock->rectype == NDAG_PKT_ENCAPERF) {
        return ndag_prepare_packet_stream_encaperf(libtrace, rt, ssock, packet);
    }

    if (ssock->rectype == NDAG_PKT_CORSAROTAG) {
        return ndag_prepare_packet_stream_corsarotag(libtrace, rt, ssock,
                                                     packet);
    }

    return -1;
}

static int ndag_prepare_packet(libtrace_t *libtrace UNUSED,
                               libtrace_packet_t *packet UNUSED,
                               void *buffer UNUSED,
                               libtrace_rt_types_t rt_type UNUSED,
                               uint32_t flags UNUSED)
{

    fprintf(stderr,
            "Sending nDAG records over RT doesn't make sense! Please stop\n");
    return 0;
}

static ndag_monitor_t *add_new_knownmonitor(recvstream_t *rt, uint16_t monid)
{

    ndag_monitor_t *mon;

    if (rt->monitorcount == 0) {
        rt->knownmonitors =
            (ndag_monitor_t *)malloc(sizeof(ndag_monitor_t) * 5);
    } else {
        rt->knownmonitors = (ndag_monitor_t *)realloc(
            rt->knownmonitors, sizeof(ndag_monitor_t) * (rt->monitorcount * 5));
    }

    mon = &(rt->knownmonitors[rt->monitorcount]);
    mon->monitorid = monid;
    mon->laststart = 0;

    rt->monitorcount++;
    return mon;
}

static void realign_sources(recvstream_t *rt)
{

    /* remove any "dead" socket entries in a source list, so
     * we can reclaim the memory and not just continuously grow
     * when sources come and go.
     */

    streamsock_t *newsrcs;
    int i, newcnt = 0;

    newsrcs = calloc(rt->sourcecount, sizeof(streamsock_t));

    for (i = 0; i < rt->sourcecount; i++) {
        streamsock_t *src = &(rt->sources[i]);
        if (src->sock == -1) {
            free_streamsock_data(src);
            continue;
        }
        memcpy(&(newsrcs[newcnt]), &(rt->sources[i]), sizeof(streamsock_t));
        newcnt++;
    }

    /* If we haven't removed any, then we'll need to extend the
     * source array to fit in the new streamsock.
     */
    if (newcnt == rt->sourcecount) {
        newsrcs = (streamsock_t *)realloc(
            rt->sources, sizeof(streamsock_t) * (rt->sourcecount + 10));
    }

    free(rt->sources);
    rt->sources = newsrcs;
    rt->sourcecount = newcnt;
}

static int add_new_streamsock(libtrace_t *libtrace, recvstream_t *rt,
                              streamsource_t src, uint8_t socktype)
{

    streamsock_t *ssock = NULL;
    ndag_monitor_t *mon = NULL;
    int i;
    char portstr[16];

    if (rt->sourcecount == 0) {
        rt->sources = (streamsock_t *)malloc(sizeof(streamsock_t) * 10);
    } else if ((rt->sourcecount % 10) == 0) {
        realign_sources(rt);
        rt->sources = (streamsock_t *)realloc(
            rt->sources, sizeof(streamsock_t) * (rt->sourcecount + 10));
    }

    ssock = &(rt->sources[rt->sourcecount]);

    for (i = 0; i < rt->monitorcount; i++) {
        if (rt->knownmonitors[i].monitorid == src.monitor) {
            mon = &(rt->knownmonitors[i]);
            break;
        }
    }

    if (mon == NULL) {
        mon = add_new_knownmonitor(rt, src.monitor);
    }

    ssock->socktype = socktype;
    ssock->port = src.port;
    ssock->groupaddr = src.groupaddr;
    ssock->expectedseq = 0;
    ssock->monitorptr = mon;
    ssock->saved = (char **)malloc(sizeof(char *) * ENCAP_BUFFERS);
    ssock->bufavail = ENCAP_BUFFERS;
    ssock->bufwaiting = 0;
    ssock->startidle = 0;
    ssock->nextts = 0;
    ssock->nextrlen = 0;
    ssock->reccount = 0;
    ssock->expectedreccount = 0;
    ssock->rectype = 0;
    ssock->srcaddr = NULL;

    for (i = 0; i < ENCAP_BUFFERS; i++) {
        ssock->saved[i] = (char *)malloc(ENCAP_BUFSIZE);
        ssock->savedsize[i] = 0;
    }
    ssock->nextread = ssock->saved[0];
    ssock->nextreadind = 0;
    ssock->nextwriteind = 0;
    ssock->total_recordcount = 0;

    if (socktype == NDAG_SOCKET_TYPE_MULTICAST) {
        ssock->sock = join_multicast_group(src.groupaddr, src.localiface, NULL,
                                           src.port, &(ssock->srcaddr));
    } else {
        snprintf(portstr, 16, "%u", src.port);
        ssock->sock =
            accept_ndagtcp_connection(libtrace, src.groupaddr, portstr);
    }

    if (ssock->sock < 0) {
        return -1;
    }

    if (ssock->sock > rt->maxfd) {
        rt->maxfd = ssock->sock;
    }

#if HAVE_DECL_RECVMMSG
    if (ssock->socktype == NDAG_SOCKET_TYPE_MULTICAST) {
        assert(ssock->srcaddr != NULL);
        for (i = 0; i < RECV_BATCH_SIZE; i++) {
            ssock->mmsgbufs[i].msg_hdr.msg_iov =
                (struct iovec *)malloc(sizeof(struct iovec));
            ssock->mmsgbufs[i].msg_hdr.msg_name = ssock->srcaddr->ai_addr;
            ssock->mmsgbufs[i].msg_hdr.msg_namelen = ssock->srcaddr->ai_addrlen;
            ssock->mmsgbufs[i].msg_hdr.msg_control = NULL;
            ssock->mmsgbufs[i].msg_hdr.msg_controllen = 0;
            ssock->mmsgbufs[i].msg_hdr.msg_flags = 0;
            ssock->mmsgbufs[i].msg_len = 0;
        }
    } else {
        memset(ssock->mmsgbufs, 0, sizeof(struct mmsghdr) * RECV_BATCH_SIZE);
    }
#endif
    memset(&(ssock->singlemsg), 0, sizeof(ssock->singlemsg));
    ssock->singlemsg.msg_iov = (struct iovec *)calloc(1, sizeof(struct iovec));

    rt->sourcecount += 1;

    return ssock->port;
}

static int receiver_read_messages(libtrace_t *libtrace, recvstream_t *rt,
                                  uint8_t socktype)
{

    ndag_internal_message_t msg;

    while (libtrace_message_queue_try_get(&(rt->mqueue), (void *)&msg) !=
           LIBTRACE_MQ_FAILED) {
        switch (msg.type) {
        case NDAG_CLIENT_NEWGROUP:
            if (add_new_streamsock(libtrace, rt, msg.contents, socktype) < 0) {
                return READ_ERROR;
            }
            break;
        case NDAG_CLIENT_HALT:
            return READ_EOF;
        }
    }
    return 1;
}

static inline int readable_data(streamsock_t *ssock)
{

    /* Don't read from a buffer belonging to a socket that we've closed,
     * since we probably closed it for sending us garbage data...
     */
    if (ssock->sock == -1) {
        return 0;
    }

    if (ssock->bufavail == ENCAP_BUFFERS) {
        return 0;
    }

    if (ssock->savedsize[ssock->nextreadind] == 0) {
        return 0;
    }

    return 1;
}

static int init_receivers(streamsock_t *ssock, int required)
{

    int wind = ssock->nextwriteind;
    int i = 1;

    if (required <= 0) {
        fprintf(
            stderr,
            "You are required to have atleast 1 receiver in init_receivers\n");
        return TRACE_ERR_INIT_FAILED;
    }
#if HAVE_DECL_RECVMMSG
    for (i = 0; i < required; i++) {
        if (ssock->socktype != NDAG_SOCKET_TYPE_MULTICAST) {
            i = 1;
            break;
        }
        if (i >= RECV_BATCH_SIZE) {
            break;
        }

        if (wind >= ENCAP_BUFFERS) {
            wind = 0;
        }

        ssock->mmsgbufs[i].msg_len = 0;
        ssock->mmsgbufs[i].msg_hdr.msg_iov->iov_base = ssock->saved[wind];
        ssock->mmsgbufs[i].msg_hdr.msg_iov->iov_len = ENCAP_BUFSIZE;
        ssock->mmsgbufs[i].msg_hdr.msg_iovlen = 1;

        wind++;
    }
#else
    ssock->singlemsg.msg_iov->iov_base = ssock->saved[wind];
    ssock->singlemsg.msg_iov->iov_len = ENCAP_BUFSIZE;
    ssock->singlemsg.msg_iovlen = 1;
#endif
    return i;
}

static int is_buffered_data_available(streamsock_t *ssock, struct timeval *tv,
                                      int *gottime)
{

    int toret = 0;
    if (readable_data(ssock)) {
        toret = 1;
    }
    if (!(*gottime)) {
        gettimeofday(tv, NULL);
        *gottime = 1;
    }
    if (ssock->startidle == 0) {
        ssock->startidle = tv->tv_sec;
    } else if (tv->tv_sec - ssock->startidle > NDAG_IDLE_TIMEOUT) {
        fprintf(stderr, "Closing channel %s:%u due to inactivity.\n",
                ssock->groupaddr, ssock->port);

        close(ssock->sock);
        ssock->sock = -1;
    }
    return toret;
}

#if HAVE_DECL_RECVMMSG
static int receive_from_single_socket_recvmmsg(streamsock_t *ssock,
                                               struct timeval *tv, int *gottime)
{

    int ret, avail;
    int i;

    avail = init_receivers(ssock, ssock->bufavail);

    ret = recvmmsg(ssock->sock, ssock->mmsgbufs, avail, MSG_DONTWAIT, NULL);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return is_buffered_data_available(ssock, tv, gottime);
        }
        fprintf(stderr,
                "Error receiving encapsulated records from %s:%u -- %s \n",
                ssock->groupaddr, ssock->port, strerror(errno));
        close(ssock->sock);
        ssock->sock = -1;
        return 0;
    }

    ssock->startidle = 0;
    for (i = 0; i < ret; i++) {
        ssock->savedsize[ssock->nextwriteind] = ssock->mmsgbufs[i].msg_len;
        ssock->nextwriteind = (ssock->nextwriteind + 1) % ENCAP_BUFFERS;
        ssock->bufavail--;
    }
    return 1;
}
#endif

static int receive_from_single_socket(streamsock_t *ssock, struct timeval *tv,
                                      int *gottime)
{

    int ret, avail;

    avail = init_receivers(ssock, ssock->bufavail);

    if (avail != 1) {
        return 0;
    }

    ret = recvmsg(ssock->sock, &(ssock->singlemsg), MSG_DONTWAIT);
    if (ret == 0 || (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
        if (ret == 0 && ssock->sock != -1) {
            close(ssock->sock);
            ssock->sock = -1;
        }
        if (is_buffered_data_available(ssock, tv, gottime)) {
            return 1;
        } else {
            return 0;
        }
    } else if (ret == -1) {
        fprintf(stderr,
                "Error receiving encapsulated records from %s:%u -- %s \n",
                ssock->groupaddr, ssock->port, strerror(errno));
        close(ssock->sock);
        ssock->sock = -1;
        return 0;
    }
    ssock->startidle = 0;

    ssock->savedsize[ssock->nextwriteind] = ret;
    ssock->nextwriteind = (ssock->nextwriteind + 1) % ENCAP_BUFFERS;
    ssock->bufavail--;
    return 1;
}

static int receive_from_sockets(recvstream_t *rt, uint8_t socktype)
{

    int i, readybufs, gottime;
    struct timeval tv;
    fd_set fds;
    int maxfd = 0;
    struct timeval zerotv;

    readybufs = 0;
    gottime = 0;

    if (rt->maxfd == -1) {
        return READ_MESSAGE;
    }

    FD_ZERO(&fds);

    for (i = 0; i < rt->sourcecount; i++) {
        if (rt->sources[i].sock == -1) {
            continue;
        }

#if HAVE_DECL_RECVMMSG
        /* Plenty of full buffers, just use the packets in those */
        if (socktype == NDAG_SOCKET_TYPE_MULTICAST) {
            if (rt->sources[i].bufavail < RECV_BATCH_SIZE / 2) {
                readybufs++;
                continue;
            }
        }
#endif
        if (rt->sources[i].bufavail == 0) {
            readybufs++;
            continue;
        }

        FD_SET(rt->sources[i].sock, &fds);
        if (maxfd < rt->sources[i].sock) {
            maxfd = rt->sources[i].sock;
        }
    }

    if (maxfd > 0) {

        zerotv.tv_sec = 0;
        zerotv.tv_usec = 0;
        if (select(maxfd + 1, &fds, NULL, NULL, &zerotv) == -1) {
            /* log the error? XXX */
            fprintf(stderr, "select() failed for recvstream %d: %s\n",
                    rt->threadindex, strerror(errno));
            return READ_ERROR;
        }
    }

    for (i = 0; i < rt->sourcecount; i++) {
        streamsock_t *ssock = &(rt->sources[i]);
        if (ssock->sock == -1 || !FD_ISSET(ssock->sock, &fds)) {

            if (ssock->nextreadind != ssock->nextwriteind) {
                readybufs++;
            } else if (ssock->savedsize[ssock->nextreadind] -
                           (ssock->nextread -
                            ssock->saved[ssock->nextreadind]) >
                       0) {
                readybufs++;
            }

            continue;
        }
#if HAVE_DECL_RECVMMSG
        if (socktype == NDAG_SOCKET_TYPE_MULTICAST) {
            readybufs += receive_from_single_socket_recvmmsg(&(rt->sources[i]),
                                                             &tv, &gottime);
            continue;
        }
#endif
        readybufs +=
            receive_from_single_socket(&(rt->sources[i]), &tv, &gottime);
    }

    return readybufs;
}

static int receive_encap_records_block(libtrace_t *libtrace, recvstream_t *rt,
                                       libtrace_packet_t *packet,
                                       libtrace_message_queue_t *msg)
{

    int iserr = 0;
    int delay = 0;

    if (packet->buf_control == TRACE_CTRL_PACKET) {
        free(packet->buffer);
        packet->buffer = NULL;
    }

    do {
        /* Make sure we shouldn't be halting */
        if ((iserr = is_halted(libtrace)) != -1) {
            return iserr;
        }

        /* Check for any messages from the control thread */
        iserr = receiver_read_messages(libtrace, rt, FORMAT_DATA->socktype);

        if (iserr <= 0) {
            return iserr;
        }

        if (delay > 1000000) {
            return rt->sourcecount + 1;
        }
        /* If blocking and no sources, sleep for a bit and then try
         * checking for messages again.
         */
        if (rt->sourcecount == 0) {
            usleep(10000);
            delay += 10000;
            continue;
        }

        if ((iserr = receive_from_sockets(rt, FORMAT_DATA->socktype)) ==
            READ_ERROR) {
            return iserr;
        } else if (iserr > 0) {
            /* At least one of our input sockets has available
             * data, let's go ahead and use what we have. */
            break;
        }

        /* if we have access to the message queue check for a message
         */
        if ((msg && libtrace_message_queue_count(msg) > 0)) {
            return READ_MESSAGE;
        }

        /* None of our sources have anything available, we can take
         * a short break rather than immediately trying again.
         */
        if (iserr == 0) {
            usleep(100);
            delay += 100;
        }

    } while (!rt->halted);

    if (rt->halted) {
        return 0;
    }
    return iserr;
}

static int receive_encap_records_nonblock(libtrace_t *libtrace,
                                          recvstream_t *rt,
                                          libtrace_packet_t *packet)
{

    int iserr = 0;

    if (packet->buf_control == TRACE_CTRL_PACKET) {
        free(packet->buffer);
        packet->buffer = NULL;
    }

    /* Make sure we shouldn't be halting */
    if ((iserr = is_halted(libtrace)) != -1) {
        return iserr;
    }

    /* If non-blocking and there are no sources, just break */
    if (rt->sourcecount == 0) {
        return 0;
    }

    return receive_from_sockets(rt, FORMAT_DATA->socktype);
}

static streamsock_t *select_next_packet(recvstream_t *rt, int *errstate)
{
    int i, r;
    streamsock_t *ssock = NULL;
    uint64_t earliest = 0;
    uint64_t currentts = 0;

    *errstate = 0;
    for (i = 0; i < rt->sourcecount; i++) {
        if (!readable_data(&(rt->sources[i]))) {
            continue;
        }

        if (rt->sources[i].rectype == 0) {
            r = process_ndag_encap_headers(&(rt->sources[i]), rt);
            if (r < 0) {
                close(rt->sources[i].sock);
                rt->sources[i].sock = -1;
                *errstate = 1;
                return NULL;
            }
            if (r == 0) {
                continue;
            }
        }

        if (rt->sources[i].nextts == 0) {
            if (rt->sources[i].rectype == NDAG_PKT_ENCAPERF) {
                r = process_ndag_erf_headers(&(rt->sources[i]), rt);
            } else if (rt->sources[i].rectype == NDAG_PKT_CORSAROTAG) {
                r = process_ndag_corsaro_header(&(rt->sources[i]), rt);
            } else {
                r = 0;
            }

            if (r < 0) {
                close(rt->sources[i].sock);
                rt->sources[i].sock = -1;
                *errstate = 1;
                return NULL;
            }
            if (r == 0) {
                continue;
            }
        }
        assert(rt->sources[i].nextts != 0);
        currentts = rt->sources[i].nextts;

        if (earliest == 0 || earliest > currentts) {
            earliest = currentts;
            ssock = &(rt->sources[i]);
        }
    }
    if (ssock && got_complete_packet(ssock)) {
        return ssock;
    }
    return NULL;
}

static int ndag_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet)
{

    int rem, ret, errstate;
    streamsock_t *nextavail = NULL;

    if (FORMAT_DATA->receivers[0].halted) {
        return 0;
    }

    rem = receive_encap_records_block(libtrace, &(FORMAT_DATA->receivers[0]),
                                      packet, NULL);

    if (rem == READ_ERROR || rem == READ_EOF) {
        return rem;
    }

    errstate = 0;
    nextavail = select_next_packet(&(FORMAT_DATA->receivers[0]), &errstate);
    if (nextavail == NULL) {
        if (errstate) {
            trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                    "Error while parsing nDAG PDU");
            return READ_ERROR;
        }
        return READ_MESSAGE;
    }

    /* nextread should point at an ERF header, so prepare 'packet' to be
     * a libtrace ERF packet. */

    ret = ndag_prepare_packet_stream(libtrace, &(FORMAT_DATA->receivers[0]),
                                     nextavail, packet,
                                     TRACE_PREP_DO_NOT_OWN_BUFFER);
    nextavail->bufavail += nextavail->bufwaiting;
    nextavail->bufwaiting = 0;
    return ret;
}

static int ndag_pread_packets(libtrace_t *libtrace, libtrace_thread_t *t,
                              libtrace_packet_t **packets, size_t nb_packets)
{

    recvstream_t *rt;
    int rem, i, r, errstate;
    size_t read_packets = 0;
    streamsock_t *nextavail = NULL;

    rt = (recvstream_t *)t->format_data;

    if (rt->halted) {
        return 0;
    }

    do {
        /* Only check for messages once per batch */
        if (nextavail == NULL) {
            rem = receive_encap_records_block(
                libtrace, rt, packets[read_packets], &t->messages);
            if (rem < 0) {
                if (rem == READ_MESSAGE && read_packets == 0) {
                    return rem;
                } else {
                    /* allow us to return the packets we've read,
                     * then libtrace can check for messages
                     */
                    break;
                }
            }

            if (rem == 0) {
                break;
            }

            if (rem > rt->sourcecount && read_packets > 0) {
                break;
            }
        }
        errstate = 0;
        nextavail = select_next_packet(rt, &errstate);
        if (nextavail == NULL) {
            if (errstate) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                        "Error while parsing nDAG PDU");
                return -1;
            }
            continue;
        }

        if ((r = ndag_prepare_packet_stream(
                 libtrace, rt, nextavail, packets[read_packets],
                 TRACE_PREP_DO_NOT_OWN_BUFFER)) < 0) {
            return -1;
        }

        if (r == 0) {
            nextavail = NULL;
            continue;
        }

        read_packets++;
        if (read_packets >= nb_packets) {
            break;
        }
    } while (!rt->halted);

    if (rt->halted) {
        return 0;
    }

    for (i = 0; i < rt->sourcecount; i++) {
        streamsock_t *src = &(rt->sources[i]);
        src->bufavail += src->bufwaiting;
        src->bufwaiting = 0;
        if (src->bufavail < 0 || src->bufavail > ENCAP_BUFFERS) {
            trace_set_err(libtrace, TRACE_ERR_BAD_IO,
                          "Not enough buffer space in ndag_pread_packets()");
            return -1;
        }
    }

    return read_packets;
}

static libtrace_eventobj_t trace_event_ndag(libtrace_t *libtrace,
                                            libtrace_packet_t *packet)
{

    libtrace_eventobj_t event = {0, 0, 0.0, 0};
    int rem, i, errstate;
    streamsock_t *nextavail = NULL;

    if (FORMAT_DATA->receivers[0].halted) {
        event.type = TRACE_EVENT_TERMINATE;
        return event;
    }
    /* Only check for messages once per call */
    rem = receiver_read_messages(libtrace, &(FORMAT_DATA->receivers[0]),
                                 FORMAT_DATA->socktype);
    if (rem <= 0) {
        event.type = TRACE_EVENT_TERMINATE;
        return event;
    }

    do {
        rem = receive_encap_records_nonblock(
            libtrace, &(FORMAT_DATA->receivers[0]), packet);

        if (rem < 0) {
            trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                          "Received invalid nDAG records.");
            event.type = TRACE_EVENT_TERMINATE;
            break;
        }

        if (rem == 0) {
            /* Either we've been halted or we've got no packets
             * right now. */
            if (is_halted(libtrace) == 0) {
                event.type = TRACE_EVENT_TERMINATE;
                break;
            }
            event.type = TRACE_EVENT_SLEEP;
            event.seconds = 0.0001;
            break;
        }

        errstate = 0;
        nextavail = select_next_packet(&(FORMAT_DATA->receivers[0]), &errstate);
        if (nextavail == NULL) {
            if (errstate) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                        "Error while parsing nDAG PDU");
                event.type = TRACE_EVENT_TERMINATE;
            } else {
                event.type = TRACE_EVENT_SLEEP;
                event.seconds = 0.0001;
            }
            break;
        }

        event.type = TRACE_EVENT_PACKET;
        ndag_prepare_packet_stream(libtrace, &(FORMAT_DATA->receivers[0]),
                                   nextavail, packet,
                                   TRACE_PREP_DO_NOT_OWN_BUFFER);
        event.size =
            trace_get_capture_length(packet) + trace_get_framing_length(packet);

        if (libtrace->filter) {
            int filtret = trace_apply_filter(libtrace->filter, packet);
            if (filtret == -1) {
                trace_set_err(libtrace, TRACE_ERR_BAD_FILTER, "Bad BPF Filter");
                event.type = TRACE_EVENT_TERMINATE;
                break;
            }

            if (filtret == 0) {
                /* Didn't match filter, try next one */
                libtrace->filtered_packets++;
                trace_clear_cache(packet);
                continue;
            }
        }

        if (libtrace->snaplen > 0) {
            trace_set_capture_length(packet, libtrace->snaplen);
        }
        libtrace->accepted_packets++;
        break;
    } while (1);

    for (i = 0; i < FORMAT_DATA->receivers[0].sourcecount; i++) {
        streamsock_t *src = &(FORMAT_DATA->receivers[0].sources[i]);
        src->bufavail += src->bufwaiting;
        src->bufwaiting = 0;
        if (src->bufavail < 0 || src->bufavail > ENCAP_BUFFERS) {
            trace_set_err(libtrace, TRACE_ERR_BAD_IO,
                          "Not enough buffer space in trace_event_ndag()");
            break;
        }
    }

    return event;
}

static void ndag_get_statistics(libtrace_t *libtrace, libtrace_stat_t *stat)
{

    int i;

    stat->dropped_valid = 1;
    stat->dropped = 0;
    stat->received_valid = 1;
    stat->received = 0;
    stat->missing_valid = 1;
    stat->missing = 0;

    /* TODO Is this thread safe? */
    for (i = 0; i < FORMAT_DATA->receiver_cnt; i++) {
        stat->dropped += FORMAT_DATA->receivers[i].dropped_upstream;
        stat->received += FORMAT_DATA->receivers[i].received_packets;
        stat->missing += FORMAT_DATA->receivers[i].missing_records;
    }
}

static void ndag_get_thread_stats(libtrace_t *libtrace, libtrace_thread_t *t,
                                  libtrace_stat_t *stat)
{

    recvstream_t *recvr = (recvstream_t *)t->format_data;

    if (libtrace == NULL)
        return;
    /* TODO Is this thread safe */
    stat->dropped_valid = 1;
    stat->dropped = recvr->dropped_upstream;

    stat->received_valid = 1;
    stat->received = recvr->received_packets;

    stat->missing_valid = 1;
    stat->missing = recvr->missing_records;
}

static int ndag_pregister_thread(libtrace_t *libtrace, libtrace_thread_t *t,
                                 bool reader)
{
    recvstream_t *recvr;

    if (!reader || t->type != THREAD_PERPKT) {
        return 0;
    }

    if (t->perpkt_num >= FORMAT_DATA->receiver_cnt) {
        return 0;
    }
    recvr = &(FORMAT_DATA->receivers[t->perpkt_num]);
    t->format_data = recvr;

    return 0;
}

static libtrace_linktype_t ndag_get_link_type(const libtrace_packet_t *packet)
{

    if (packet->header == NULL) {
        return ~0;
    }

    if (packet->type == TRACE_RT_DATA_CORSARO_TAGGED) {
        return TRACE_TYPE_CORSAROTAG;
    }

    if (packet->type == TRACE_RT_DATA_ERF) {
        return erf_get_link_type(packet);
    }

    return ~0;
}

static libtrace_direction_t ndag_get_direction(const libtrace_packet_t *packet)
{
    if (packet->type == TRACE_RT_DATA_ERF) {
        return erf_get_direction(packet);
    }

    /* TODO think about whether corsaro tagged packets need dir tags */
    return TRACE_DIR_UNKNOWN;
}

static libtrace_direction_t ndag_set_direction(libtrace_packet_t *packet,
                                               libtrace_direction_t direction)
{

    if (packet->type == TRACE_RT_DATA_ERF) {
        return erf_set_direction(packet, direction);
    }

    /* TODO think about whether corsaro tagged packets need dir tags */
    return TRACE_DIR_UNKNOWN;
}

static uint64_t ndag_get_erf_timestamp(const libtrace_packet_t *packet)
{
    if (packet->type == TRACE_RT_DATA_ERF) {
        return erf_get_erf_timestamp(packet);
    }
    if (packet->type == TRACE_RT_DATA_CORSARO_TAGGED) {
        return packet->order;
    }
    return 0;
}

static int ndag_get_capture_length(const libtrace_packet_t *packet)
{
    if (packet->type == TRACE_RT_DATA_ERF) {
        return erf_get_capture_length(packet);
    }

    if (packet->type == TRACE_RT_DATA_CORSARO_TAGGED) {
        corsaro_tagged_packet_header_t *tag;

        tag = (corsaro_tagged_packet_header_t *)packet->header;
        return ntohs(tag->pktlen) + sizeof(corsaro_packet_tags_t);
    }

    return 0;
}

static int ndag_get_wire_length(const libtrace_packet_t *packet)
{
    if (packet->type == TRACE_RT_DATA_ERF) {
        return erf_get_wire_length(packet);
    }

    if (packet->type == TRACE_RT_DATA_CORSARO_TAGGED) {
        corsaro_tagged_packet_header_t *tag;

        tag = (corsaro_tagged_packet_header_t *)packet->header;
        return ntohs(tag->wirelen);
    }

    return 0;
}

static size_t ndag_set_capture_length(libtrace_packet_t *packet, size_t size)
{

    if (packet->type == TRACE_RT_DATA_ERF) {
        return erf_set_capture_length(packet, size);
    }

    if (packet->type == TRACE_RT_DATA_CORSARO_TAGGED) {
        corsaro_tagged_packet_header_t *tag;

        tag = (corsaro_tagged_packet_header_t *)packet->header;
        if (tag == NULL) {
            return ~0U;
        }

        if (size > ntohs(tag->pktlen) - sizeof(corsaro_packet_tags_t)) {
            return ntohs(tag->pktlen) - sizeof(corsaro_packet_tags_t);
        }
        packet->cached.capture_length = -1;

        tag->pktlen = htons(size);
        return size;
    }

    return ~0U;
}

static struct libtrace_format_t ndag = {

    "ndag",
    "",
    TRACE_FORMAT_NDAG,
    NULL,                    /* probe filename */
    NULL,                    /* probe magic */
    ndag_init_input,         /* init_input */
    ndag_config_input,       /* config_input */
    ndag_start_input,        /* start_input */
    ndag_pause_input,        /* pause_input */
    NULL,                    /* init_output */
    NULL,                    /* config_output */
    NULL,                    /* start_output */
    ndag_fin_input,          /* fin_input */
    NULL,                    /* fin_output */
    ndag_read_packet,        /* read_packet */
    ndag_prepare_packet,     /* prepare_packet */
    NULL,                    /* fin_packet */
    NULL,                    /* can_hold_packet */
    NULL,                    /* write_packet */
    NULL,                    /* flush_output */
    ndag_get_link_type,      /* get_link_type */
    ndag_get_direction,      /* get_direction */
    ndag_set_direction,      /* set_direction */
    ndag_get_erf_timestamp,  /* get_erf_timestamp */
    NULL,                    /* get_timeval */
    NULL,                    /* get_seconds */
    NULL,                    /* get_timespec */
    NULL,                    /* get_meta_section */
    NULL,                    /* seek_erf */
    NULL,                    /* seek_timeval */
    NULL,                    /* seek_seconds */
    ndag_get_capture_length, /* get_capture_length */
    ndag_get_wire_length,    /* get_wire_length */
    ndag_get_framing_length, /* get_framing_length */
    ndag_set_capture_length, /* set_capture_length */
    NULL,                    /* get_received_packets */
    NULL,                    /* get_filtered_packets */
    NULL,                    /* get_dropped_packets */
    ndag_get_statistics,     /* get_statistics */
    NULL,                    /* get_fd */
    trace_event_ndag,        /* trace_event */
    NULL,                    /* help */
    NULL,                    /* next pointer */
    {true, 0},               /* live packet capture */
    ndag_pstart_input,       /* parallel start */
    ndag_pread_packets,      /* parallel read */
    ndag_pause_input,        /* parallel pause */
    NULL,
    ndag_pregister_thread, /* register thread */
    NULL,
    ndag_get_thread_stats /* per-thread stats */
};

static struct libtrace_format_t ndagtcp = {

    "ndagtcp",
    "",
    TRACE_FORMAT_NDAG_TCP,
    NULL,                    /* probe filename */
    NULL,                    /* probe magic */
    ndag_init_input,         /* init_input */
    ndag_config_input,       /* config_input */
    ndagtcp_start_input,     /* start_input */
    ndag_pause_input,        /* pause_input */
    NULL,                    /* init_output */
    NULL,                    /* config_output */
    NULL,                    /* start_output */
    ndag_fin_input,          /* fin_input */
    NULL,                    /* fin_output */
    ndag_read_packet,        /* read_packet */
    ndag_prepare_packet,     /* prepare_packet */
    NULL,                    /* fin_packet */
    NULL,                    /* can_hold_packet */
    NULL,                    /* write_packet */
    NULL,                    /* flush_output */
    ndag_get_link_type,      /* get_link_type */
    ndag_get_direction,      /* get_direction */
    ndag_set_direction,      /* set_direction */
    ndag_get_erf_timestamp,  /* get_erf_timestamp */
    NULL,                    /* get_timeval */
    NULL,                    /* get_seconds */
    NULL,                    /* get_timespec */
    NULL,                    /* get_meta_section */
    NULL,                    /* seek_erf */
    NULL,                    /* seek_timeval */
    NULL,                    /* seek_seconds */
    ndag_get_capture_length, /* get_capture_length */
    ndag_get_wire_length,    /* get_wire_length */
    ndag_get_framing_length, /* get_framing_length */
    ndag_set_capture_length, /* set_capture_length */
    NULL,                    /* get_received_packets */
    NULL,                    /* get_filtered_packets */
    NULL,                    /* get_dropped_packets */
    ndag_get_statistics,     /* get_statistics */
    NULL,                    /* get_fd */
    trace_event_ndag,        /* trace_event */
    NULL,                    /* help */
    NULL,                    /* next pointer */
    {true, 0},               /* live packet capture */
    ndagtcp_pstart_input,    /* parallel start */
    ndag_pread_packets,      /* parallel read */
    ndag_pause_input,        /* parallel pause */
    NULL,
    ndag_pregister_thread, /* register thread */
    NULL,
    ndag_get_thread_stats /* per-thread stats */
};

void ndag_constructor(void)
{
    register_format(&ndag);
    register_format(&ndagtcp);
}
