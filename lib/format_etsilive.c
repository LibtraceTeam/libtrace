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
#include "data-struct/simple_circular_buffer.h"
#include "format_etsi.h"

#include <libwandder.h>
#include <libwandder_etsili.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#define ETSI_RECVBUF_SIZE (64 * 1024 * 1024)

#define FORMAT_DATA ((etsilive_format_data_t *)libtrace->format_data)

typedef struct etsipktcache {

    uint64_t timestamp;
    uint16_t length;

} etsi_packet_cache_t;

typedef struct etsisocket {
    int sock;
    struct sockaddr *srcaddr;

    libtrace_scb_t recvbuffer;
    etsi_packet_cache_t cached;

} etsisocket_t;

typedef struct etsithread {
    libtrace_message_queue_t mqueue;
    etsisocket_t *sources;
    uint16_t sourcecount;
    uint16_t sourcealloc;
    uint16_t activesources;
    int threadindex;
    wandder_etsispec_t *etsidec;
} etsithread_t;

typedef struct etsilive_format_data {
    char *listenport;
    char *listenaddr;

    pthread_t listenthread;
    etsithread_t *receivers;
    int maxthreads;
    int nextthreadid;
} etsilive_format_data_t;

typedef struct newsendermessage {
    int recvsock;
    struct sockaddr *recvaddr;
} newsend_message_t;

static int send_etsili_keepalive_response(int fd, int64_t seqno);

static void *etsi_listener(void *tdata)
{
    libtrace_t *libtrace = (libtrace_t *)tdata;
    struct addrinfo hints, *listenai;
    struct sockaddr_storage *connected;
    socklen_t addrsize;
    int sock, consock;
    int reuse = 1;

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;

    sock = -1;
    listenai = NULL;

    if (getaddrinfo(FORMAT_DATA->listenaddr, FORMAT_DATA->listenport, &hints,
                    &listenai) != 0) {
        fprintf(stderr, "Call to getaddrinfo failed for %s:%s -- %s\n",
                FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
                strerror(errno));
        goto listenerror;
    }

    sock = socket(listenai->ai_family, listenai->ai_socktype, 0);
    if (sock < 0) {
        fprintf(stderr, "Failed to create socket for %s:%s -- %s\n",
                FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
                strerror(errno));
        goto listenerror;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {

        fprintf(stderr, "Failed to configure socket for %s:%s -- %s\n",
                FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
                strerror(errno));

        goto listenerror;
    }

    if (bind(sock, (struct sockaddr *)listenai->ai_addr, listenai->ai_addrlen) <
        0) {

        fprintf(stderr, "Failed to bind socket for %s:%s -- %s\n",
                FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
                strerror(errno));
        goto listenerror;
    }

    if (listen(sock, 10) < 0) {
        fprintf(stderr, "Failed to listen on socket for %s:%s -- %s\n",
                FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
                strerror(errno));
        goto listenerror;
    }

    freeaddrinfo(listenai);
    listenai = NULL;

    /* TODO consider possibility of pausing and resuming? */
    while ((is_halted(libtrace) == -1)) {
        newsend_message_t msg;
        etsithread_t *et;

        memset(&msg, 0, sizeof(msg));

        /* accept */
        connected =
            (struct sockaddr_storage *)malloc(sizeof(struct sockaddr_storage));
        addrsize = sizeof(struct sockaddr_storage);
        consock = accept(sock, (struct sockaddr *)connected, &addrsize);
        if (consock < 0) {
            fprintf(stderr,
                    "Failed to accept connection on socket for %s:%s -- %s\n",
                    FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
                    strerror(errno));
            free(connected);
            goto listenerror;
        }

        /* if successful, send consock to next available thread */
        msg.recvsock = consock;
        msg.recvaddr = (struct sockaddr *)connected;
        et = &(FORMAT_DATA->receivers[FORMAT_DATA->nextthreadid]);
        libtrace_message_queue_put(&(et->mqueue), (void *)&msg);

        if (FORMAT_DATA->maxthreads > 1) {
            FORMAT_DATA->nextthreadid =
                ((FORMAT_DATA->nextthreadid + 1) % FORMAT_DATA->maxthreads);
        }
    }

    goto listenshutdown;

listenerror:
    trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
                  "Unable to create listening socket for etsilive");

listenshutdown:
    if (sock >= 0) {
        close(sock);
    }
    if (listenai) {
        freeaddrinfo(listenai);
    }
    if (!is_halted(libtrace)) {
        trace_interrupt();
    }
    pthread_exit(NULL);
}

static int etsilive_init_input(libtrace_t *libtrace)
{
    char *scan = NULL;
    libtrace->format_data =
        (etsilive_format_data_t *)malloc(sizeof(etsilive_format_data_t));

    if (!libtrace->format) {
        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
                      "Unable to allocate memory for "
                      "format data inside etsilive_init_input()");
        return 1;
    }

    FORMAT_DATA->receivers = NULL;
    FORMAT_DATA->nextthreadid = 0;
    FORMAT_DATA->maxthreads = 1;
    FORMAT_DATA->listenaddr = NULL;
    FORMAT_DATA->listenthread = 0;

    /* TODO is there a sensible default port number? */
    scan = strchr(libtrace->uridata, ':');
    if (scan == NULL) {
        trace_set_err(
            libtrace, TRACE_ERR_BAD_FORMAT,
            "Bad etsilive URI. Should be etsilive:<listenaddr>:<port number>");
        return -1;
    }
    FORMAT_DATA->listenaddr =
        strndup(libtrace->uridata, (size_t)(scan - libtrace->uridata));
    FORMAT_DATA->listenport = strdup(scan + 1);

    return 0;
}

static int etsilive_fin_input(libtrace_t *libtrace)
{
    /*
    if (FORMAT_DATA->listenthread != 0) {
            pthread_join(FORMAT_DATA->listenthread, NULL);
    }
    */
    if (FORMAT_DATA->receivers) {
        free(FORMAT_DATA->receivers);
    }

    if (FORMAT_DATA->listenaddr) {
        free(FORMAT_DATA->listenaddr);
    }
    if (FORMAT_DATA->listenport) {
        free(FORMAT_DATA->listenport);
    }
    free(libtrace->format_data);
    return 0;
}

static int etsilive_start_threads(libtrace_t *libtrace, uint32_t maxthreads)
{
    int ret;
    uint32_t i;
    /* Configure the set of receiver threads */

    if (FORMAT_DATA->receivers == NULL) {
        /* What if the number of threads changes between a pause and
         * a restart? Can this happen? */
        FORMAT_DATA->receivers =
            (etsithread_t *)malloc(sizeof(etsithread_t) * maxthreads);
    }

    for (i = 0; i < maxthreads; i++) {

        libtrace_message_queue_init(&(FORMAT_DATA->receivers[i].mqueue),
                                    sizeof(newsend_message_t));

        FORMAT_DATA->receivers[i].sources = NULL;
        FORMAT_DATA->receivers[i].sourcealloc = 0;
        FORMAT_DATA->receivers[i].sourcecount = 0;
        FORMAT_DATA->receivers[i].activesources = 0;
        FORMAT_DATA->receivers[i].threadindex = i;
        FORMAT_DATA->receivers[i].etsidec = wandder_create_etsili_decoder();
    }
    FORMAT_DATA->maxthreads = maxthreads;

    /* Start the listening thread */
    /* TODO consider affinity of this thread? */

    ret = pthread_create(&(FORMAT_DATA->listenthread), NULL, etsi_listener,
                         libtrace);
    if (ret != 0) {
        return -1;
    }
    return maxthreads;
}

static int etsilive_start_input(libtrace_t *libtrace)
{
    return etsilive_start_threads(libtrace, 1);
}

static void free_etsi_socket(etsisocket_t *esock)
{
    if (esock->sock == -1)
        return;
    close(esock->sock);
    esock->sock = -1;
    libtrace_scb_destroy(&(esock->recvbuffer));
    free(esock->srcaddr);
    esock->srcaddr = NULL;
}

static void halt_etsi_thread(etsithread_t *receiver)
{
    int i;
    libtrace_message_queue_destroy(&(receiver->mqueue));
    wandder_free_etsili_decoder(receiver->etsidec);
    if (receiver->sources == NULL)
        return;
    for (i = 0; i < receiver->sourcecount; i++) {
        etsisocket_t *src = &receiver->sources[i];
        if (src->sock == -1)
            /* Skip if already closed */
            continue;
        free_etsi_socket(src);
    }
    free(receiver->sources);
}

static int etsilive_pause_input(libtrace_t *libtrace)
{

    int i;
    if (libtrace->perpkt_thread_count == 0) {
        halt_etsi_thread(&(FORMAT_DATA->receivers[0]));
    } else {
        for (i = 0; i < FORMAT_DATA->maxthreads; i++) {
            halt_etsi_thread(&(FORMAT_DATA->receivers[i]));
        }
    }
    return 0;
}

static int receiver_read_message(etsithread_t *et)
{
    newsend_message_t msg;

    while (libtrace_message_queue_try_get(&(et->mqueue), (void *)&msg) !=
           LIBTRACE_MQ_FAILED) {
        etsisocket_t *esock = NULL;
        int i;

        if (et->sourcecount == 0) {
            et->sources = (etsisocket_t *)malloc(sizeof(etsisocket_t) * 10);
            et->sourcealloc = 10;

            for (i = 0; i < et->sourcealloc; i++) {
                et->sources[i].sock = -1;
                et->sources[i].srcaddr = NULL;
                et->sources[i].recvbuffer.fd = -1;
                et->sources[i].recvbuffer.address = NULL;
            }

            esock = &(et->sources[0]);
            et->sourcecount = 1;
        } else {
            for (i = 0; i < et->sourcealloc; i++) {
                if (et->sources[i].sock == -1) {
                    esock = &(et->sources[i]);
                    break;
                }
            }
        }

        if (esock == NULL) {
            et->sources = (etsisocket_t *)realloc(
                et->sources, sizeof(etsisocket_t) * (et->sourcealloc + 10));

            for (i = et->sourcealloc; i < et->sourcealloc + 10; i++) {
                et->sources[i].sock = -1;
                et->sources[i].srcaddr = NULL;
                et->sources[i].recvbuffer.fd = -1;
                et->sources[i].recvbuffer.address = NULL;
            }
            esock = &(et->sources[et->sourcealloc]);
            et->sourcealloc += 10;
            et->sourcecount += 1;
        }

        esock->sock = msg.recvsock;
        esock->srcaddr = msg.recvaddr;
        libtrace_scb_init(&(esock->recvbuffer), ETSI_RECVBUF_SIZE,
                          et->threadindex);
        esock->cached.timestamp = 0;
        esock->cached.length = 0;

        et->activesources += 1;

        fprintf(stderr, "Thread %d is now handling %u sources.\n",
                et->threadindex, et->activesources);
    }
    return 1;
}

static void receive_from_single_socket(etsisocket_t *esock, etsithread_t *et)
{

    int ret = 0;

    if (esock->sock == -1) {
        return;
    }

    ret =
        libtrace_scb_recv_sock(&(esock->recvbuffer), esock->sock, MSG_DONTWAIT);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Would have blocked, nothing available */
            return;
        }
        fprintf(stderr, "Error receiving on socket %d: %s\n", esock->sock,
                strerror(errno));
        free_etsi_socket(esock);
        et->activesources -= 1;
    }

    if (ret == 0) {
        fprintf(stderr, "Socket %d has disconnected\n", esock->sock);
        free_etsi_socket(esock);
        et->activesources -= 1;
    }
}

static int receive_etsi_sockets(libtrace_t *libtrace, etsithread_t *et)
{

    int iserr = 0;
    int i;

    if ((iserr = is_halted(libtrace)) != -1) {
        return iserr;
    }

    iserr = receiver_read_message(et);
    if (iserr <= 0) {
        return iserr;
    }

    if (et->activesources == 0) {
        return 1;
    }

    for (i = 0; i < et->sourcecount; i++) {
        receive_from_single_socket(&(et->sources[i]), et);
    }
    return 1;
}

static inline void inspect_next_packet(etsisocket_t *sock,
                                       etsisocket_t **earliestsock,
                                       uint64_t *earliesttime,
                                       wandder_etsispec_t *dec,
                                       etsithread_t *et)
{

    struct timeval tv;
    uint32_t available;
    uint8_t *ptr = NULL;
    uint32_t reclen = 0;
    uint64_t current;

    if (sock->sock == -1) {
        return;
    }
    /* Have we already successfully decoded this? Cool,
     * just use whatever we cached last time.
     */
    if (sock->cached.timestamp != 0) {
        current = sock->cached.timestamp;

        if (*earliesttime == 0 || *earliesttime > current) {
            *earliesttime = current;
            *earliestsock = sock;
        }
        return;
    }

    ptr = libtrace_scb_get_read(&(sock->recvbuffer), &available);

    if (available == 0 || ptr == NULL) {
        return;
    }

    wandder_attach_etsili_buffer(dec, ptr, available, false);
    if (sock->cached.length != 0) {
        reclen = sock->cached.length;
    } else {
        reclen = wandder_etsili_get_pdu_length(dec);
        if (reclen == 0) {
            return;
        }
    }

    if (available < reclen) {
        /* Don't have the whole PDU yet */
        return;
    }

    if (wandder_etsili_is_keepalive(dec)) {
        int64_t kaseq = wandder_etsili_get_sequence_number(dec);
        if (kaseq < 0) {
            fprintf(stderr, "bogus sequence number in ETSILI keep alive.\n");
            free_etsi_socket(sock);
            et->activesources -= 1;
            return;
        }
        /* Send keep alive response */
        if (send_etsili_keepalive_response(sock->sock, kaseq) < 0) {
            fprintf(stderr,
                    "error sending response to ETSILI keep alive: %s.\n",
                    strerror(errno));
            free_etsi_socket(sock);
            et->activesources -= 1;
            return;
        }
        /* Skip past KA */
        libtrace_scb_advance_read(&(sock->recvbuffer), reclen);
        return;
    }

    /* Get the timestamp */

    tv = wandder_etsili_get_header_timestamp(dec);
    if (tv.tv_sec == 0) {
        return;
    }
    current = ((((uint64_t)tv.tv_sec) << 32) +
               (((uint64_t)tv.tv_usec << 32) / 1000000));

    /* Success, cache everything we used so we don't have to
     * decode this packet again.
     */
    sock->cached.timestamp = current;
    sock->cached.length = reclen;

    /* Don't forget to update earliest and esock... */
    if (current < *earliesttime || *earliesttime == 0) {
        *earliestsock = sock;
        *earliesttime = current;
    }
}

static etsisocket_t *select_next_packet(etsithread_t *et)
{

    int i;
    etsisocket_t *esock = NULL;
    uint64_t earliest = 0;

    for (i = 0; i < et->sourcecount; i++) {
        inspect_next_packet(&(et->sources[i]), &esock, &earliest, et->etsidec,
                            et);
    }
    return esock;
}

static int etsilive_prepare_received(libtrace_t *libtrace,
                                     etsithread_t *et UNUSED,
                                     etsisocket_t *esock,
                                     libtrace_packet_t *packet)
{

    uint32_t available = 0;

    if (packet->buf_control == TRACE_CTRL_PACKET) {
        free(packet->buffer);
    }

    packet->trace = libtrace;
    packet->buffer = libtrace_scb_get_read(&(esock->recvbuffer), &available);
    packet->buf_control = TRACE_CTRL_EXTERNAL;
    packet->header = NULL; // Check this is ok to do
    packet->payload = packet->buffer;
    packet->type = TRACE_RT_DATA_ETSILI;
    packet->order = esock->cached.timestamp;
    packet->error = esock->cached.length;

    packet->cached.link_type = TRACE_TYPE_ETSILI;
    packet->cached.wire_length = esock->cached.length;
    packet->cached.capture_length = esock->cached.length;
    packet->fmtdata = &(esock->recvbuffer);

    /* Advance the read pointer for this buffer
     * TODO should really do this in fin_packet, but will need a ref
     * to esock to do this properly */
    libtrace_scb_advance_read(&(esock->recvbuffer), esock->cached.length);
    esock->cached.length = 0;
    esock->cached.timestamp = 0;

    return 1;
}

static int etsilive_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet)
{

    etsisocket_t *nextavail = NULL;
    int ret;

    while (1) {
        /* Read from sockets for any buffers that do not have
         * a complete packet */
        ret = receive_etsi_sockets(libtrace, &(FORMAT_DATA->receivers[0]));
        if (ret <= 0) {
            return ret;
        }

        nextavail = select_next_packet(&(FORMAT_DATA->receivers[0]));
        if (nextavail == NULL) {
            /* No complete packets available, take a short
             * break before trying again. */
            if (FORMAT_DATA->receivers[0].sourcecount == 0) {
                /* No sources yet, so we can wait a bit
                 * longer. */
                usleep(10000);
            } else {
                usleep(100);
            }
            continue;
        }
        break;
    }

    return etsilive_prepare_received(libtrace, &(FORMAT_DATA->receivers[0]),
                                     nextavail, packet);
}

static int etsilive_prepare_packet(libtrace_t *libtrace UNUSED,
                                   libtrace_packet_t *packet UNUSED,
                                   void *buffer UNUSED,
                                   libtrace_rt_types_t rt_type UNUSED,
                                   uint32_t flags UNUSED)
{
    return 0;
}

int etsilive_get_pdu_length(const libtrace_packet_t *packet)
{

    /* Should never get here because cache is set when packet is read */
    size_t reclen;
    libtrace_t *libtrace = packet->trace;
    wandder_etsispec_t *dec;

    if (!libtrace) {
        fprintf(stderr, "Packet is not associated with a trace in "
                        "etsilive_get_pdu_length()\n");
        return TRACE_ERR_NULL_TRACE;
    }
    /* Creating a decoder every time will be slow, but again we
     * should never get here anyway...
     */
    dec = wandder_create_etsili_decoder();

    /* 0 should be ok here for quickly evaluating the first length
     * field... */
    wandder_attach_etsili_buffer(dec, packet->buffer, 0, false);
    reclen = (size_t)wandder_etsili_get_pdu_length(dec);

    wandder_free_etsili_decoder(dec);
    return reclen;
}

int etsilive_get_framing_length(const libtrace_packet_t *packet UNUSED)
{

    return 0;
}

uint64_t etsilive_get_erf_timestamp(const libtrace_packet_t *packet)
{
    return packet->order;
}

static int etsilive_can_hold_packet(libtrace_packet_t *packet)
{
    int wlen = -1;

    /* Can hold the packet (temporarily) as long as a decent chunk of
     * our SCB is available.
     * SCB is only valid if the trace is not paused / halted...
     */
    if (!is_halted(packet->trace) && packet->fmtdata != NULL) {
        libtrace_scb_t *scb = (libtrace_scb_t *)packet->fmtdata;
        if (libtrace_scb_get_available_space(scb) > 0.25 * ETSI_RECVBUF_SIZE) {
            return 0;
        }
    }

    /* Otherwise, we have to copy but let's save our cached lengths
     * to avoid having to decode them from the record again...
     */
    wlen = packet->cached.wire_length;
    libtrace_make_packet_safe(packet);

    /* The copy will clear the cache, so we need to put the saved
     * lengths back in again.
     */
    packet->cached.wire_length = wlen;
    packet->cached.capture_length = wlen;
    return 0;
}

libtrace_linktype_t
etsilive_get_link_type(const libtrace_packet_t *packet UNUSED)
{
    return TRACE_TYPE_ETSILI;
}

static void etsilive_help(void)
{
    printf("etsilive format module: \n");
    printf("Supported input URIs:\n");
    printf("\etsilive:hostname:port\n");
    printf("\n");
    printf("\te.g.: etsilive:127.0.0.1:3004\n");
    printf("\n");
}


static struct libtrace_format_t etsilive = {
    "etsilive",
    "$Id$",
    TRACE_FORMAT_ETSILIVE,
    NULL,                        /* probe filename */
    NULL,                        /* probe magic */
    etsilive_init_input,         /* init_input */
    NULL,                        /* config_input */
    etsilive_start_input,        /* start_input */
    etsilive_pause_input,        /* pause */
    NULL,                        /* init_output */
    NULL,                        /* config_output */
    NULL,                        /* start_output */
    etsilive_fin_input,          /* fin_input */
    NULL,                        /* fin_output */
    etsilive_read_packet,        /* read_packet */
    etsilive_prepare_packet,     /* prepare_packet */
    NULL,                        /* fin_packet */
    etsilive_can_hold_packet,    /* can_hold_packet */
    NULL,                        /* write_packet */
    NULL,                        /* flush_output */
    etsilive_get_link_type,      /* get_link_type */
    NULL,                        /* get_direction */
    NULL,                        /* set_direction */
    etsilive_get_erf_timestamp,  /* get_erf_timestamp */
    NULL,                        /* get_timeval */
    NULL,                        /* get_timespec */
    NULL,                        /* get_seconds */
    NULL,                        /* get_meta_section */
    NULL,                        /* seek_erf */
    NULL,                        /* seek_timeval */
    NULL,                        /* seek_seconds */
    etsilive_get_pdu_length,     /* get_capture_length */
    etsilive_get_pdu_length,     /* get_wire_length */
    etsilive_get_framing_length, /* get_framing_length */
    NULL,                        /* set_capture_length */
    NULL,                        /* get_received_packets */
    NULL,                        /* get_filtered_packets */
    NULL,                        /* get_dropped_packets */
    NULL,                        /* get_statistics */
    NULL,                        /* get_fd */
    NULL,                        /* trace_event */
	etsilive_help,                        /* help */
    NULL,                        /* next pointer */
    NON_PARALLEL(true)           /* TODO this can be parallel */
};

void etsilive_constructor(void) { register_format(&etsilive); }

#define ENC_USEQUENCE(enc)                                                     \
    wandder_encode_next(enc, WANDDER_TAG_SEQUENCE,                             \
                        WANDDER_CLASS_UNIVERSAL_CONSTRUCT,                     \
                        WANDDER_TAG_SEQUENCE, NULL, 0)

#define ENC_CSEQUENCE(enc, x)                                                  \
    wandder_encode_next(enc, WANDDER_TAG_SEQUENCE,                             \
                        WANDDER_CLASS_CONTEXT_CONSTRUCT, x, NULL, 0)

#define LT_ETSI_LIID "none"
#define LT_ETSI_NA "NA"
#define LT_ETSI_OPERATOR "libtrace"

static int send_etsili_keepalive_response(int fd, int64_t seqno)
{

    wandder_encoder_t *encoder;
    wandder_encoded_result_t *tosend;
    int ret = 0;
    uint64_t zero = 0;
    struct timeval tv;

    encoder = init_wandder_encoder();

    ENC_USEQUENCE(encoder); // starts outermost sequence

    ENC_CSEQUENCE(encoder, 1);
    wandder_encode_next(
        encoder, WANDDER_TAG_OID, WANDDER_CLASS_CONTEXT_PRIMITIVE, 0,
        (void *)(WANDDER_ETSILI_PSDOMAINID), sizeof(WANDDER_ETSILI_PSDOMAINID));
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, LT_ETSI_LIID,
                        strlen(LT_ETSI_LIID));
    wandder_encode_next(encoder, WANDDER_TAG_PRINTABLE,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, LT_ETSI_NA,
                        strlen(LT_ETSI_NA));

    ENC_CSEQUENCE(encoder, 3);

    ENC_CSEQUENCE(encoder, 0);
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, LT_ETSI_OPERATOR,
                        strlen(LT_ETSI_OPERATOR));

    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, LT_ETSI_OPERATOR,
                        strlen(LT_ETSI_OPERATOR));
    wandder_encode_endseq(encoder);

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(zero),
                        sizeof(zero));
    wandder_encode_next(encoder, WANDDER_TAG_PRINTABLE,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, LT_ETSI_NA,
                        strlen(LT_ETSI_NA));
    wandder_encode_endseq(encoder);

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(seqno),
                        sizeof(seqno));

    gettimeofday(&tv, NULL);
    wandder_encode_next(encoder, WANDDER_TAG_GENERALTIME,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, 5, &tv,
                        sizeof(struct timeval));

    wandder_encode_endseq(encoder);

    ENC_CSEQUENCE(encoder, 2); // Payload
    ENC_CSEQUENCE(encoder, 2); // TRIPayload
    wandder_encode_next(encoder, WANDDER_TAG_NULL,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, NULL, 0);
    wandder_encode_endseq(encoder); // End TRIPayload
    wandder_encode_endseq(encoder); // End Payload
    wandder_encode_endseq(encoder); // End Outermost Sequence

    tosend = wandder_encode_finish(encoder);

    if (tosend != NULL) {
        /* Will block, but hopefully we shouldn't be doing much
         * sending.
         */
        ret = send(fd, tosend->encoded, tosend->len, 0);
    }

    wandder_release_encoded_result(encoder, tosend);
    free_wandder_encoder(encoder);
    return ret;
}
