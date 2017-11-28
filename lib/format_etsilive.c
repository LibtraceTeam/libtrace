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

#define _GNU_SOURCE

#include "config.h"
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "data-struct/simple_circular_buffer.h"

#include "etsiasn1tab.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libtasn1.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#define ETSI_RECVBUF_SIZE (64 * 1024 * 1024)

#define FORMAT_DATA ((etsilive_format_data_t *)libtrace->format_data)

typedef struct etsipktcache {

        uint64_t timestamp;
        uint8_t *ccptr;
        uint8_t *iriptr;
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
        int threadindex;
} etsithread_t;

typedef struct etsilive_format_data {
	char *listenport;
	char *listenaddr;

        pthread_t listenthread;
        etsithread_t *receivers;
        int nextthreadid;
        ASN1_TYPE etsidef;
} etsilive_format_data_t;

typedef struct newsendermessage {
        int recvsock;
        struct sockaddr *recvaddr;
} newsend_message_t;


static void *etsi_listener(void *tdata) {
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

        if (getaddrinfo(FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
                        &hints, &listenai) != 0) {
                fprintf(stderr,
                        "Call to getaddrinfo failed for %s:%s -- %s\n",
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

        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))
                        < 0) {

                fprintf(stderr, "Failed to configure socket for %s:%s -- %s\n",
                        FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
                        strerror(errno));

                goto listenerror;
        }

        if (bind(sock, (struct sockaddr *)listenai->ai_addr,
                        listenai->ai_addrlen) < 0) {

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

        /* TODO consider possibility of pausing and resuming? */
        while ((is_halted(libtrace) == -1)) {
                newsend_message_t msg;
                etsithread_t *et;

                /* accept */
                connected = (struct sockaddr_storage *)malloc(sizeof(struct
                                sockaddr_storage));
                addrsize = sizeof(struct sockaddr_storage);
                consock = accept(sock, (struct sockaddr *)connected,
                                &addrsize);
                if (consock < 0) {
                        fprintf(stderr, "Failed to accept connection on socket for %s:%s -- %s\n",
                                FORMAT_DATA->listenaddr,
                                FORMAT_DATA->listenport,
                                strerror(errno));
                        free(connected);
                        goto listenerror;
                }

                /* if successful, send consock to next available thread */
                msg.recvsock = consock;
                msg.recvaddr = (struct sockaddr *)connected;
                et = &(FORMAT_DATA->receivers[FORMAT_DATA->nextthreadid]);
                libtrace_message_queue_put(&(et->mqueue), (void *)&msg);

                if (libtrace->perpkt_thread_count > 0) {
                        FORMAT_DATA->nextthreadid =
                                ((FORMAT_DATA->nextthreadid + 1) %
                                libtrace->perpkt_thread_count);
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



static int etsilive_init_input(libtrace_t *libtrace) {
        char *scan = NULL;
        char errordesc[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

        libtrace->format_data = (etsilive_format_data_t *)malloc(
                        sizeof(etsilive_format_data_t));

        FORMAT_DATA->receivers = NULL;
        FORMAT_DATA->nextthreadid = 0;
        FORMAT_DATA->listenaddr = NULL;

        /* TODO is there a sensible default port number? */
        scan = strchr(libtrace->uridata, ':');
        if (scan == NULL) {
                trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT,
                        "Bad etsilive URI. Should be etsilive:<listenaddr>:<port number>");
                return -1;
        }
        FORMAT_DATA->listenaddr = strndup(libtrace->uridata,
                        (size_t)(scan - libtrace->uridata));
        FORMAT_DATA->listenport = strdup(scan + 1);

        if (asn1_array2tree(etsili_asn1tab, &(FORMAT_DATA->etsidef),
                                errordesc) != ASN1_SUCCESS) {
                trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT,
                        "Failed to parse ETSI ASN.1 array: %s", errordesc);
                return -1;
        }

        return 0;
}

static int etsilive_fin_input(libtrace_t *libtrace) {
        if (FORMAT_DATA->receivers) {
                free(FORMAT_DATA->receivers);
        }

        if (FORMAT_DATA->listenaddr) {
                free(FORMAT_DATA->listenaddr);
        }
        if (FORMAT_DATA->listenport) {
                free(FORMAT_DATA->listenport);
        }
        asn1_delete_structure(&(FORMAT_DATA->etsidef));
        free(libtrace->format_data);
        return 0;
}

static int etsilive_start_threads(libtrace_t *libtrace, uint32_t maxthreads) {
	int ret;
        uint32_t i;
        /* Configure the set of receiver threads */

        if (FORMAT_DATA->receivers == NULL) {
                /* What if the number of threads changes between a pause and
                 * a restart? Can this happen? */
                FORMAT_DATA->receivers = (etsithread_t *)
                                malloc(sizeof(etsithread_t) * maxthreads);
        }

        for (i = 0; i < maxthreads; i++) {

                libtrace_message_queue_init(&(FORMAT_DATA->receivers[i].mqueue),
                                sizeof(newsend_message_t));

                FORMAT_DATA->receivers[i].sources = NULL;
                FORMAT_DATA->receivers[i].sourcecount = 0;
                FORMAT_DATA->receivers[i].threadindex = i;

        }

        /* Start the listening thread */
        /* TODO consider affinity of this thread? */

        ret = pthread_create(&(FORMAT_DATA->listenthread), NULL,
                        etsi_listener, libtrace);
        if (ret != 0) {
                return -1;
        }
        return maxthreads;
}

static int etsilive_start_input(libtrace_t *libtrace) {
        return etsilive_start_threads(libtrace, 1);
}

static void halt_etsi_thread(etsithread_t *receiver) {
        int i;
        libtrace_message_queue_destroy(&(receiver->mqueue));
        if (receiver->sources == NULL)
                return;
        for (i = 0; i < receiver->sourcecount; i++) {
                etsisocket_t src = receiver->sources[i];
                libtrace_scb_destroy(&(src.recvbuffer));
                close(src.sock);
        }
        free(receiver->sources);
}

static int etsilive_pause_input(libtrace_t *libtrace) {

        int i;
        for (i = 0; i < libtrace->perpkt_thread_count; i++) {
                halt_etsi_thread(&(FORMAT_DATA->receivers[i]));
        }
        return 0;

}

static int receiver_read_message(etsithread_t *et) {
        newsend_message_t msg;

        while (libtrace_message_queue_try_get(&(et->mqueue), (void *)&msg)
                        != LIBTRACE_MQ_FAILED) {
                etsisocket_t *esock = NULL;

                if (et->sourcecount == 0) {
                        et->sources = (etsisocket_t *)malloc(
                                        sizeof(etsisocket_t) * 10);
                } else if ((et->sourcecount % 10) == 0) {
                        et->sources = (etsisocket_t *)realloc(et->sources,
                                sizeof(etsisocket_t) * (et->sourcecount + 10));
                }

                esock = &(et->sources[et->sourcecount]);
                esock->sock = msg.recvsock;
                esock->srcaddr = msg.recvaddr;
                libtrace_scb_init(&(esock->recvbuffer), ETSI_RECVBUF_SIZE,
                                et->threadindex);
                esock->cached.timestamp = 0;
                esock->cached.length = 0;
                esock->cached.iriptr = NULL;
                esock->cached.ccptr = NULL;

                et->sourcecount += 1;

                fprintf(stderr, "Thread %d is now handling %u sources.\n",
                                et->threadindex, et->sourcecount);
        }
        return 1;
}

static void receive_from_single_socket(etsisocket_t *esock) {

        int ret = 0;

        if (esock->sock == -1) {
                return;
        }

        ret = libtrace_scb_recv_sock(&(esock->recvbuffer), esock->sock,
                        MSG_DONTWAIT);
        if (ret == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        /* Would have blocked, nothing available */
                        return;
                }
                fprintf(stderr, "Error receiving on socket %d: %s\n",
                                esock->sock, strerror(errno));
                close(esock->sock);
                esock->sock = -1;
        }

        if (ret == 0) {
                fprintf(stderr, "Socket %d has disconnected\n", esock->sock);
                close(esock->sock);
                esock->sock = -1;
        }

}

static int receive_etsi_sockets(libtrace_t *libtrace, etsithread_t *et) {

        int iserr = 0;
        int i;

        if ((iserr = is_halted(libtrace)) != -1) {
                return iserr;
        }

        iserr = receiver_read_message(et);
        if (iserr <= 0) {
                return iserr;
        }

        if (et->sourcecount == 0) {
                return 1;
        }

        for (i = 0; i < et->sourcecount; i++) {
                receive_from_single_socket(&(et->sources[i]));
        }
        return 1;

}

static etsisocket_t *select_next_packet(etsithread_t *et, libtrace_t *libtrace) {

        int i, asnret;
        etsisocket_t *esock = NULL;
        char errordesc[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
        char readstring[100];
        uint64_t earliest = 0;
        uint64_t currentts = 0;
        uint32_t available;
        uint8_t *ptr = NULL;
        ASN1_TYPE psheader;
        int ider_len;
        int readlen;

        for (i = 0; i < et->sourcecount; i++) {
                if (et->sources[i].sock == -1) {
                        continue;
                }
                /* Have we already successfully decoded this? Cool,
                 * just use whatever we cached last time.
                 */
                if (et->sources[i].cached.timestamp != 0) {
                        currentts = et->sources[i].cached.timestamp;

                        if (earliest == 0 || earliest > currentts) {
                                earliest = currentts;
                                esock = &(et->sources[i]);
                        }
                        continue;
                }

                ptr = libtrace_scb_get_read(&(et->sources[i].recvbuffer),
                                &available);

                if (available == 0) {
                        continue;
                }

                /* Try to decode whatever is at the front of the buffer. */
                asnret = asn1_create_element(FORMAT_DATA->etsidef,
                                "LI-PS-PDU.PSHeader", &psheader);
                if (asnret != ASN1_SUCCESS) {
                        fprintf(stderr, "failed to create asn1 element\n");
                        asn1_delete_structure(&psheader);
                        continue;
                }

                ider_len = (int)available;
                asnret = asn1_der_decoding2(&psheader, ptr, &ider_len, 0, errordesc);

                /* Failed? Must not have the whole packet... */
                if (asnret != ASN1_SUCCESS) {
                        int j;
                        for (j = 0; j < available; j++) {
                                printf("%02x ", ptr[j]);
                                if (j % 16 == 15 && j > 0) {
                                        printf("\n");
                                }
                                if (j >= 16 * 16)
                                        break;
                        }
                        fprintf(stderr, "%d failed to decode asn1 content: %s\n",
                                        available, errordesc);
                        assert(0);
                        asn1_delete_structure(&psheader);
                        continue;
                }

                readlen = sizeof(readstring);
                asnret = asn1_read_value(psheader, "timeStamp", readstring, &readlen);

                if (asnret == ASN1_SUCCESS) {
                        fprintf(stderr, "timeStamp=%s\n", readstring);
                        /* TODO turn to 64 bit timestamp */
                } else {
                        int msts_sec;
                        int msts_ms;

                        readlen = sizeof(int);
                        asnret = asn1_read_value(psheader, "microSecondTimeStamp.seconds", &msts_sec, &readlen);

                        if (asnret != ASN1_SUCCESS) {
                                fprintf(stderr, "no microSecondTimeStamp.seconds\n");
                                continue;
                        }

                        readlen = sizeof(int);
                        asnret = asn1_read_value(psheader, "microSecondTimeStamp.microSeconds", &msts_ms, &readlen);

                        if (asnret != ASN1_SUCCESS) {
                                fprintf(stderr, "no microSecondTimeStamp.microSeconds?\n");
                                continue;
                        }
                        fprintf(stderr, "microSecondTimeStamp=%d.%d\n", msts_sec, msts_ms);
                }
                assert(0);
                /* Success, cache everything we used so we don't have to
                 * decode this packet again.
                 */

                /* Advance the read pointer for this buffer */

                /* Don't forget to update earliest and esock... */

        }
        return esock;
}

static int etsilive_prepare_received(libtrace_t *libtrace, etsithread_t *et,
                etsisocket_t *esock, libtrace_packet_t *packet) {
        return 1;
}


static int etsilive_read_packet(libtrace_t *libtrace,
                libtrace_packet_t *packet) {

        etsisocket_t *nextavail = NULL;
        int ret;

        while (1) {
                /* Read from sockets for any buffers that do not have
                 * a complete packet */
                ret = receive_etsi_sockets(libtrace,
                                &(FORMAT_DATA->receivers[0]));
                if (ret <= 0) {
                        return ret;
                }

                nextavail = select_next_packet(&(FORMAT_DATA->receivers[0]),
                                libtrace);
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

        return etsilive_prepare_received(libtrace,
                        &(FORMAT_DATA->receivers[0]), nextavail,
                        packet);
}

static int etsilive_prepare_packet(libtrace_t *libtrace UNUSED,
                libtrace_packet_t *packet UNUSED,
                void *buffer UNUSED, libtrace_rt_types_t rt_type UNUSED,
                uint32_t flags UNUSED) {
        return 0;
}




static struct libtrace_format_t etsilive = {
        "etsilive",
        "$Id$",
        TRACE_FORMAT_ETSILIVE,
        NULL,                           /* probe filename */
        NULL,                           /* probe magic */
        etsilive_init_input,            /* init_input */
        NULL,                           /* config_input */
        etsilive_start_input,           /* staetsilive_input */
        etsilive_pause_input,           /* pause */
        NULL,                           /* init_output */
        NULL,                           /* config_output */
        NULL,                           /* staetsilive_output */
        etsilive_fin_input,             /* fin_input */
        NULL,                           /* fin_output */
        etsilive_read_packet,           /* read_packet */
        etsilive_prepare_packet,        /* prepare_packet */
        NULL,                           /* fin_packet */
        NULL,                           /* write_packet */
        NULL, //etsilive_get_link_type,         /* get_link_type */
        NULL,                           /* get_direction */
        NULL,                           /* set_direction */
        NULL,                           /* get_erf_timestamp */
        NULL,                           /* get_timeval */
        NULL,                           /* get_timespec */
        NULL,                           /* get_seconds */
        NULL,                           /* seek_erf */
        NULL,                           /* seek_timeval */
        NULL,                           /* seek_seconds */
        NULL, //etsilive_get_capture_length,    /* get_capture_length */
        NULL, //etsilive_get_wire_length,       /* get_wire_length */
        NULL, //etsilive_get_framing_length,    /* get_framing_length */
        NULL,                           /* set_capture_length */
        NULL,                           /* get_received_packets */
        NULL,                           /* get_filtered_packets */
        NULL,                           /* get_dropped_packets */
        NULL,                           /* get_statistics */
        NULL,                           /* get_fd */
        NULL, //trace_event_etsilive,           /* trace_event */
        NULL,                           /* help */
        NULL,                           /* next pointer */
        NON_PARALLEL(true)              /* TODO this can be parallel */
};


void etsilive_constructor(void) {
        register_format(&etsilive);
}
