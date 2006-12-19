/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson
 *          Perry Lorier
 *	    Shane Alcock
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
 * $Id: format_dag25.c 1 2006-12-14 21:13:09Z spa1 $
 *
 */
#define _GNU_SOURCE

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
#include <stdlib.h>

#include <sys/mman.h>

#ifdef WIN32
#  include <io.h>
#  include <share.h>
#  define PATH_MAX _MAX_PATH
#  define snprintf sprintf_s
#else
#  include <netdb.h>
#  ifndef PATH_MAX
#       define PATH_MAX 4096
#  endif
#  include <sys/ioctl.h>
#endif

#define DATA(x) ((struct dag_format_data_t *)x->format_data)
#define FORMAT_DATA DATA(libtrace)
#define DUCK FORMAT_DATA->duck
static struct libtrace_format_t dag;

struct dag_format_data_t {
	struct {
		uint32_t last_duck;
                uint32_t duck_freq;
                uint32_t last_pkt;
                libtrace_t *dummy_duck;
        } duck;

	int fd;
	unsigned int dagstream;
};

static int dag_init_input(libtrace_t *libtrace) {
	struct stat buf;
        libtrace->format_data = (struct dag_format_data_t *)
                malloc(sizeof(struct dag_format_data_t));
        if (stat(libtrace->uridata, &buf) == -1) {
                trace_set_err(libtrace,errno,"stat(%s)",libtrace->uridata);
                return -1;
        }

	/* For now, we don't offer the ability to select the stream */
	FORMAT_DATA->dagstream = 0;

	if (S_ISCHR(buf.st_mode)) {
		if((FORMAT_DATA->fd = dag_open(libtrace->uridata)) < 0) {
                        trace_set_err(libtrace,errno,"Cannot open DAG %s",
                                        libtrace->uridata);
                        return -1;
                }
	} else {
		trace_set_err(libtrace,errno,"Not a valid dag device: %s",
                                libtrace->uridata);
                return -1;
        }

	DUCK.last_duck = 0;
        DUCK.duck_freq = 0;
        DUCK.last_pkt = 0;
        DUCK.dummy_duck = NULL;

        return 0;
}
	
static int dag_config_input(libtrace_t *libtrace, trace_option_t option,
                                void *data) {
        switch(option) {
                case TRACE_META_FREQ:
                        DUCK.duck_freq = *(int *)data;
                        return 0;
                case TRACE_OPTION_SNAPLEN:
                        /* Surely we can set this?? Fall through for now*/
                        return -1;
                case TRACE_OPTION_PROMISC:
                        /* DAG already operates in a promisc fashion */
                        return -1;
                case TRACE_OPTION_FILTER:
                        return -1;
                default:
                        trace_set_err(libtrace, TRACE_ERR_UNKNOWN_OPTION,
                                        "Unknown or unsupported option: %i",
                                        option);
                        return -1;
        }
        assert (0);
}

static int dag_start_input(libtrace_t *libtrace) {
        struct timeval zero, nopoll;
        uint8_t *top, *bottom;
	uint8_t diff = 0;
	top = bottom = NULL;

	zero.tv_sec = 0;
        zero.tv_usec = 0;
        nopoll = zero;


	
	if (dag_attach_stream(FORMAT_DATA->fd, 
				FORMAT_DATA->dagstream, 0, 0) < 0) {
                trace_set_err(libtrace, errno, "Cannot attach DAG stream");
                return -1;
        }

	if (dag_start_stream(FORMAT_DATA->fd, 
				FORMAT_DATA->dagstream) < 0) {
                trace_set_err(libtrace, errno, "Cannot start DAG stream");
                return -1;
        }
	/* We don't want the dag card to do any sleeping */
        dag_set_stream_poll(FORMAT_DATA->fd, 
				FORMAT_DATA->dagstream, 0, &zero, 
				&nopoll);
	
	/* Should probably flush the memory hole now */
	do {
		top = dag_advance_stream(FORMAT_DATA->fd,
					FORMAT_DATA->dagstream,
					&bottom);
		assert(top && bottom);
		diff = top - bottom;
	} while (diff != 0);

	return 0;
}

static int dag_pause_input(libtrace_t *libtrace) {
	if (dag_stop_stream(FORMAT_DATA->fd, 
				FORMAT_DATA->dagstream) < 0) {
                trace_set_err(libtrace, errno, "Could not stop DAG stream");
                return -1;
        }
        if (dag_detach_stream(FORMAT_DATA->fd, 
				FORMAT_DATA->dagstream) < 0) {
                trace_set_err(libtrace, errno, "Could not detach DAG stream");
                return -1;
	}

	return 0;
}

static int dag_fin_input(libtrace_t *libtrace) {
	if (DUCK.dummy_duck)
		trace_destroy_dead(DUCK.dummy_duck);
	free(libtrace->format_data);
        return 0; /* success */
}

static int dag_get_duckinfo(libtrace_t *libtrace,
                                libtrace_packet_t *packet) {
        daginf_t lt_dag_inf;

        if (packet->buf_control == TRACE_CTRL_EXTERNAL ||
                        !packet->buffer) {
                packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
                packet->buf_control = TRACE_CTRL_PACKET;
                if (!packet->buffer) {
                        trace_set_err(libtrace, errno,
                                        "Cannot allocate packet buffer");
                        return -1;
                }
        }

        packet->header = 0;
        packet->payload = packet->buffer;

        /* No need to check if we can get DUCK or not - we're modern
         * enough */
        if ((ioctl(FORMAT_DATA->fd, DAGIOCDUCK, (duckinf_t *)packet->payload)
                                < 0)) {
                trace_set_err(libtrace, errno, "Error using DAGIOCDUCK");
                return -1;
        }

        packet->type = TRACE_RT_DUCK_2_5;
        if (!DUCK.dummy_duck)
                DUCK.dummy_duck = trace_create_dead("rt:localhost:3434");
        packet->trace = DUCK.dummy_duck;
        return sizeof(duckinf_t);
}

dag_record_t *dag_get_record(libtrace_t *libtrace) {
        dag_record_t *erfptr = NULL;
        uint16_t size;
	erfptr = (dag_record_t *) dag_rx_stream_next_record(FORMAT_DATA->fd,
                        FORMAT_DATA->dagstream);
	if (!erfptr)
                return NULL;
        size = ntohs(erfptr->rlen);
        assert( size >= dag_record_size );
	return erfptr;
}

void dag_form_packet(dag_record_t *erfptr, libtrace_packet_t *packet) {
        packet->buffer = erfptr;
        packet->header = erfptr;
        if (erfptr->flags.rxerror == 1) {
                /* rxerror means the payload is corrupt - drop it
                 * by tweaking rlen */
                packet->payload = NULL;
                erfptr->rlen = htons(erf_get_framing_length(packet));
        } else {
                packet->payload = (char*)packet->buffer
                        + erf_get_framing_length(packet);
        }

}


static int dag_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
        int size = 0;
        struct timeval tv;
        dag_record_t *erfptr = NULL;

        if (DUCK.last_pkt - DUCK.last_duck > DUCK.duck_freq &&
                        DUCK.duck_freq != 0) {
                size = dag_get_duckinfo(libtrace, packet);
                DUCK.last_duck = DUCK.last_pkt;
                if (size != 0) {
                        return size;
                }
                /* No DUCK support, so don't waste our time anymore */
                DUCK.duck_freq = 0;
        }

        if (packet->buf_control == TRACE_CTRL_PACKET) {
                packet->buf_control = TRACE_CTRL_EXTERNAL;
                free(packet->buffer);
                packet->buffer = 0;
        }

        packet->type = TRACE_RT_DATA_ERF;

	do {
		erfptr = dag_get_record(libtrace);
	} while (erfptr == NULL);

	dag_form_packet(erfptr, packet);
	tv = trace_get_timeval(packet);
        DUCK.last_pkt = tv.tv_sec;
	return packet->payload ? htons(erfptr->rlen) : 
				erf_get_framing_length(packet);
}

static libtrace_eventobj_t trace_event_dag(libtrace_t *trace,
                                        libtrace_packet_t *packet) {
        libtrace_eventobj_t event = {0,0,0.0,0};
	dag_record_t *erfptr = NULL;
	
	erfptr = dag_get_record(trace);
	if (erfptr == NULL) {
		/* No packet available */
		event.type = TRACE_EVENT_SLEEP;
		event.seconds = 0.0001;
		return event;
	}
	dag_form_packet(erfptr, packet);
	event.size = trace_get_capture_length(packet) + trace_get_framing_length(packet);
	if (trace->filter) {
		if (trace_apply_filter(trace->filter, packet)) {
			event.type = TRACE_EVENT_PACKET;
		} else {
			event.type = TRACE_EVENT_SLEEP;
                        event.seconds = 0.000001;
                        return event;
		}
	} else {
		event.type = TRACE_EVENT_PACKET;
	}

	if (trace->snaplen > 0) {
		trace_set_capture_length(packet, trace->snaplen);
	}

	return event;
}


static void dag_help(void) {
        printf("dag format module: $Revision: 1110 $\n");
        printf("Supported input URIs:\n");
        printf("\tdag:/dev/dagn\n");
        printf("\n");
        printf("\te.g.: dag:/dev/dag0\n");
        printf("\n");
        printf("Supported output URIs:\n");
        printf("\tnone\n");
        printf("\n");
}

static struct libtrace_format_t dag = {
        "dag",
        "$Id: format_dag25.c 0 2006-12-14 21:13:09Z spa1 $",
        TRACE_FORMAT_ERF,
        dag_init_input,                 /* init_input */
        dag_config_input,               /* config_input */
        dag_start_input,                /* start_input */
        dag_pause_input,                /* pause_input */
        NULL,                           /* init_output */
        NULL,                           /* config_output */
        NULL,                           /* start_output */
        dag_fin_input,                  /* fin_input */
        NULL,                           /* fin_output */
        dag_read_packet,                /* read_packet */
        NULL,                           /* fin_packet */
        NULL,                           /* write_packet */
        erf_get_link_type,              /* get_link_type */
        erf_get_direction,              /* get_direction */
        erf_set_direction,              /* set_direction */
        erf_get_erf_timestamp,          /* get_erf_timestamp */
        NULL,                           /* get_timeval */
        NULL,                           /* get_seconds */
        NULL,                           /* seek_erf */
        NULL,                           /* seek_timeval */
        NULL,                           /* seek_seconds */
        erf_get_capture_length,         /* get_capture_length */
        erf_get_wire_length,            /* get_wire_length */
        erf_get_framing_length,         /* get_framing_length */
        erf_set_capture_length,         /* set_capture_length */
        NULL,                           /* get_fd */
        trace_event_dag,                /* trace_event */
        dag_help,                       /* help */
        NULL                            /* next pointer */
};

void dag_constructor(void) {
	register_format(&dag);
}
