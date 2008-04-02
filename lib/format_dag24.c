/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson
 *          Perry Lorier
 *          Shane Alcock
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
 * $Id$
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


static struct libtrace_format_t dag;

#define DATA(x) ((struct dag_format_data_t *)x->format_data)
#define DUCK DATA(libtrace)->duck
#define FORMAT_DATA DATA(libtrace)

struct dag_format_data_t {
	struct {
                uint32_t last_duck;
                uint32_t duck_freq;
                uint32_t last_pkt;
                libtrace_t *dummy_duck;
        } duck;	
	
	int fd;
	void *buf;
	uint32_t diff;
	uint32_t offset;
	uint32_t bottom;
	uint32_t top;
	uint64_t drops;
};

static void dag_init_format_data(libtrace_t *libtrace) {
	libtrace->format_data = (struct dag_format_data_t *)
		malloc(sizeof(struct dag_format_data_t));

	DUCK.last_duck = 0;
        DUCK.duck_freq = 0;
        DUCK.last_pkt = 0;
        DUCK.dummy_duck = NULL;
	FORMAT_DATA->drops = 0;
	FORMAT_DATA->top = 0;
	FORMAT_DATA->bottom = 0;
	FORMAT_DATA->buf = NULL;
	FORMAT_DATA->fd = -1;
	FORMAT_DATA->offset = 0;
	FORMAT_DATA->diff = 0;
}

static int dag_available(libtrace_t *libtrace) {

        if (FORMAT_DATA->diff > 0)
                return FORMAT_DATA->diff;

        FORMAT_DATA->bottom = FORMAT_DATA->top;
	FORMAT_DATA->top = dag_offset(
                        FORMAT_DATA->fd,
                        &(FORMAT_DATA->bottom),
                        DAGF_NONBLOCK);
	FORMAT_DATA->diff = FORMAT_DATA->top - FORMAT_DATA->bottom;
	FORMAT_DATA->offset = 0;
        return FORMAT_DATA->diff;
}

static int dag_init_input(libtrace_t *libtrace) {
	struct stat buf;
        char *dag_dev_name = NULL;
	char *scan = NULL;

	/* Since DAG 2.5 has been changed to support a slightly different URI
	 * format, it's probably a good idea to deal with URIs specified in
	 * such a fashion even if we just end up ignoring the stream number */
	if ((scan = strchr(libtrace->uridata,',')) == NULL) {
		dag_dev_name = strdup(libtrace->uridata);
	} else {
		dag_dev_name = (char *)strndup(libtrace->uridata,
				(size_t)(scan - libtrace->uridata));
	}

	
        if (stat(dag_dev_name, &buf) == -1) {
                trace_set_err(libtrace,errno,"stat(%s)",dag_dev_name);
		free(dag_dev_name);
                return -1;
        }
	
	dag_init_format_data(libtrace);
	if (S_ISCHR(buf.st_mode)) {
                /* DEVICE */
                if((FORMAT_DATA->fd = dag_open(dag_dev_name)) < 0) {
                        trace_set_err(libtrace,errno,"Cannot open DAG %s",
                                        dag_dev_name);
			free(dag_dev_name);
                        return -1;
                }
                if((FORMAT_DATA->buf = (void *)dag_mmap(FORMAT_DATA->fd)) == MAP_FAILED) {
                        trace_set_err(libtrace,errno,"Cannot mmap DAG %s",
                                        dag_dev_name);
			free(dag_dev_name);
                        return -1;
                }
        } else {
                trace_set_err(libtrace,errno,"Not a valid dag device: %s",
                                dag_dev_name);
		free(dag_dev_name);
                return -1;
        }

	free(dag_dev_name);

        return 0;
}

static int dag_config_input(libtrace_t *libtrace, trace_option_t option,
                                void *data) {
        switch(option) {
                case TRACE_OPTION_META_FREQ:
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
		case TRACE_OPTION_EVENT_REALTIME:
			return -1;
        }
	return -1;
}

static int dag_start_input(libtrace_t *libtrace) {	
	if(dag_start(FORMAT_DATA->fd) < 0) {
                trace_set_err(libtrace,errno,"Cannot start DAG %s",
                                libtrace->uridata);
                return -1;
        }

	/* Flush the memory hole */
	while(dag_available(libtrace) != 0)
		FORMAT_DATA->diff = 0;
	FORMAT_DATA->drops = 0;
	return 0;
}

static int dag_pause_input(libtrace_t *libtrace) {
	dag_stop(FORMAT_DATA->fd);
	return 0;
}

static int dag_fin_input(libtrace_t *libtrace) {
        dag_close(FORMAT_DATA->fd);
	if (DUCK.dummy_duck)
                trace_destroy_dead(DUCK.dummy_duck);
        free(libtrace->format_data);
        return 0; /* success */
}

static int dag_get_duckinfo(libtrace_t *libtrace,
                                libtrace_packet_t *packet) {
        dag_inf lt_dag_inf;

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

        if ((ioctl(FORMAT_DATA->fd, DAG_IOINF, &lt_dag_inf) < 0)) {
                trace_set_err(libtrace, errno,
                                "Error using DAG_IOINF");
                return -1;
        }
        if (!IsDUCK(&lt_dag_inf)) {
                printf("WARNING: %s does not have modern clock support - No DUCK information will be gathered\n", libtrace->uridata);
                return 0;
        }

        if ((ioctl(FORMAT_DATA->fd, DAG_IOGETDUCK, (duck_inf *)packet->payload)
                                < 0)) {
                trace_set_err(libtrace, errno, "Error using DAG_IOGETDUCK");
                return -1;
        }

        packet->type = TRACE_RT_DUCK_2_4;
        if (!DUCK.dummy_duck)
                DUCK.dummy_duck = trace_create_dead("duck:dummy");
        packet->trace = DUCK.dummy_duck;
        return sizeof(duck_inf);
}


static dag_record_t *dag_get_record(libtrace_t *libtrace) {
        dag_record_t *erfptr = NULL;
        uint16_t size;
	erfptr = (dag_record_t *) ((char *)FORMAT_DATA->buf + 
			(FORMAT_DATA->bottom + FORMAT_DATA->offset));

	if (!erfptr)
                return NULL;
        size = ntohs(erfptr->rlen);
        assert( size >= dag_record_size );
        FORMAT_DATA->offset += size;
        FORMAT_DATA->diff -= size;
        return erfptr;
}

static int dag_prepare_packet(libtrace_t *libtrace, libtrace_packet_t *packet,
		void *buffer, libtrace_rt_types_t rt_type, uint32_t flags) {

        dag_record_t *erfptr;
        if (packet->buffer != buffer &&
                        packet->buf_control == TRACE_CTRL_PACKET) {
                free(packet->buffer);
        }

	if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER) {
		packet->buf_control = TRACE_CTRL_PACKET;
	} else 
		packet->buf_control = TRACE_CTRL_EXTERNAL;
	
        erfptr = (dag_record_t *)buffer;
        packet->buffer = erfptr;
        packet->header = erfptr;
        packet->type = rt_type;

        if (erfptr->flags.rxerror == 1) {
                /* rxerror means the payload is corrupt - drop it
                 * by tweaking rlen */
                packet->payload = NULL;
                erfptr->rlen = htons(erf_get_framing_length(packet));
        } else {
                packet->payload = (char*)packet->buffer
                        + erf_get_framing_length(packet);
        }

        if (libtrace->format_data == NULL) {
                dag_init_format_data(libtrace);
        }

        DATA(libtrace)->drops += ntohs(erfptr->lctr);

        return 0;

}

static int dag_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
        int numbytes;
        int size = 0;
        uint32_t flags = 0;
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

	flags |= TRACE_PREP_DO_NOT_OWN_BUFFER;
	
        if (packet->buf_control == TRACE_CTRL_PACKET) {
                packet->buf_control = TRACE_CTRL_EXTERNAL;
                free(packet->buffer);
                packet->buffer = 0;
        }


        do {
                numbytes = dag_available(libtrace);
                if (numbytes < 0)
                        return numbytes;
                if (numbytes == 0)
                        continue;
                erfptr = dag_get_record(libtrace);
        } while (erfptr == NULL);
        
	
	if (dag_prepare_packet(libtrace, packet, erfptr, TRACE_RT_DATA_ERF, 
				flags))
		return -1;
	tv = trace_get_timeval(packet);
        DUCK.last_pkt = tv.tv_sec;
        return packet->payload ? htons(erfptr->rlen) : erf_get_framing_length(packet);
}

static libtrace_eventobj_t trace_event_dag(libtrace_t *trace,
                                        libtrace_packet_t *packet) {
        libtrace_eventobj_t event = {0,0,0.0,0};
        int data;

        data = dag_available(trace);
        if (data > 0) {
                event.size = dag_read_packet(trace,packet);
                //DATA(trace)->dag.diff -= event.size;
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
        assert(data == 0);
        event.type = TRACE_EVENT_SLEEP;
        event.seconds = 0.0001;
        return event;
}

static uint64_t dag_get_dropped_packets(libtrace_t *trace)
{
	if (!trace->format_data)
		return (uint64_t)-1;
	return DATA(trace)->drops;
}

static void dag_help(void) {
        printf("dag format module: $Revision$\n");
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
        "$Id$",
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
        dag_prepare_packet,		/* prepare_packet */
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
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	dag_get_dropped_packets,	/* get_dropped_packets */
	NULL,				/* get_captured_packets */
        NULL,                           /* get_fd */
        trace_event_dag,                /* trace_event */
        dag_help,                       /* help */
        NULL                            /* next pointer */
};

void dag_constructor(void) {
	register_format(&dag);
}
