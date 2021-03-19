/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
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
#include "config.h"
#include <sys/types.h>
#include <fcntl.h> /* for O_LARGEFILE */
#include <math.h>
#include "libtrace.h"
#include "libtrace_int.h"
#include "wandio.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "format_helper.h"
#include <unistd.h>
#ifndef _SC_NPROCESSORS_ONLN
#include <sys/param.h>
#include <sys/sysctl.h>
#endif

#include <stdarg.h>

#ifdef WIN32
#  include <io.h>
#  include <share.h>
#  include <sys/timeb.h>

struct libtrace_eventobj_t trace_event_device(struct libtrace_t *trace, struct libtrace_packet_t *packet) {
    struct libtrace_eventobj_t event = {0,0,0.0,0};

    trace_set_err(trace,TRACE_ERR_OPTION_UNAVAIL, "trace_event() is not "
            "supported on devices under windows in this version");

    event.type = TRACE_EVENT_TERMINATE;
    return event;
}
#else
#  include <sys/ioctl.h>

/* Generic event function for live capture devices / interfaces */
struct libtrace_eventobj_t trace_event_device(struct libtrace_t *trace, 
					struct libtrace_packet_t *packet) {
	struct libtrace_eventobj_t event = {0,0,0.0,0};

	fd_set rfds, rfds_param;
	int ret;
	int max_fd;
	struct timeval tv;

	if (!trace) {
		fprintf(stderr, "NULL trace passed into trace_event_device()\n");
		event.type = TRACE_EVENT_TERMINATE;
		return event;
	}
	if (!packet) {
		trace_set_err(trace, TRACE_ERR_NULL_PACKET, "NULL packet passed into trace_event_device()");
		event.type = TRACE_EVENT_TERMINATE;
		return event;
	}

	FD_ZERO(&rfds);
	FD_ZERO(&rfds_param);

	if (trace->format->get_fd) {
		event.fd = trace->format->get_fd(trace);
		FD_SET(event.fd, &rfds);
		max_fd = event.fd;
	} else {
		event.fd = 0;
		max_fd = -1;
	}

	/* Use select() to perform a quick poll to check that there is data
	 * available - we used to use FIONREAD here but that does not work
	 * for mmapped pcap sockets. As recent pcap on linux (e.g. Ubuntu 9.04)
	 * uses mmapped sockets by default, I've switched over to this 
	 * solution. */

        do {
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		rfds_param = rfds;

		ret = select(max_fd + 1, &rfds_param, NULL, NULL, &tv);
		if (ret == -1 && errno != EINTR) {
			event.type = TRACE_EVENT_TERMINATE;
			return event;
		}
	} while (ret == -1);

	if (FD_ISSET(event.fd, &rfds_param)) {
                event.size = trace_read_packet(trace,packet);
		if (event.size < 1) {
			/* Covers error and EOF events - terminate rather 
			 * than report a packet as available */
			if (trace_is_err(trace)) {
				trace_perror(trace, "read packet");
			}
			event.type = TRACE_EVENT_TERMINATE;
		} else {

			event.type = TRACE_EVENT_PACKET;
		}
		return event;
	}
	event.type= TRACE_EVENT_IOWAIT;
	return event;
}
#endif

/* Generic event function for trace files */ 
struct libtrace_eventobj_t trace_event_trace(struct libtrace_t *trace, struct libtrace_packet_t *packet) {
	struct libtrace_eventobj_t event = {0,0,0.0,0};
	double ts;
	double now;
        double sincebeginnow = 0;
        double sincebegintrace = 0;

#ifdef WIN32
	struct __timeb64 tstruct;
#else
	struct timeval stv;
#endif

	if (!trace->event.packet) {
		trace->event.packet = trace_create_packet();
	}

	if (!trace->event.waiting) {
		/* There is no packet event waiting for us, so create a new
		 * libtrace packet in the event structure and read the next
		 * packet into that.
		 *
		 * If a SLEEP event is reported this time around, the read
		 * packet can therefore be saved until the next time this
		 * function is called. */

		trace->event.psize=
			trace_read_packet(trace,trace->event.packet);
		if (trace->event.psize<1) {
			/* Return here, the test for event.size will sort out 
			 * the error  */
			if (trace_is_err(trace)) {
				trace_perror(trace, "read packet");
			}
			event.type = TRACE_EVENT_TERMINATE;
			trace_destroy_packet(trace->event.packet);
			trace->event.packet = NULL;
			packet->buffer = NULL;
			packet->header = NULL;
			packet->payload = NULL;
			packet->buf_control = TRACE_CTRL_EXTERNAL;
			return event;
		}
	}

	/* The goal here is to replicate the inter-packet gaps that are
	 * present in the trace. */

	ts=trace_get_seconds(trace->event.packet);

	/* Get the current walltime */
#ifdef WIN32
	_ftime64(&tstruct);
	now = tstruct.time + 
		((double)tstruct.millitm / 1000.0);
#else
	gettimeofday(&stv, NULL);
	now = stv.tv_sec + 
		((double)stv.tv_usec / 1000000.0);
#endif

	
	if (fabs(trace->event.first_ts)>1e-9) {
		/* Subtract the tdelta from the starting times to get a suitable
		 * "relative" time */
                sincebeginnow = (now - trace->event.first_now);
                sincebegintrace = (ts - trace->event.first_ts);

		/* If the trace timestamp is still in the future, return a 
		 * SLEEP event, otherwise return the packet */
                if (sincebeginnow <= sincebegintrace / (double)trace->replayspeedup) {
			event.seconds = ((sincebegintrace / (double)trace->replayspeedup) - sincebeginnow);
			event.type = TRACE_EVENT_SLEEP;
			trace->event.waiting = true;
			return event;
		}
	} else {
		/* Work out the difference between the walltime at the start 
		 * of the trace replay and the timestamp of the first packet 
		 * in the trace. This will be used to convert the walltime
		 * into a timeline that is relative to the timestamps in the
		 * trace file.
		 */
                trace->event.first_now = (double)now;
                trace->event.first_ts = (double)ts;
	}

	/* The packet that we had read earlier is now ready to be returned
	 * to the user - switch all the pointers etc. over */	
	packet->type = trace->event.packet->type;
	packet->trace = trace->event.packet->trace;
	packet->header = trace->event.packet->header;
	packet->payload = trace->event.packet->payload;
	
	packet->buffer = trace->event.packet->buffer;
	packet->buf_control = trace->event.packet->buf_control;

        packet->which_trace_start = trace->event.packet->which_trace_start;

	event.type = TRACE_EVENT_PACKET;

	trace->event.waiting = false;

	return event;
}

/* Catch undefined O_LARGEFILE on *BSD etc */
#ifndef O_LARGEFILE
#  define O_LARGEFILE 0
#endif 

/* Catching O_BINARY on all sane OS's */
#ifndef O_BINARY
#  define O_BINARY 0
#endif

/* Open a file for reading using the new Libtrace IO system */
io_t *trace_open_file(libtrace_t *trace)
{
	io_t *io=wandio_create(trace->uridata);

	if (!io) {
		if (errno != 0) {
			trace_set_err(trace,errno,"Unable to open %s",trace->uridata);
		} else {
			trace_set_err(trace,TRACE_ERR_UNSUPPORTED_COMPRESS,"Unsupported compression error: %s", trace->uridata);
		}
	}
	return io;
}

/* Open a file for writing using the new Libtrace IO system */ 
iow_t *trace_open_file_out(libtrace_out_t *trace, int compress_type, int level, int fileflag)
{
	iow_t *io = NULL;

        if (level < 0 || level > 9) {
                trace_set_err_out(trace, TRACE_ERR_UNSUPPORTED_COMPRESS, 
                                "Compression level %d is invalid, must be between 0 and 9 inclusive", 
                                level);
                return NULL;
        }

        if (compress_type < 0 || 
                        compress_type >= TRACE_OPTION_COMPRESSTYPE_LAST) {
                trace_set_err_out(trace, TRACE_ERR_UNSUPPORTED_COMPRESS,
                                "Invalid compression type %d", compress_type);
                return NULL;
        }

	io = wandio_wcreate(trace->uridata, compress_type, level, fileflag);

	if (!io) {
		trace_set_err_out(trace, errno, "Unable to create output file %s", trace->uridata);
	}
	return io;
}


/** Sets the error status for an input trace
 * @param errcode either an Econstant from libc, or a LIBTRACE_ERROR
 * @param msg a plaintext error message
 * @internal
 */
void trace_set_err(libtrace_t *trace,int errcode,const char *msg,...)
{
	char buf[256];
	va_list va;
	va_start(va,msg);

	if (errcode == 0) {
		fprintf(stderr, "An error occurred, but it is unknown what it is");
		return;
	}

	trace->err.err_num=errcode;
	if (errcode>0) {
		vsnprintf(buf,sizeof(buf),msg,va);
		snprintf(trace->err.problem,sizeof(trace->err.problem),
				"%s: %s",buf,strerror(errcode));
	} else {
		vsnprintf(trace->err.problem,sizeof(trace->err.problem),
				msg,va);
	}
	va_end(va);
}

/** Sets the error status for an output trace
 * @param errcode either an Econstant from libc, or a LIBTRACE_ERROR
 * @param msg a plaintext error message
 * @internal
 */
void trace_set_err_out(libtrace_out_t *trace,int errcode,const char *msg,...)
{
	char buf[256];
	va_list va;
	va_start(va,msg);
	if (errcode == 0) {
		fprintf(stderr, "An error occurred, but is is unknown what is is");
		return;
	}
	trace->err.err_num=errcode;
	if (errcode>0) {
		vsnprintf(buf,sizeof(buf),msg,va);
		snprintf(trace->err.problem,sizeof(trace->err.problem),
				"%s: %s",buf,strerror(errno));
	} else {
		vsnprintf(trace->err.problem,sizeof(trace->err.problem),
				msg,va);
	}
	va_end(va);
}

uint32_t trace_get_number_of_cores(void) {

	uint32_t t = 0;
#ifdef _SC_NPROCESSORS_ONLN
	t = sysconf(_SC_NPROCESSORS_ONLN);
	if (t < 1 || t > ((uint32_t)1 << 31))
		t = sysconf(_SC_NPROCESSORS_CONF);
#else
	int nm[2];
	size_t len = 4;
	
	nm[0] = CTL_HW; nm[1] = HW_AVAILCPU;
	sysctl(nm, 2, &t, &len, NULL, 0);
	
	if (t < 1) {
		nm[1] = HW_NCPU;
		sysctl(nm, 2, &t, &len, NULL, 0);
	}
#endif
	if (t < 1 || t > ((uint32_t)1 << 31))
		t = 4;
	return t;
}

/** Attempts to determine the direction for a pcap (or pcapng) packet.
 *
 * @param packet        The packet in question.
 * @return A valid libtrace_direction_t describing the direction that the
 *         packet was travelling, if direction can be determined. Otherwise
 *         returns TRACE_DIR_UNKNOWN.
 * @internal
 *
 * Note that we can determine the direction for only certain types of packets
 * if they are captured using pcap/pcapng, specifically SLL and PFLOG captures.
 */
libtrace_direction_t pcap_get_direction(const libtrace_packet_t *packet) {
        libtrace_direction_t direction  = -1;
        switch(pcap_linktype_to_libtrace(rt_to_pcap_linktype(packet->type))) {
                /* We can only get the direction for PCAP packets that have
                 * been encapsulated in Linux SLL or PFLOG */
                case TRACE_TYPE_LINUX_SLL:
                {
                        libtrace_sll_header_t *sll;
                        libtrace_linktype_t linktype;

                        sll = (libtrace_sll_header_t*)trace_get_packet_buffer(
                                        packet,
                                        &linktype,
                                        NULL);
                        if (!sll) {
                                trace_set_err(packet->trace,
                                        TRACE_ERR_BAD_PACKET,
                                                "Bad or missing packet");
                                return -1;
                        }
                        /* 0 == LINUX_SLL_HOST */
                        /* the Waikato Capture point defines "packets
                         * originating locally" (ie, outbound), with a
                         * direction of 0, and "packets destined locally"
                         * (ie, inbound), with a direction of 1.
                         * This is kind-of-opposite to LINUX_SLL.
                         * We return consistent values here, however
                         *
                         * Note that in recent versions of pcap, you can
                         * use "inbound" and "outbound" on ppp in linux
                         */
                        if (ntohs(sll->pkttype == 0)) {
                                direction = TRACE_DIR_INCOMING;
                        } else {
                                direction = TRACE_DIR_OUTGOING;
                        }
                        break;

                }
               case TRACE_TYPE_PFLOG:
                {
                        libtrace_pflog_header_t *pflog;
                        libtrace_linktype_t linktype;

                        pflog=(libtrace_pflog_header_t*)trace_get_packet_buffer(
                                        packet,&linktype,NULL);
                        if (!pflog) {
                                trace_set_err(packet->trace,
                                                TRACE_ERR_BAD_PACKET,
                                                "Bad or missing packet");
                                return -1;
                        }
                        /* enum    { PF_IN=0, PF_OUT=1 }; */
                        if (ntohs(pflog->dir==0)) {

                                direction = TRACE_DIR_INCOMING;
                        }
                        else {
                                direction = TRACE_DIR_OUTGOING;
                        }
                        break;
                }
                default:
                        break;
        }       
        return direction;
}

