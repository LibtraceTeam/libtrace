/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson 
 *          Perry Lorier 
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
#include "parse_cmd.h"

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
#  error "Can't find inttypes.h - this needs to be fixed"
#endif 

#ifdef HAVE_STDDEF_H
#  include <stddef.h>
#else
# error "Can't find stddef.h - do you define ptrdiff_t elsewhere?"
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#define COLLECTOR_PORT 3435

static struct libtrace_format_t erf;
static struct libtrace_format_t rtclient;
#if HAVE_DAG
static struct libtrace_format_t dag;
#endif 

#define CONNINFO libtrace->format_data->conn_info
#define INPUT libtrace->format_data->input
#define OUTPUT libtrace->format_data->output
#if HAVE_DAG
#define DAG libtrace->format_data->dag
#endif
#define OPTIONS libtrace->format_data->options
struct libtrace_format_data_t {
	union {
                struct {
                        char *hostname;
                        short port;
                } rt;
        } conn_info;
        
	union {
                int fd;
		LIBTRACE_FILE file;
        } input;

#if HAVE_DAG
	struct {
		void *buf; 
		unsigned bottom;
		unsigned top;
		unsigned diff;
		unsigned curr;
		unsigned offset;
	} dag;
#endif
};

struct libtrace_format_data_out_t {
        union {
                struct {
                        char *hostname;
                        short port;
                } rt;
                char *path;
        } conn_info;



	union {
		struct {
			int level;
			int fileflag;
		} erf;
		
	} options;
	
        union {
                int fd;
                struct rtserver_t * rtserver;
#if HAVE_ZLIB
                gzFile *file;
#else
		int file;
#endif
        } output;
};

/** Structure holding status information for a packet */
typedef struct libtrace_packet_status {
	uint8_t type;
	uint8_t reserved;
	uint16_t message;
} libtrace_packet_status_t;


#ifdef HAVE_DAG
static int dag_init_input(struct libtrace_t *libtrace) {
	libtrace->format_data = (struct libtrace_format_data_t *)
		malloc(sizeof(struct libtrace_format_data_t));
}

static int dag_start_input(struct libtrace_t *libtrace) {
	struct stat buf;
	if (stat(libtrace->uridata, &buf) == -1) {
		trace_set_err(errno,"stat(%s)",libtrace->uridata);
		return 0;
	} 
	if (S_ISCHR(buf.st_mode)) {
		/* DEVICE */
		if((INPUT.fd = dag_open(libtrace->uridata)) < 0) {
			trace_set_err(errno,"Cannot open DAG %s",
					libtrace->uridata);
			return 0;
		}
		if((DAG.buf = (void *)dag_mmap(INPUT.fd)) == MAP_FAILED) {
			trace_set_err(errno,"Cannot mmap DAG %s",
					libtrace->uridata);
			return 0;
		}
		if(dag_start(INPUT.fd) < 0) {
			trace_set_err(errno,"Cannot start DAG %s",
					libtrace->uridata);
			return 0;
		}
	} else {
		trace_set_err(errno,"Not a valid dag device: %s",
				libtrace->uridata);
		return 0;
	}
	return 1;
}
#endif

/* Dag erf ether packets have a 2 byte padding before the packet
 * so that the ip header is aligned on a 32 bit boundary.
 */
static int erf_get_padding(const struct libtrace_packet_t *packet)
{
	switch(trace_get_link_type(packet)) {
		case TRACE_TYPE_ETH: 	return 2;
		default: 		return 0;
	}
}

static int erf_get_framing_length(const struct libtrace_packet_t *packet)
{
	return dag_record_size + erf_get_padding(packet);
}


static int erf_init_input(struct libtrace_t *libtrace) 
{
	libtrace->format_data = (struct libtrace_format_data_t *)
		malloc(sizeof(struct libtrace_format_data_t));

}

static int erf_start_input(struct libtrace_t *libtrace)
{
	libtrace->format_data->input.file = trace_open_file(libtrace);

	if (libtrace->format_data->input.file)
		return 1;

	return 0;
}

static int rtclient_init_input(struct libtrace_t *libtrace) {
	char *scan;
	char *uridata = libtrace->uridata;
	struct hostent *he;
	struct sockaddr_in remote;
	libtrace->format_data = (struct libtrace_format_data_t *)
		malloc(sizeof(struct libtrace_format_data_t));


	if (strlen(uridata) == 0) {
		CONNINFO.rt.hostname = 
			strdup("localhost");
		CONNINFO.rt.port = 
			COLLECTOR_PORT;
	} else {
		if ((scan = strchr(uridata,':')) == NULL) {
			CONNINFO.rt.hostname = 
				strdup(uridata);
			CONNINFO.rt.port =
				COLLECTOR_PORT;
		} else {
			CONNINFO.rt.hostname = 
				(char *)strndup(uridata,
						(scan - uridata));
			CONNINFO.rt.port = 
				atoi(++scan);
		}
	}
	
	if ((he=gethostbyname(CONNINFO.rt.hostname)) == NULL) {  
		trace_set_err(errno,"failed to resolve %s",
				CONNINFO.rt.hostname);
		return 0;
	} 
	if ((INPUT.fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		trace_set_err(errno,"socket(AF_INET,SOCK_STREAM)");
		return 0;
	}

	remote.sin_family = AF_INET;   
	remote.sin_port = htons(CONNINFO.rt.port);
	remote.sin_addr = *((struct in_addr *)he->h_addr);
	bzero(&(remote.sin_zero), 8);

	if (connect(INPUT.fd, (struct sockaddr *)&remote,
				sizeof(struct sockaddr)) == -1) {
		trace_set_err(errno,"connect(%s)",
				CONNINFO.rt.hostname);
		return 0;
	}
	return 1;
}

static int erf_init_output(struct libtrace_out_t *libtrace) {
	libtrace->format_data = (struct libtrace_format_data_out_t *)
		calloc(1,sizeof(struct libtrace_format_data_out_t));

	OPTIONS.erf.level = 0;
	OPTIONS.erf.fileflag = O_CREAT | O_LARGEFILE | O_WRONLY;
	OUTPUT.file = 0;

	return 0;
}

static int erf_config_output(struct libtrace_out_t *libtrace, trace_option_t option, void *value) {

	switch (option) {
		case TRACE_OPTION_OUTPUT_COMPRESS:
			OPTIONS.erf.level = *(int*)value;
			return 0;
		case TRACE_OPTION_OUTPUT_FILEFLAGS:
			OPTIONS.erf.fileflag = *(int*)value;
			return 0;
		default:
			/* Unknown option */
			trace_set_err(TRACE_ERR_UNKNOWN_OPTION,
					"Unknown option");
			return -1;
	}
}


#ifdef HAVE_DAG
static int dag_fin_input(struct libtrace_t *libtrace) {
	dag_stop(INPUT.fd);
	free(libtrace->format_data);
}
#endif

static int rtclient_fin_input(struct libtrace_t *libtrace) {
	free(CONNINFO.rt.hostname);
	close(INPUT.fd);
	free(libtrace->format_data);
	return 0;
}

static int erf_fin_input(struct libtrace_t *libtrace) {
	LIBTRACE_CLOSE(INPUT.file);
	free(libtrace->format_data);
	return 0;
}

static int erf_fin_output(struct libtrace_out_t *libtrace) {
	LIBTRACE_CLOSE(OUTPUT.file);
	free(libtrace->format_data);
	return 0;
}
 
#if HAVE_DAG
static int dag_read(struct libtrace_t *libtrace, int block_flag) {
	int numbytes;
	static short lctr = 0;
	struct dag_record_t *erfptr = 0;
	int rlen;

	if (DAG.diff != 0) 
		return DAG.diff;

	DAG.bottom = DAG.top;
	DAG.top = dag_offset(
			INPUT.fd,
			&(DAG.bottom),
			block_flag);
	DAG.diff = DAG.top -
		DAG.bottom;

	numbytes=DAG.diff;
	DAG.offset = 0;
	return numbytes;
}
#endif

#if HAVE_DAG
static int dag_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes;
	int size;
	dag_record_t *erfptr;
	void *buffer = packet->buffer;
	void *buffer2 = buffer;
	int rlen;

	if (packet->buf_control == TRACE_CTRL_PACKET) {
		packet->buf_control = TRACE_CTRL_EXTERNAL;
		free(packet->buffer);
		packet->buffer = 0;
	}
   
	if ((numbytes = dag_read(libtrace,0)) <= 0) 
		return numbytes;

	/*DAG always gives us whole packets */
	erfptr = (dag_record_t *) ((void *)DAG.buf + 
			(DAG.bottom + DAG.offset));
	size = ntohs(erfptr->rlen);

	if ( size  > LIBTRACE_PACKET_BUFSIZE) {
		assert( size < LIBTRACE_PACKET_BUFSIZE);
	}
	
	packet->buffer = erfptr;
	packet->header = erfptr;
	if (((dag_record_t *)packet->buffer)->flags.rxerror == 1) {
		packet->payload = NULL;
	} else {
		packet->payload = packet->buffer + erf_get_framing_length(packet);
	}

	packet->size = size;
	DAG.offset += size;
	DAG.diff -= size;

	assert(DAG.diff >= 0);

	return (size);
}
#endif 

static int erf_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes;
	int size;
	void *buffer2 = packet->buffer;
	int rlen;

	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
		packet->buf_control = TRACE_CTRL_PACKET;
	}

	packet->header = packet->buffer;

	if ((numbytes=LIBTRACE_READ(INPUT.file,
					packet->buffer,
					dag_record_size)) == -1) {
		trace_set_err(errno,"read(%s)",
				packet->trace->uridata);
		return -1;
	}
	if (numbytes == 0) {
		return 0;
	}

	rlen = ntohs(((dag_record_t *)packet->buffer)->rlen);
	buffer2 = (char*)packet->buffer + dag_record_size;
	size = rlen - dag_record_size;
	assert(size < LIBTRACE_PACKET_BUFSIZE);

	
	/* Unknown/corrupt */
	assert(((dag_record_t *)packet->buffer)->type < 10);
	
	/* read in the rest of the packet */
	if ((numbytes=LIBTRACE_READ(INPUT.file,
					buffer2,
					size)) != size) {
		trace_set_err(errno, "read(%s)", packet->trace->uridata);
		return -1;
	}
	packet->size = rlen;
	if (((dag_record_t *)packet->buffer)->flags.rxerror == 1) {
		packet->payload = NULL;
	} else {
		packet->payload = (char*)packet->buffer + erf_get_framing_length(packet);
	}
	return rlen;
}

static int rtclient_read(struct libtrace_t *libtrace, void *buffer, size_t len) {
	int numbytes;

	while(1) {
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif
		if ((numbytes = recv(INPUT.fd,
						buffer,
						len,
						MSG_NOSIGNAL)) == -1) {
			if (errno == EINTR) {
				/*ignore EINTR in case
				 *a caller is using signals
				 */
				continue;
			}
			trace_set_err(errno,"recv(%s)",
					libtrace->uridata);
			return -1;
		}
		break;

	}
	return numbytes;
}

#define RT_DATA 1
#define RT_MSG 2

static int rtclient_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes = 0;
	char buf[RP_BUFSIZE];
	int read_required = 0;
	
	void *buffer = 0;

	packet->trace = libtrace;

	if (packet->buf_control == TRACE_CTRL_EXTERNAL || !packet->buffer) {
		packet->buf_control = TRACE_CTRL_PACKET;
		packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
	}

	buffer = packet->buffer;
	packet->header = packet->buffer;

	
	do {
		struct libtrace_packet_status status;
		if (tracefifo_out_available(libtrace->fifo) == 0 || read_required) {
			if ((numbytes = rtclient_read(
					libtrace,buf,RP_BUFSIZE))<=0) {
				return numbytes;
			}
			tracefifo_write(libtrace->fifo,buf,numbytes);
			read_required = 0;
		}
		/* Read status byte */
		if (tracefifo_out_read(libtrace->fifo,
				&status, sizeof(uint32_t)) == 0) {
			read_required = 1;
			continue;
		}
		tracefifo_out_update(libtrace->fifo,sizeof(uint32_t));
		/* Read in packet size */
		if (tracefifo_out_read(libtrace->fifo,
				&packet->size, sizeof(uint32_t)) == 0) {
			tracefifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}
		tracefifo_out_update(libtrace->fifo, sizeof(uint32_t));
		
		if (status.type == RT_MSG) {
			/* Need to skip this packet as it is a message packet */
			tracefifo_out_update(libtrace->fifo, packet->size);
			tracefifo_ack_update(libtrace->fifo, packet->size + 
					sizeof(uint32_t) + 
					sizeof(libtrace_packet_status_t));
			continue;
		}
		
		/* read in the full packet */
		if ((numbytes = tracefifo_out_read(libtrace->fifo, 
						buffer, packet->size)) == 0) {
			tracefifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}

		/* got in our whole packet, so... */
		tracefifo_out_update(libtrace->fifo,packet->size);

		tracefifo_ack_update(libtrace->fifo,packet->size + 
				sizeof(uint32_t) + 
				sizeof(libtrace_packet_status_t));

		if (((dag_record_t *)buffer)->flags.rxerror == 1) {
			packet->payload = NULL;
		} else {
			packet->payload = (char*)packet->buffer + erf_get_framing_length(packet);
		}
		return numbytes;
	} while(1);
}

static int erf_dump_packet(libtrace_out_t *libtrace,
		dag_record_t *erfptr, int pad, void *buffer, size_t size) {
	int numbytes = 0;
	assert(size>=0 && size<=65536);
	/* FIXME: Shouldn't this return != dag_record_size+pad on error? */
	if ((numbytes = LIBTRACE_WRITE(OUTPUT.file, erfptr, dag_record_size + pad)) == 0) {
		trace_set_err(errno,"write(%s)",libtrace->uridata);
		return -1;
	}

	if ((numbytes=LIBTRACE_WRITE(OUTPUT.file, buffer, size)) == 0) {
		trace_set_err(errno,"write(%s)",libtrace->uridata);
		return -1;
	}

	return numbytes + pad + dag_record_size;
}

static int erf_start_output(libtrace_out_t *libtrace)
{
	OUTPUT.file = trace_open_file_out(libtrace,
			OPTIONS.erf.level,
			OPTIONS.erf.fileflag);
	if (!OUTPUT.file) {
		return -1;
	}
	return 0;
}
		
static int erf_write_packet(libtrace_out_t *libtrace, 
		const libtrace_packet_t *packet) 
{
	int numbytes = 0;
	int pad = 0;
	dag_record_t *dag_hdr = (dag_record_t *)packet->header;
	void *payload = packet->payload;

	assert(OUTPUT.file);

	pad = erf_get_padding(packet);

	/* If we've had an rxerror, we have no payload to write - fix rlen to
	 * be the correct length */
	if (payload == NULL) {
		dag_hdr->rlen = htons(dag_record_size + pad);
	} 
	
	if (packet->trace->format == &erf  
#if HAVE_DAG
			|| packet->trace->format == &dag 
#endif
			) {
		numbytes = erf_dump_packet(libtrace,
				(dag_record_t *)packet->buffer,
				pad,
				payload,
				trace_get_capture_length(packet)
				);
	} else {
		dag_record_t erfhdr;
		/* convert format - build up a new erf header */
		/* Timestamp */
		erfhdr.ts = trace_get_erf_timestamp(packet);
		erfhdr.type = libtrace_to_erf_type(trace_get_link_type(packet));
		/* Flags. Can't do this */
		memset(&erfhdr.flags,1,sizeof(erfhdr.flags));
		/* Packet length (rlen includes format overhead) */
		erfhdr.rlen = trace_get_capture_length(packet) 
			+ erf_get_framing_length(packet);
		/* loss counter. Can't do this */
		erfhdr.lctr = 0;
		/* Wire length */
		erfhdr.wlen = trace_get_wire_length(packet);

		/* Write it out */
		numbytes = erf_dump_packet(libtrace,
				&erfhdr,
				pad,
				payload,
				trace_get_capture_length(packet));
	}
	return numbytes;
}

static libtrace_linktype_t erf_get_link_type(const struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return erf_type_to_libtrace(erfptr->type);
}

static int8_t erf_get_direction(const struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return erfptr->flags.iface;
}

static int8_t erf_set_direction(const struct libtrace_packet_t *packet, int8_t direction) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	erfptr->flags.iface = direction;
	return erfptr->flags.iface;
}

static uint64_t erf_get_erf_timestamp(const struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return erfptr->ts;
}

static int erf_get_capture_length(const struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return (ntohs(erfptr->rlen) - erf_get_framing_length(packet));
}

static int erf_get_wire_length(const struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return ntohs(erfptr->wlen);
}

static size_t erf_set_capture_length(struct libtrace_packet_t *packet, size_t size) {
	dag_record_t *erfptr = 0;
	assert(packet);
	if((size + erf_get_framing_length(packet)) > packet->size) {
		/* can't make a packet larger */
		return (packet->size - erf_get_framing_length(packet));
	}
	erfptr = (dag_record_t *)packet->header;
	erfptr->rlen = htons(size + erf_get_framing_length(packet));
	packet->size = size + erf_get_framing_length(packet);
	return packet->size;
}

static int rtclient_get_fd(const struct libtrace_packet_t *packet) {
	return packet->trace->format_data->input.fd;
}

static int erf_get_fd(const struct libtrace_packet_t *packet) {
	return packet->trace->format_data->input.fd;
}

#ifdef HAVE_DAG
struct libtrace_eventobj_t trace_event_dag(struct libtrace_t *trace, struct libtrace_packet_t *packet) {
        struct libtrace_eventobj_t event = {0,0,0.0,0};
        int dag_fd;
        int data;

        if (packet->trace->format->get_fd) {
                dag_fd = packet->trace->format->get_fd(packet);
        } else {
                dag_fd = 0;
        }
	
	data = dag_read(trace, DAGF_NONBLOCK);

        if (data > 0) {
                event.size = trace_read_packet(trace,packet);
                event.type = TRACE_EVENT_PACKET;
                return event;
        }
        event.type = TRACE_EVENT_SLEEP;
        event.seconds = 0.0001;
        return event;
}
#endif

#if HAVE_DAG
static void dag_help() {
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
#endif

static void erf_help() {
	printf("erf format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\terf:/path/to/file\t(uncompressed)\n");
	printf("\terf:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\terf:-\t(stdin, either compressed or not)\n");
	printf("\terf:/path/to/socket\n");
	printf("\n");
	printf("\te.g.: erf:/tmp/trace\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\terf:path/to/file\t(uncompressed)\n");
	printf("\terf:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\terf:-\t(stdout, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: erf:/tmp/trace\n");
	printf("\n");
	printf("Supported output options:\n");
	printf("\t-z\tSpecify the gzip compression, ranging from 0 (uncompressed) to 9 - defaults to 1\n");
	printf("\n");

	
}

static void rtclient_help() {
	printf("rtclient format module: $Revision$\n");
	printf("DEPRECATED - use rt module instead\n");
	printf("Supported input URIs:\n");
	printf("\trtclient:host:port\n");
	printf("\n");
	printf("\te.g.:rtclient:localhost:3435\n");
	printf("\n");
        printf("Supported output URIs:\n");
        printf("\tnone\n");
        printf("\n");
}	

static struct libtrace_format_t erf = {
	"erf",
	"$Id$",
	TRACE_FORMAT_ERF,
	erf_init_input,			/* init_input */	
	NULL,				/* config_input */
	erf_start_input,		/* start_input */
	NULL,				/* pause_input */
	erf_init_output,		/* init_output */
	erf_config_output,		/* config_output */
	erf_start_output,		/* start_output */
	erf_fin_input,			/* fin_input */
	erf_fin_output,			/* fin_output */
	erf_read_packet,		/* read_packet */
	erf_write_packet,		/* write_packet */
	erf_get_link_type,		/* get_link_type */
	erf_get_direction,		/* get_direction */
	erf_set_direction,		/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	erf_get_capture_length,		/* get_capture_length */
	erf_get_wire_length,		/* get_wire_length */
	erf_get_framing_length,		/* get_framing_length */
	erf_set_capture_length,		/* set_capture_length */
	erf_get_fd,			/* get_fd */
	trace_event_trace,		/* trace_event */
	erf_help			/* help */
};

#ifdef HAVE_DAG
static struct libtrace_format_t dag = {
	"dag",
	"$Id$",
	TRACE_FORMAT_ERF,
	dag_init_input,			/* init_input */	
	NULL,				/* config_input */
	dag_start_input,		/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	dag_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	dag_read_packet,		/* read_packet */
	NULL,				/* write_packet */
	erf_get_link_type,		/* get_link_type */
	erf_get_direction,		/* get_direction */
	erf_set_direction,		/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL, 				/* seek_timeval */
	NULL, 				/* seek_seconds */
	erf_get_capture_length,		/* get_capture_length */
	erf_get_wire_length,		/* get_wire_length */
	erf_get_framing_length,		/* get_framing_length */
	erf_set_capture_length,		/* set_capture_length */
	NULL,				/* get_fd */
	trace_event_dag,		/* trace_event */
	dag_help			/* help */
};
#endif

static struct libtrace_format_t rtclient = {
	"rtclient",
	"$Id$",
	TRACE_FORMAT_ERF,
	rtclient_init_input,		/* init_input */	
	NULL,				/* config_input */
	NULL,				/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	rtclient_fin_input,		/* fin_input */
	NULL,				/* fin_output */
	rtclient_read_packet,		/* read_packet */
	NULL,				/* write_packet */
	erf_get_link_type,		/* get_link_type */
	erf_get_direction,		/* get_direction */
	erf_set_direction,		/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	erf_get_capture_length,		/* get_capture_length */
	erf_get_wire_length,		/* get_wire_length */
	erf_get_framing_length,		/* get_framing_length */
	erf_set_capture_length,		/* set_capture_length */
	rtclient_get_fd,		/* get_fd */
	trace_event_device,		/* trace_event */
	rtclient_help			/* help */
};

void __attribute__((constructor)) erf_constructor() {
	register_format(&rtclient);
	register_format(&erf);
#ifdef HAVE_DAG
	register_format(&dag);
#endif
}
