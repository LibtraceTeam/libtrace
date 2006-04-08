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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef WIN32
#  include <io.h>
#  include <share.h>
#  define PATH_MAX _MAX_PATH
#  define snprintf sprintf_s
#else
#  include <netdb.h>
#endif


#define COLLECTOR_PORT 3435

static struct libtrace_format_t erf;
static struct libtrace_format_t rtclient;
#if HAVE_DAG
static struct libtrace_format_t dag;
#endif 

#define DATA(x) ((struct erf_format_data_t *)x->format_data)
#define DATAOUT(x) ((struct erf_format_data_out_t *)x->format_data)

#define CONNINFO DATA(libtrace)->conn_info
#define INPUT DATA(libtrace)->input
#define OUTPUT DATAOUT(libtrace)->output
#if HAVE_DAG
#define DAG DATA(libtrace)->dag
#endif
#define OPTIONS DATAOUT(libtrace)->options
struct erf_format_data_t {
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

	struct {
		enum { INDEX_UNKNOWN=0, INDEX_NONE, INDEX_EXISTS } exists;
		LIBTRACE_FILE index;
		off_t index_len;
	} seek;

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

struct erf_format_data_out_t {
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

typedef struct erf_index_t {
	uint64_t timestamp;
	uint64_t offset; 
} erf_index_t;

#ifdef HAVE_DAG
static int dag_init_input(struct libtrace_t *libtrace) {
	struct stat buf;

	libtrace->format_data = (struct erf_format_data_t *)
		malloc(sizeof(struct erf_format_data_t));
	if (stat(libtrace->uridata, &buf) == -1) {
		trace_set_err(libtrace,errno,"stat(%s)",libtrace->uridata);
		return -1;
	} 
	if (S_ISCHR(buf.st_mode)) {
		/* DEVICE */
		if((INPUT.fd = dag_open(libtrace->uridata)) < 0) {
			trace_set_err(libtrace,errno,"Cannot open DAG %s",
					libtrace->uridata);
			return -1;
		}
		if((DAG.buf = (void *)dag_mmap(INPUT.fd)) == MAP_FAILED) {
			trace_set_err(libtrace,errno,"Cannot mmap DAG %s",
					libtrace->uridata);
			return -1;
		}
	} else {
		trace_set_err(libtrace,errno,"Not a valid dag device: %s",
				libtrace->uridata);
		return -1;
	}
	return 0;
}

#endif

/* Dag erf ether packets have a 2 byte padding before the packet
 * so that the ip header is aligned on a 32 bit boundary.
 */
static int erf_get_padding(const libtrace_packet_t *packet)
{
	dag_record_t *erfptr = (dag_record_t *)packet->header;
	switch(erfptr->type) {
		case TYPE_ETH: 		return 2;
		default: 		return 0;
	}
}

static int erf_get_framing_length(const libtrace_packet_t *packet)
{
	return dag_record_size + erf_get_padding(packet);
}


static int erf_init_input(libtrace_t *libtrace) 
{
	libtrace->format_data = malloc(sizeof(struct erf_format_data_t));
	
	INPUT.file = 0;

	return 0; /* success */
}

static int erf_start_input(libtrace_t *libtrace)
{
	if (INPUT.file)
		return 0; /* success */

	INPUT.file = trace_open_file(libtrace);

	if (!INPUT.file)
		return -1;

	return 0; /* success */
}

/* Binary search through the index to find the closest point before
 * the packet.  Consider in future having a btree index perhaps?
 */
static int erf_fast_seek_start(libtrace_t *libtrace,uint64_t erfts)
{
	size_t max_off = DATA(libtrace)->seek.index_len/sizeof(erf_index_t);
	size_t min_off = 0;
	off_t current;
	erf_index_t record;
	do {
		current=(max_off+min_off)>>2;

		LIBTRACE_SEEK(DATA(libtrace)->seek.index,
				current*sizeof(record),
				SEEK_SET);
		LIBTRACE_READ(DATA(libtrace)->seek.index,
				&record,sizeof(record));
		if (record.timestamp < erfts) {
			min_off=current;
		}
		if (record.timestamp > erfts) {
			max_off=current;
		}
		if (record.timestamp == erfts)
			break;
	} while(min_off<max_off);

	/* If we've passed it, seek backwards.  This loop shouldn't
	 * execute more than twice.
	 */
	do {
		LIBTRACE_SEEK(DATA(libtrace)->seek.index,
				current*sizeof(record),SEEK_SET);
		LIBTRACE_READ(DATA(libtrace)->seek.index,
				&record,sizeof(record));
		current--;
	} while(record.timestamp>erfts);

	/* We've found our location in the trace, now use it. */
	LIBTRACE_SEEK(INPUT.file,record.offset,SEEK_SET);

	return 0; /* success */
}

/* There is no index.  Seek through the entire trace from the start, nice
 * and slowly.
 */
static int erf_slow_seek_start(libtrace_t *libtrace,uint64_t erfts)
{
	if (INPUT.file) {
		LIBTRACE_CLOSE(INPUT.file);
	}
	INPUT.file = trace_open_file(libtrace);
	if (!INPUT.file)
		return -1;
	return 0;
}

static int erf_seek_erf(libtrace_t *libtrace,uint64_t erfts)
{
	libtrace_packet_t *packet;
	off_t off = 0;

	if (DATA(libtrace)->seek.exists==INDEX_UNKNOWN) {
		char buffer[PATH_MAX];
		snprintf(buffer,sizeof(buffer),"%s.idx",libtrace->uridata);
		DATA(libtrace)->seek.index=LIBTRACE_OPEN(buffer,"r");
		if (DATA(libtrace)->seek.index) {
			DATA(libtrace)->seek.exists=INDEX_EXISTS;
		}
		else {
			DATA(libtrace)->seek.exists=INDEX_NONE;
		}
	}

	/* If theres an index, use it to find the nearest packet that isn't
	 * after the time we're looking for.  If there is no index we need
	 * to seek slowly through the trace from the beginning.  Sigh.
	 */
	switch(DATA(libtrace)->seek.exists) {
		case INDEX_EXISTS:
			erf_fast_seek_start(libtrace,erfts);
			break;
		case INDEX_NONE:
			erf_slow_seek_start(libtrace,erfts);
			break;
		case INDEX_UNKNOWN:
			assert(0);
			break;
	}

	/* Now seek forward looking for the correct timestamp */
	packet=trace_create_packet();
	do {
		trace_read_packet(libtrace,packet);
		if (trace_get_erf_timestamp(packet)==erfts)
			break;
		off=LIBTRACE_TELL(INPUT.file);
	} while(trace_get_erf_timestamp(packet)<erfts);

	LIBTRACE_SEEK(INPUT.file,off,SEEK_SET);

	return 0;
}

static int rtclient_init_input(libtrace_t *libtrace) {
	char *scan;
	libtrace->format_data = malloc(sizeof(struct erf_format_data_t));

	if (strlen(libtrace->uridata) == 0) {
		CONNINFO.rt.hostname = 
			strdup("localhost");
		CONNINFO.rt.port = 
			COLLECTOR_PORT;
	} else {
		if ((scan = strchr(libtrace->uridata,':')) == NULL) {
			CONNINFO.rt.hostname = 
				strdup(libtrace->uridata);
			CONNINFO.rt.port =
				COLLECTOR_PORT;
		} else {
			CONNINFO.rt.hostname = 
				(char *)strndup(libtrace->uridata,
						(scan - libtrace->uridata));
			CONNINFO.rt.port = 
				atoi(++scan);
		}
	}

	return 0; /* success */
}

static int rtclient_start_input(libtrace_t *libtrace)
{
	struct hostent *he;
	struct sockaddr_in remote;
	if ((he=gethostbyname(CONNINFO.rt.hostname)) == NULL) {  
		trace_set_err(libtrace,errno,"failed to resolve %s",
				CONNINFO.rt.hostname);
		return -1;
	} 
	if ((INPUT.fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		trace_set_err(libtrace,errno,"socket(AF_INET,SOCK_STREAM)");
		return -1;
	}

	remote.sin_family = AF_INET;   
	remote.sin_port = htons(CONNINFO.rt.port);
	remote.sin_addr = *((struct in_addr *)he->h_addr);
	memset(&(remote.sin_zero), 0, 8);

	if (connect(INPUT.fd, (struct sockaddr *)&remote,
				sizeof(struct sockaddr)) == -1) {
		trace_set_err(libtrace,errno,"connect(%s)",
				CONNINFO.rt.hostname);
		return -1;
	}
	return 0; /* success */
}

static int rtclient_pause_input(libtrace_t *libtrace)
{
	close(INPUT.fd);
	return 0; /* success */
}

static int erf_init_output(libtrace_out_t *libtrace) {
	libtrace->format_data = calloc(1,sizeof(struct erf_format_data_out_t));

	OPTIONS.erf.level = 0;
	OPTIONS.erf.fileflag = O_CREAT | O_WRONLY;
	OUTPUT.file = 0;

	return 0;
}

static int erf_config_output(libtrace_out_t *libtrace, trace_option_output_t option,
		void *value) {

	switch (option) {
		case TRACE_OPTION_OUTPUT_COMPRESS:
			OPTIONS.erf.level = *(int*)value;
			return 0;
		case TRACE_OPTION_OUTPUT_FILEFLAGS:
			OPTIONS.erf.fileflag = *(int*)value;
			return 0;
		default:
			/* Unknown option */
			trace_set_err_out(libtrace,TRACE_ERR_UNKNOWN_OPTION,
					"Unknown option");
			return -1;
	}
}


#ifdef HAVE_DAG
static int dag_pause_input(libtrace_t *libtrace) {
	dag_stop(INPUT.fd);
	return 0; /* success */
}

static int dag_fin_input(libtrace_t *libtrace) {
	/* dag pause input implicitly called to cleanup before this */
	dag_close(INPUT.fd);
	free(libtrace->format_data);
	return 0; /* success */
}
#endif

static int rtclient_fin_input(libtrace_t *libtrace) {
	free(CONNINFO.rt.hostname);
	close(INPUT.fd);
	free(libtrace->format_data);
	return 0;
}

static int erf_fin_input(libtrace_t *libtrace) {
	LIBTRACE_CLOSE(INPUT.file);
	free(libtrace->format_data);
	return 0;
}

static int erf_fin_output(libtrace_out_t *libtrace) {
	LIBTRACE_CLOSE(OUTPUT.file);
	free(libtrace->format_data);
	return 0;
}
 
#if HAVE_DAG
static int dag_read(libtrace_t *libtrace, int block_flag) {

	if (DAG.diff != 0) 
		return DAG.diff;

	DAG.bottom = DAG.top;

	DAG.top = dag_offset(
			INPUT.fd,
			&(DAG.bottom),
			block_flag);

	DAG.diff = DAG.top - DAG.bottom;

	DAG.offset = 0;
	return DAG.diff;
}

/* FIXME: dag_read_packet shouldn't update the pointers, dag_fin_packet
 * should do that.
 */
static int dag_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int numbytes;
	int size;
	dag_record_t *erfptr;

	if (packet->buf_control == TRACE_CTRL_PACKET) {
		packet->buf_control = TRACE_CTRL_EXTERNAL;
		free(packet->buffer);
		packet->buffer = 0;
	}
 	
	packet->type = RT_DATA_ERF;
	
	if ((numbytes = dag_read(libtrace,0)) < 0) 
		return numbytes;
	assert(numbytes>0);

	/*DAG always gives us whole packets */
	erfptr = (dag_record_t *) ((char *)DAG.buf + 
			(DAG.bottom + DAG.offset));
	size = ntohs(erfptr->rlen);

	assert( size >= dag_record_size );
	assert( size < LIBTRACE_PACKET_BUFSIZE);
	
	packet->buffer = erfptr;
	packet->header = erfptr;
	if (((dag_record_t *)packet->buffer)->flags.rxerror == 1) {
		packet->payload = NULL;
	} else {
		packet->payload = (char*)packet->buffer 
			+ erf_get_framing_length(packet);
	}

	DAG.offset += size;
	DAG.diff -= size;

	return (size);
}

static int dag_start_input(libtrace_t *libtrace) {
	if(dag_start(INPUT.fd) < 0) {
		trace_set_err(libtrace,errno,"Cannot start DAG %s",
				libtrace->uridata);
		return -1;
	}
	/* dags appear to have a bug where if you call dag_start after
	 * calling dag_stop, and at least one packet has arrived, bad things
	 * happen.  flush the memory hole 
	 */
	while(dag_read(libtrace,1)!=0)
		DAG.diff=0;
	return 0;
}
#endif 

static int erf_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int numbytes;
	int size;
	void *buffer2 = packet->buffer;
	int rlen;

	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
		packet->buf_control = TRACE_CTRL_PACKET;
	}

	packet->header = packet->buffer;
	packet->type = RT_DATA_ERF;

	if ((numbytes=LIBTRACE_READ(INPUT.file,
					packet->buffer,
					dag_record_size)) == -1) {
		trace_set_err(libtrace,errno,"read(%s)",
				libtrace->uridata);
		return -1;
	}
	if (numbytes == 0) {
		printf("eof\n");
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
		trace_set_err(libtrace,errno, "read(%s)", libtrace->uridata);
		return -1;
	}
	if (((dag_record_t *)packet->buffer)->flags.rxerror == 1) {
		packet->payload = NULL;
	} else {
		packet->payload = (char*)packet->buffer + erf_get_framing_length(packet);
	}
	return rlen;
}

static int rtclient_read(libtrace_t *libtrace, void *buffer, size_t len) {
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
			trace_set_err(libtrace,errno,"recv(%s)",
					libtrace->uridata);
			return -1;
		}
		break;

	}
	return numbytes;
}

static int rtclient_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int numbytes = 0;
	char buf[RP_BUFSIZE];
	int read_required = 0;
	
	void *buffer = 0;

	if (packet->buf_control == TRACE_CTRL_EXTERNAL || !packet->buffer) {
		packet->buf_control = TRACE_CTRL_PACKET;
		packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
	}

	buffer = packet->buffer;
	packet->header = packet->buffer;
	
	packet->type = RT_DATA_ERF;

	
	do {
		libtrace_packet_status_t status;
		int size;
		if (tracefifo_out_available(libtrace->fifo) == 0 
				|| read_required) {
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
				&size, sizeof(uint32_t)) == 0) {
			tracefifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}
		tracefifo_out_update(libtrace->fifo, sizeof(uint32_t));
		
		if (status.type == 2 /* RT_MSG */) {
			/* Need to skip this packet as it is a message packet */
			tracefifo_out_update(libtrace->fifo, size);
			tracefifo_ack_update(libtrace->fifo, size + 
					sizeof(uint32_t) + 
					sizeof(libtrace_packet_status_t));
			continue;
		}
		
		/* read in the full packet */
		if ((numbytes = tracefifo_out_read(libtrace->fifo, 
						buffer, size)) == 0) {
			tracefifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}

		/* got in our whole packet, so... */
		tracefifo_out_update(libtrace->fifo,size);

		tracefifo_ack_update(libtrace->fifo,size + 
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
	assert(size<=65536);

	if ((numbytes = LIBTRACE_WRITE(OUTPUT.file, erfptr, dag_record_size + pad)) != dag_record_size+pad) {
		trace_set_err_out(libtrace,errno,
				"write(%s)",libtrace->uridata);
		return -1;
	}

	if ((numbytes=LIBTRACE_WRITE(OUTPUT.file, buffer, size)) != size) {
		trace_set_err_out(libtrace,errno,
				"write(%s)",libtrace->uridata);
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
				(dag_record_t *)packet->header,
				pad,
				payload,
				trace_get_capture_length(packet)
				);
	} else {
		dag_record_t erfhdr;
		int type;
		/* convert format - build up a new erf header */
		/* Timestamp */
		erfhdr.ts = trace_get_erf_timestamp(packet);
		type=libtrace_to_erf_type(trace_get_link_type(packet));
		if (type==(char)-1) {
			trace_set_err_out(libtrace,TRACE_ERR_BAD_PACKET,
					"No erf type for packet");
			return -1;
		}
		erfhdr.type = type;
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

static libtrace_linktype_t erf_get_link_type(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return erf_type_to_libtrace(erfptr->type);
}

static int8_t erf_get_direction(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return erfptr->flags.iface;
}

static int8_t erf_set_direction(const libtrace_packet_t *packet, int8_t direction) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	erfptr->flags.iface = direction;
	return erfptr->flags.iface;
}

static uint64_t erf_get_erf_timestamp(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return erfptr->ts;
}

static int erf_get_capture_length(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return (ntohs(erfptr->rlen) - erf_get_framing_length(packet));
}

static int erf_get_wire_length(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return ntohs(erfptr->wlen);
}

static size_t erf_set_capture_length(libtrace_packet_t *packet, size_t size) {
	dag_record_t *erfptr = 0;
	assert(packet);
	if(size  > trace_get_capture_length(packet)) {
		/* can't make a packet larger */
		return trace_get_capture_length(packet);
	}
	erfptr = (dag_record_t *)packet->header;
	erfptr->rlen = htons(size + erf_get_framing_length(packet));
	return trace_get_capture_length(packet);
}

static int rtclient_get_fd(const libtrace_t *libtrace) {
	return INPUT.fd;
}

#ifdef HAVE_DAG
libtrace_eventobj_t trace_event_dag(libtrace_t *trace, libtrace_packet_t *packet) {
        libtrace_eventobj_t event = {0,0,0.0,0};
        int dag_fd;
        int data;

        if (trace->format->get_fd) {
                dag_fd = trace->format->get_fd(trace);
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
	NULL,				/* fin_packet */
	erf_write_packet,		/* write_packet */
	erf_get_link_type,		/* get_link_type */
	erf_get_direction,		/* get_direction */
	erf_set_direction,		/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	erf_seek_erf,			/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	erf_get_capture_length,		/* get_capture_length */
	erf_get_wire_length,		/* get_wire_length */
	erf_get_framing_length,		/* get_framing_length */
	erf_set_capture_length,		/* set_capture_length */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	erf_help,			/* help */
	NULL				/* next pointer */
};

#ifdef HAVE_DAG
static struct libtrace_format_t dag = {
	"dag",
	"$Id$",
	TRACE_FORMAT_ERF,
	dag_init_input,			/* init_input */	
	NULL,				/* config_input */
	dag_start_input,		/* start_input */
	dag_pause_input,		/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	dag_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	dag_read_packet,		/* read_packet */
	NULL,				/* fin_packet */
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
	dag_help,			/* help */
	NULL				/* next pointer */
};
#endif

static struct libtrace_format_t rtclient = {
	"rtclient",
	"$Id$",
	TRACE_FORMAT_ERF,
	rtclient_init_input,		/* init_input */	
	NULL,				/* config_input */
	rtclient_start_input,		/* start_input */
	rtclient_pause_input,		/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	rtclient_fin_input,		/* fin_input */
	NULL,				/* fin_output */
	rtclient_read_packet,		/* read_packet */
	NULL,				/* fin_packet */
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
	rtclient_help,			/* help */
	NULL				/* next pointer */
};

void CONSTRUCTOR erf_constructor() {
	register_format(&rtclient);
	register_format(&erf);
#ifdef HAVE_DAG
	register_format(&dag);
#endif
}
