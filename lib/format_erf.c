/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008 The University of Waikato, Hamilton, New Zealand.
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
#include "format_erf.h"

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
#else
#  include <netdb.h>
#  ifndef PATH_MAX
#	define PATH_MAX 4096
#  endif
#  include <sys/ioctl.h>
#endif


#define COLLECTOR_PORT 3435

static struct libtrace_format_t erfformat;

#define DATA(x) ((struct erf_format_data_t *)x->format_data)
#define DATAOUT(x) ((struct erf_format_data_out_t *)x->format_data)

#define INPUT DATA(libtrace)->input
#define IN_OPTIONS DATA(libtrace)->options
#define OUTPUT DATAOUT(libtrace)->output
#define OUT_OPTIONS DATAOUT(libtrace)->options
struct erf_format_data_t {
        
	union {
                int fd;
		libtrace_io_t *file;
        } input;

	
	struct {
		enum { INDEX_UNKNOWN=0, INDEX_NONE, INDEX_EXISTS } exists;
		libtrace_io_t *index;
		off_t index_len;
	} seek;

	struct {
		int real_time;
	} options;
	uint64_t drops;
};

struct erf_format_data_out_t {
	union {
		struct {
			int level;
			int fileflag;
		} erf;
		
	} options;
	
        union {
                int fd;
                struct rtserver_t * rtserver;
		libtrace_io_t *file;
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


/* Dag erf ether packets have a 2 byte padding before the packet
 * so that the ip header is aligned on a 32 bit boundary.
 */
static int erf_get_padding(const libtrace_packet_t *packet)
{
	if (packet->trace->format->type==TRACE_FORMAT_ERF) {
		dag_record_t *erfptr = (dag_record_t *)packet->header;
		switch(erfptr->type) {
			case TYPE_ETH: 		
			case TYPE_DSM_COLOR_ETH:
				return 2;
			default: 		return 0;
		}
	}
	else {
		switch(trace_get_link_type(packet)) {
			case TRACE_TYPE_ETH:	return 2;
			default:		return 0;
		}
	}
}

int erf_get_framing_length(const libtrace_packet_t *packet)
{
	return dag_record_size + erf_get_padding(packet);
}


static int erf_init_input(libtrace_t *libtrace) 
{
	libtrace->format_data = malloc(sizeof(struct erf_format_data_t));
	
	INPUT.file = 0;
	IN_OPTIONS.real_time = 0;
	DATA(libtrace)->drops = 0;
	
	return 0; /* success */
}

static int erf_config_input(libtrace_t *libtrace, trace_option_t option,
		void *value) {

	switch (option) {
		case TRACE_OPTION_EVENT_REALTIME:
			IN_OPTIONS.real_time = *(int *)value;
			return 0;
		case TRACE_OPTION_SNAPLEN:
		case TRACE_OPTION_PROMISC:
		case TRACE_OPTION_FILTER:
		case TRACE_OPTION_META_FREQ:
			trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
					"Unsupported option");
			return -1;
		default:
			/* Unknown option */
			trace_set_err(libtrace,TRACE_ERR_UNKNOWN_OPTION,
					"Unknown option");
			return -1;
	}
}

static int erf_start_input(libtrace_t *libtrace)
{
	if (INPUT.file)
		return 0; /* success */

	INPUT.file = trace_open_file(libtrace);

	if (!INPUT.file)
		return -1;

	DATA(libtrace)->drops = 0;

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

		libtrace_io_seek(DATA(libtrace)->seek.index,
				(int64_t)(current*sizeof(record)),
				SEEK_SET);
		libtrace_io_read(DATA(libtrace)->seek.index,
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
		libtrace_io_seek(DATA(libtrace)->seek.index,
				(int64_t)(current*sizeof(record)),SEEK_SET);
		libtrace_io_read(DATA(libtrace)->seek.index,
				&record,sizeof(record));
		current--;
	} while(record.timestamp>erfts);

	/* We've found our location in the trace, now use it. */
	libtrace_io_seek(INPUT.file,(int64_t) record.offset,SEEK_SET);

	return 0; /* success */
}

/* There is no index.  Seek through the entire trace from the start, nice
 * and slowly.
 */
static int erf_slow_seek_start(libtrace_t *libtrace,uint64_t erfts UNUSED)
{
	if (INPUT.file) {
		libtrace_io_close(INPUT.file);
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
		DATA(libtrace)->seek.index=libtrace_io_open(buffer,"rb");
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
		off=libtrace_io_tell(INPUT.file);
	} while(trace_get_erf_timestamp(packet)<erfts);

	libtrace_io_seek(INPUT.file,off,SEEK_SET);

	return 0;
}

static int erf_init_output(libtrace_out_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct erf_format_data_out_t));

	OUT_OPTIONS.erf.level = 0;
	OUT_OPTIONS.erf.fileflag = O_CREAT | O_WRONLY;
	OUTPUT.file = 0;

	return 0;
}

static int erf_config_output(libtrace_out_t *libtrace, trace_option_output_t option,
		void *value) {

	switch (option) {
		case TRACE_OPTION_OUTPUT_COMPRESS:
			OUT_OPTIONS.erf.level = *(int*)value;
			return 0;
		case TRACE_OPTION_OUTPUT_FILEFLAGS:
			OUT_OPTIONS.erf.fileflag = *(int*)value;
			return 0;
		default:
			/* Unknown option */
			trace_set_err_out(libtrace,TRACE_ERR_UNKNOWN_OPTION,
					"Unknown option");
			return -1;
	}
}



static int erf_fin_input(libtrace_t *libtrace) {
	if (INPUT.file)
		libtrace_io_close(INPUT.file);
	free(libtrace->format_data);
	return 0;
}

static int erf_fin_output(libtrace_out_t *libtrace) {
	if (OUTPUT.file)
		libtrace_io_close(OUTPUT.file);
	free(libtrace->format_data);
	return 0;
}
 

static int erf_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int numbytes;
	unsigned int size;
	void *buffer2 = packet->buffer;
	unsigned int rlen;

	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
		packet->buf_control = TRACE_CTRL_PACKET;
		if (!packet->buffer) {
			trace_set_err(libtrace, errno, 
					"Cannot allocate memory");
			return -1;
		}
	}

	
	
	packet->header = packet->buffer;
	packet->type = TRACE_RT_DATA_ERF;

	if ((numbytes=libtrace_io_read(INPUT.file,
					packet->buffer,
					(size_t)dag_record_size)) == -1) {
		trace_set_err(libtrace,errno,"read(%s)",
				libtrace->uridata);
		return -1;
	}
	/* EOF */
	if (numbytes == 0) {
		return 0;
	}

	rlen = ntohs(((dag_record_t *)packet->buffer)->rlen);
	buffer2 = (char*)packet->buffer + dag_record_size;
	size = rlen - dag_record_size;

	if (size >= LIBTRACE_PACKET_BUFSIZE) {
		trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Packet size %u larger than supported by libtrace - packet is probably corrupt", size);
		return -1;
	}

	/* Unknown/corrupt */
	if (((dag_record_t *)packet->buffer)->type >= 10) {
		trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Corrupt or Unknown ERF type");
		return -1;
	}
	
	/* read in the rest of the packet */
	if ((numbytes=libtrace_io_read(INPUT.file,
					buffer2,
					(size_t)size)) != (int)size) {
		if (numbytes==-1) {
			trace_set_err(libtrace,errno, "read(%s)", libtrace->uridata);
			return -1;
		}
		trace_set_err(libtrace,EIO,"Truncated packet (wanted %d, got %d)", size, numbytes);
		/* Failed to read the full packet?  must be EOF */
		return -1;
	}
	if (((dag_record_t *)packet->buffer)->flags.rxerror == 1) {
		packet->payload = NULL;
	} else {
		packet->payload = (char*)packet->buffer + erf_get_framing_length(packet);
	}
	return rlen;
}

static int erf_dump_packet(libtrace_out_t *libtrace,
		dag_record_t *erfptr, unsigned int pad, void *buffer) {
	int numbytes = 0;
	int size;

	if ((numbytes = 
		libtrace_io_write(OUTPUT.file, 
				erfptr,
				(size_t)(dag_record_size + pad))) 
			!= (int)(dag_record_size+pad)) {
		trace_set_err_out(libtrace,errno,
				"write(%s)",libtrace->uridata);
		return -1;
	}

	size=ntohs(erfptr->rlen)-(dag_record_size+pad);
	numbytes=libtrace_io_write(OUTPUT.file, buffer, (size_t)size);
	if (numbytes != size) {
		trace_set_err_out(libtrace,errno,
				"write(%s)",libtrace->uridata);
		return -1;
	}
	return numbytes + pad + dag_record_size;
}

static int erf_start_output(libtrace_out_t *libtrace)
{
	OUTPUT.file = trace_open_file_out(libtrace,
			OUT_OPTIONS.erf.level,
			OUT_OPTIONS.erf.fileflag);
	if (!OUTPUT.file) {
		return -1;
	}
	return 0;
}

static bool find_compatible_linktype(libtrace_out_t *libtrace,
				libtrace_packet_t *packet)
{
	/* Keep trying to simplify the packet until we can find 
	 * something we can do with it */
	do {
		char type=libtrace_to_erf_type(trace_get_link_type(packet));

		/* Success */
		if (type != (char)-1)
			return true;

		if (!demote_packet(packet)) {
			trace_set_err_out(libtrace,
					TRACE_ERR_NO_CONVERSION,
					"No erf type for packet (%i)",
					trace_get_link_type(packet));
			return false;
		}

	} while(1);

	return true;
}
		
static int erf_write_packet(libtrace_out_t *libtrace, 
		libtrace_packet_t *packet) 
{
	int numbytes = 0;
	unsigned int pad = 0;
	dag_record_t *dag_hdr = (dag_record_t *)packet->header;
	void *payload = packet->payload;

	assert(OUTPUT.file);

	if (!packet->header) {
		/*trace_set_err_output(libtrace, TRACE_ERR_BAD_PACKET,
				"Packet has no header - probably an RT packet");
		*/
		return -1;
	}
	
	pad = erf_get_padding(packet);

	/* If we've had an rxerror, we have no payload to write - fix
	 * rlen to be the correct length 
	 */
	/* I Think this is bogus, we should somehow figure out
	 * a way to write out the payload even if it is gibberish -- Perry */
	if (payload == NULL) {
		dag_hdr->rlen = htons(dag_record_size + pad);
		
	} 
	
	if (packet->type == TRACE_RT_DATA_ERF) {
			numbytes = erf_dump_packet(libtrace,
				(dag_record_t *)packet->header,
				pad,
				payload
				);
	} else {
		dag_record_t erfhdr;
		/* convert format - build up a new erf header */
		/* Timestamp */
		erfhdr.ts = bswap_host_to_le64(trace_get_erf_timestamp(packet));

		/* Flags. Can't do this */
		memset(&erfhdr.flags,1,sizeof(erfhdr.flags));
		if (trace_get_direction(packet)!=~0U)
			erfhdr.flags.iface = trace_get_direction(packet);

		if (!find_compatible_linktype(libtrace,packet))
			return -1;

		payload=packet->payload;
		pad = erf_get_padding(packet);

		erfhdr.type = libtrace_to_erf_type(trace_get_link_type(packet));

		/* Packet length (rlen includes format overhead) */
		assert(trace_get_capture_length(packet)>0 
				&& trace_get_capture_length(packet)<=65536);
		assert(erf_get_framing_length(packet)>0 
				&& trace_get_framing_length(packet)<=65536);
		assert(
			trace_get_capture_length(packet)+erf_get_framing_length(packet)>0
		      &&trace_get_capture_length(packet)+erf_get_framing_length(packet)<=65536);
		erfhdr.rlen = htons(trace_get_capture_length(packet) 
			+ erf_get_framing_length(packet));
		/* loss counter. Can't do this */
		erfhdr.lctr = 0;
		/* Wire length, does not include padding! */
		erfhdr.wlen = htons(trace_get_wire_length(packet));

		/* Write it out */
		numbytes = erf_dump_packet(libtrace,
				&erfhdr,
				pad,
				payload);
	}
	return numbytes;
}

libtrace_linktype_t erf_get_link_type(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	if (erfptr->type != TYPE_LEGACY)
		return erf_type_to_libtrace(erfptr->type);
	else {
		/* Sigh, lets start wildly guessing */
		if (((char*)packet->payload)[4]==0x45)
			return TRACE_TYPE_PPP;
		return ~0;
	}
}

libtrace_direction_t erf_get_direction(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return erfptr->flags.iface;
}

libtrace_direction_t erf_set_direction(libtrace_packet_t *packet, libtrace_direction_t direction) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	erfptr->flags.iface = direction;
	return erfptr->flags.iface;
}

uint64_t erf_get_erf_timestamp(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return bswap_le_to_host64(erfptr->ts);
}

int erf_get_capture_length(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	int caplen;
	if (packet->payload == NULL)
		return 0; 
	
	erfptr = (dag_record_t *)packet->header;
	caplen = ntohs(erfptr->rlen) - erf_get_framing_length(packet);
	if (ntohs(erfptr->wlen) < caplen)
		return ntohs(erfptr->wlen);

	return (ntohs(erfptr->rlen) - erf_get_framing_length(packet));
}

int erf_get_wire_length(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
	return ntohs(erfptr->wlen);
}

size_t erf_set_capture_length(libtrace_packet_t *packet, size_t size) {
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

static struct libtrace_eventobj_t erf_event(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	struct libtrace_eventobj_t event = {0,0,0.0,0};
	
	if (IN_OPTIONS.real_time) {
		event.size = erf_read_packet(libtrace, packet);
		if (event.size < 1)
			event.type = TRACE_EVENT_TERMINATE;
		else
			event.type = TRACE_EVENT_PACKET;
		return event;
		
	} else {
		return trace_event_trace(libtrace, packet);
	}
	
}

static uint64_t erf_get_dropped_packets(libtrace_t *trace)
{
	return DATA(trace)->drops;
}

static void erf_help(void) {
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

static struct libtrace_format_t erfformat = {
	"erf",
	"$Id$",
	TRACE_FORMAT_ERF,
	erf_init_input,			/* init_input */	
	erf_config_input,		/* config_input */
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
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	erf_get_dropped_packets,	/* get_dropped_packets */
	NULL,				/* get_captured_packets */
	NULL,				/* get_fd */
	erf_event,			/* trace_event */
	erf_help,			/* help */
	NULL				/* next pointer */
};


void erf_constructor(void) {
	register_format(&erfformat);
}
