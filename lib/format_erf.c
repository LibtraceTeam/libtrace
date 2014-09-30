/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
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
#include "wandio.h"

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

/* This format module deals with reading and writing ERF traces. ERF is the
 * trace format developed by Endace for use by DAG hardware capture cards.
 *
 * ERF is not a live capture format. 
 *
 */


static struct libtrace_format_t erfformat;

#define DATA(x) ((struct erf_format_data_t *)x->format_data)
#define DATAOUT(x) ((struct erf_format_data_out_t *)x->format_data)

#define IN_OPTIONS DATA(libtrace)->options
#define OUTPUT DATAOUT(libtrace)
#define OUT_OPTIONS DATAOUT(libtrace)->options

/* "Global" data that is stored for each ERF input trace */
struct erf_format_data_t {
        
	/* Index used for seeking within a trace */
	struct {
		/* The index itself */
		io_t *index;
		/* The offset of the index */
		off_t index_len;
		/* Indicates the existence of an index */
		enum { INDEX_UNKNOWN=0, INDEX_NONE, INDEX_EXISTS } exists;
	} seek;

	/* Number of packets that were dropped during the capture */
	uint64_t drops;

	/* Config options for the input trace */
	struct {
		/* Flag indicating whether the event API should replicate the
		 * time gaps between each packet or return a PACKET event for
		 * each packet */
		int real_time;
	} options;
};

/* "Global" data that is stored for each ERF output trace */
struct erf_format_data_out_t {

	/* Config options for the output trace */
	struct {
		/* Compression level for the output file */
		int level;
		/* Compression type */
		int compress_type;
		/* File flags used to open the file, e.g. O_CREATE */
		int fileflag;
	} options;

	/* The output file itself */
	iow_t *file;
	
};

typedef struct erf_index_t {
	uint64_t timestamp;
	uint64_t offset; 
} erf_index_t;


/* Ethernet packets have a 2 byte padding before the packet
 * so that the IP header is aligned on a 32 bit boundary.
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

/* Attempts to determine whether a given trace file is using the ERF format
 *
 * Returns 1 if the trace is probably ERF, 0 otherwise
 */
static int erf_probe_magic(io_t *io)
{
	char buffer[4096];
	int len;
	dag_record_t *erf;
	len = wandio_peek(io, buffer, sizeof(buffer));
	if (len < (int)dag_record_size) {
		return 0; /* False */
	}
	erf = (dag_record_t *) buffer;
	/* If the record is too short */
	if (ntohs(erf->rlen) < dag_record_size) {
		return 0;
	}
	/* There aren't any erf traces before 1995-01-01 */
	if (bswap_le_to_host64(erf->ts) < 0x2f0539b000000000ULL) {
		return 0;
	}
	/* And not pcap! */
	if (bswap_le_to_host64(erf->ts) >>32 == 0xa1b2c3d4) {
		return 0;
	}
	/* And not the other pcap! */
	if (bswap_le_to_host64(erf->ts) >>32 == 0xd4c3b2a1) {
		return 0;
	}
	/* Is this a proper typed packet */
	if (erf->type > TYPE_AAL2) {
		return 0;
	}
	/* We should put some more tests in here. */
	/* Yeah, this is probably ERF */
	return 1;
}

static int erf_init_input(libtrace_t *libtrace) 
{
	libtrace->format_data = malloc(sizeof(struct erf_format_data_t));
	
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
        if (libtrace->io)
                return 0; /* Success -- already done. */

        libtrace->io = trace_open_file(libtrace);

        if (!libtrace->io)
                return -1;

        DATA(libtrace)->drops = 0;
        return 0; /* success */
}

/* Raw ERF is a special case -- we want to force libwandio to treat the file
 * as uncompressed so we can't just use trace_open_file() */
static int rawerf_start_input(libtrace_t *libtrace)
{
	if (libtrace->io)
		return 0; 

	libtrace->io = wandio_create_uncompressed(libtrace->uridata);

	if (!libtrace->io) {
		if (errno != 0) {
			trace_set_err(libtrace, errno, "Unable to open raw ERF file %s", libtrace->uridata);
		}
		return -1;
	}

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

		wandio_seek(DATA(libtrace)->seek.index,
				(int64_t)(current*sizeof(record)),
				SEEK_SET);
		wandio_read(DATA(libtrace)->seek.index,
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
		wandio_seek(DATA(libtrace)->seek.index,
				(int64_t)(current*sizeof(record)),SEEK_SET);
		wandio_read(DATA(libtrace)->seek.index,
				&record,sizeof(record));
		current--;
	} while(record.timestamp>erfts);

	/* We've found our location in the trace, now use it. */
	wandio_seek(libtrace->io,(int64_t) record.offset,SEEK_SET);

	return 0; /* success */
}

/* There is no index.  Seek through the entire trace from the start, nice
 * and slowly.
 */
static int erf_slow_seek_start(libtrace_t *libtrace,uint64_t erfts UNUSED)
{
	if (libtrace->io) {
		wandio_destroy(libtrace->io);
	}
	libtrace->io = trace_open_file(libtrace);
	if (!libtrace->io)
		return -1;
	return 0;
}

/* Seek within an ERF trace based on an ERF timestamp */
static int erf_seek_erf(libtrace_t *libtrace,uint64_t erfts)
{
	libtrace_packet_t *packet;
	off_t off = 0;

	if (DATA(libtrace)->seek.exists==INDEX_UNKNOWN) {
		char buffer[PATH_MAX];
		snprintf(buffer,sizeof(buffer),"%s.idx",libtrace->uridata);
		DATA(libtrace)->seek.index=wandio_create(buffer);
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
		off=wandio_tell(libtrace->io);
	} while(trace_get_erf_timestamp(packet)<erfts);

	wandio_seek(libtrace->io,off,SEEK_SET);

	return 0;
}

static int erf_init_output(libtrace_out_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct erf_format_data_out_t));

	OUT_OPTIONS.level = 0;
	OUT_OPTIONS.compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
	OUT_OPTIONS.fileflag = O_CREAT | O_WRONLY;
	OUTPUT->file = 0;

	return 0;
}

static int erf_config_output(libtrace_out_t *libtrace, 
		trace_option_output_t option, void *value) {

	switch (option) {
		case TRACE_OPTION_OUTPUT_COMPRESS:
			OUT_OPTIONS.level = *(int*)value;
			return 0;
		case TRACE_OPTION_OUTPUT_COMPRESSTYPE:
			OUT_OPTIONS.compress_type = *(int*)value;
			return 0;
		case TRACE_OPTION_OUTPUT_FILEFLAGS:
			OUT_OPTIONS.fileflag = *(int*)value;
			return 0;
		default:
			/* Unknown option */
			trace_set_err_out(libtrace,TRACE_ERR_UNKNOWN_OPTION,
					"Unknown option");
			return -1;
	}
}



static int erf_fin_input(libtrace_t *libtrace) {
	if (libtrace->io)
		wandio_destroy(libtrace->io);
	free(libtrace->format_data);
	return 0;
}

static int erf_fin_output(libtrace_out_t *libtrace) {
	if (OUTPUT->file)
		wandio_wdestroy(OUTPUT->file);
	free(libtrace->format_data);
	return 0;
}
 
static int erf_prepare_packet(libtrace_t *libtrace, libtrace_packet_t *packet,
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
	
	
	packet->type = rt_type;
	packet->buffer = buffer;
	packet->header = buffer;
	erfptr = (dag_record_t *)packet->buffer;
	if (erfptr->flags.rxerror == 1) {
		packet->payload = NULL;
	} else {
		packet->payload = (char*)packet->buffer + erf_get_framing_length(packet);
	}
	
	if (libtrace->format_data == NULL) {
		/* Allocates the format_data structure */
		if (erf_init_input(libtrace)) 
			return -1;
	}

	/* Check for loss */
	if (erfptr->type == TYPE_DSM_COLOR_ETH) {
		/* No idea how we get this yet */

	} else if (erfptr->lctr) {
		DATA(libtrace)->drops += ntohs(erfptr->lctr);
	}

	return 0;
}

static int erf_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int numbytes;
	unsigned int size;
	void *buffer2 = packet->buffer;
	unsigned int rlen;
	uint32_t flags = 0;
	
	
	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
		if (!packet->buffer) {
			trace_set_err(libtrace, errno, 
					"Cannot allocate memory");
			return -1;
		}
	}

	flags |= TRACE_PREP_OWN_BUFFER;	
	
	if ((numbytes=wandio_read(libtrace->io,
					packet->buffer,
					(size_t)dag_record_size)) == -1) {
		trace_set_err(libtrace,errno,"reading ERF file");
		return -1;
	}
	/* EOF */
	if (numbytes == 0) {
		return 0;
	}

        if (numbytes < (int)dag_record_size) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Incomplete ERF header");
                return -1;
        }

	rlen = ntohs(((dag_record_t *)packet->buffer)->rlen);
	buffer2 = (char*)packet->buffer + dag_record_size;
	size = rlen - dag_record_size;

	if (size >= LIBTRACE_PACKET_BUFSIZE) {
		trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, 
				"Packet size %u larger than supported by libtrace - packet is probably corrupt", 
				size);
		return -1;
	}

	/* Unknown/corrupt */
	if (((dag_record_t *)packet->buffer)->type >= TYPE_RAW_LINK) {
		trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, 
				"Corrupt or Unknown ERF type");
		return -1;
	}
	
	/* read in the rest of the packet */
	if ((numbytes=wandio_read(libtrace->io,
					buffer2,
					(size_t)size)) != (int)size) {
		if (numbytes==-1) {
			trace_set_err(libtrace,errno, "read(%s)", 
					libtrace->uridata);
			return -1;
		}
		trace_set_err(libtrace,EIO,
				"Truncated packet (wanted %d, got %d)", 
				size, numbytes);
		/* Failed to read the full packet?  must be EOF */
		return -1;
	}

        if (numbytes < (int)size) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Incomplete ERF record");
                return -1;
        }
	
	if (erf_prepare_packet(libtrace, packet, packet->buffer, 
				TRACE_RT_DATA_ERF, flags))
		return -1;
	
	return rlen;
}

static int erf_dump_packet(libtrace_out_t *libtrace,
		dag_record_t *erfptr, unsigned int pad, void *buffer) {
	int numbytes = 0;
	int size;

	if ((numbytes = 
		wandio_wwrite(OUTPUT->file, 
				erfptr,
				(size_t)(dag_record_size + pad))) 
			!= (int)(dag_record_size+pad)) {
		trace_set_err_out(libtrace,errno,
				"write(%s)",libtrace->uridata);
		return -1;
	}

	size=ntohs(erfptr->rlen)-(dag_record_size+pad);
	numbytes=wandio_wwrite(OUTPUT->file, buffer, (size_t)size);
	if (numbytes != size) {
		trace_set_err_out(libtrace,errno,
				"write(%s)",libtrace->uridata);
		return -1;
	}
	return numbytes + pad + dag_record_size;
}

static int erf_start_output(libtrace_out_t *libtrace)
{
	OUTPUT->file = trace_open_file_out(libtrace,
			OUT_OPTIONS.compress_type,
			OUT_OPTIONS.level,
			OUT_OPTIONS.fileflag);

	if (!OUTPUT->file) {
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

	assert(OUTPUT->file);

	if (trace_get_link_type(packet) == TRACE_TYPE_NONDATA)
		return 0;

	if (!packet->header) {
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
		int rlen;
		/* convert format - build up a new erf header */
		/* Timestamp */
		erfhdr.ts = bswap_host_to_le64(trace_get_erf_timestamp(packet));

		/* Flags. Can't do this */
		memset(&erfhdr.flags,1,sizeof(erfhdr.flags));
		if (trace_get_direction(packet)!=TRACE_DIR_UNKNOWN)
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

		rlen = trace_get_capture_length(packet) + 
				erf_get_framing_length(packet);
		assert(rlen > 0 && rlen <= 65536);
		erfhdr.rlen = htons(rlen);
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
		/* Can't make a packet larger */
		return trace_get_capture_length(packet);
	}
	/* Reset cached capture length - otherwise we will both return the
	 * wrong value here and subsequent get_capture_length() calls will
	 * return the wrong value. */
	packet->capture_length = -1;
	erfptr = (dag_record_t *)packet->header;
	erfptr->rlen = htons(size + erf_get_framing_length(packet));
	return trace_get_capture_length(packet);
}

static struct libtrace_eventobj_t erf_event(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	struct libtrace_eventobj_t event = {0,0,0.0,0};
	
	/* If we are being told to replay packets as fast as possible, then
	 * we just need to read and return the next packet in the trace */
	if (IN_OPTIONS.real_time) {
		event.size = trace_read_packet(libtrace, packet);
		if (event.size < 1)
			event.type = TRACE_EVENT_TERMINATE;
		else
			event.type = TRACE_EVENT_PACKET;
		return event;
		
	} else {
		/* Otherwise, use the generic event function */
		return trace_event_trace(libtrace, packet);
	}
	
}

static uint64_t erf_get_dropped_packets(libtrace_t *trace)
{
	if (trace->format_data == NULL)
		return (uint64_t)-1;
	return DATA(trace)->drops;
}

static void erf_help(void) {
	printf("erf format module: $Revision: 1752 $\n");
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

	
}

static struct libtrace_format_t erfformat = {
	"erf",
	"$Id$",
	TRACE_FORMAT_ERF,
	NULL,				/* probe filename */
	erf_probe_magic,		/* probe magic */
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
	erf_prepare_packet,		/* prepare_packet */
	NULL,				/* fin_packet */
	erf_write_packet,		/* write_packet */
	erf_get_link_type,		/* get_link_type */
	erf_get_direction,		/* get_direction */
	erf_set_direction,		/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_timespec */
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

static struct libtrace_format_t rawerfformat = {
	"rawerf",
	"$Id$",
	TRACE_FORMAT_RAWERF,
	NULL,				/* probe filename */
	NULL,		/* probe magic */
	erf_init_input,			/* init_input */	
	erf_config_input,		/* config_input */
	rawerf_start_input,		/* start_input */
	NULL,				/* pause_input */
	erf_init_output,		/* init_output */
	erf_config_output,		/* config_output */
	erf_start_output,		/* start_output */
	erf_fin_input,			/* fin_input */
	erf_fin_output,			/* fin_output */
	erf_read_packet,		/* read_packet */
	erf_prepare_packet,		/* prepare_packet */
	NULL,				/* fin_packet */
	erf_write_packet,		/* write_packet */
	erf_get_link_type,		/* get_link_type */
	erf_get_direction,		/* get_direction */
	erf_set_direction,		/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_timespec */
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
	register_format(&rawerfformat);
}
