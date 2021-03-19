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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config.h"
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "format_erf.h"
#include "wandio.h"

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

#define ERF_META_TYPE 27

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

	bool discard_meta;

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

static int libtrace_to_erf_hdr(libtrace_out_t *libtrace, libtrace_packet_t *packet,
    dag_record_t *erf, int *framinglen, int *caplen);

static bool erf_can_write(libtrace_packet_t *packet) {
	/* Get the linktype */
        libtrace_linktype_t ltype = trace_get_link_type(packet);

        if (ltype == TRACE_TYPE_CONTENT_INVALID) {
                return false;
        }
        if (ltype == TRACE_TYPE_PCAPNG_META
                || ltype == TRACE_TYPE_NONDATA) {

                return false;
        }

        return true;
}

/* Ethernet packets have a 2 byte padding before the packet
 * so that the IP header is aligned on a 32 bit boundary.
 */
int erf_get_padding(const libtrace_packet_t *packet)
{
        dag_record_t *erfptr = (dag_record_t *)packet->header;

        switch(packet->trace->format->type) {
                case TRACE_FORMAT_ERF:
                case TRACE_FORMAT_NDAG:
                case TRACE_FORMAT_RAWERF:
                case TRACE_FORMAT_DPDK_NDAG:
                        switch((erfptr->type & 0x7f)) {
                                case TYPE_ETH:
                                case TYPE_COLOR_ETH:
                                case TYPE_DSM_COLOR_ETH:
                                case TYPE_COLOR_HASH_ETH:
                                        return 2;
                                default:
                                        return 0;
                        }
                        break;
                default:
                        switch(trace_get_link_type(packet)) {
                                case TRACE_TYPE_ETH:	return 2;
                                default:		return 0;
                        }
                        break;
	}
        return 0;
}

int erf_is_color_type(uint8_t erf_type)
{
	switch(erf_type & 0x7f) {
		case TYPE_COLOR_HDLC_POS:
		case TYPE_DSM_COLOR_HDLC_POS:
		case TYPE_COLOR_ETH:
		case TYPE_DSM_COLOR_ETH:
		case TYPE_COLOR_HASH_POS:
		case TYPE_COLOR_HASH_ETH:
			return 1;
	}

	return 0;
}

int erf_get_framing_length(const libtrace_packet_t *packet)
{
        uint16_t extsize = 0;
	dag_record_t *erfptr = NULL;
        uint64_t *exthdr = NULL;
        uint8_t *firstbyte;

        erfptr = (dag_record_t *)packet->header;
        if ((erfptr->type & 0x80) == 0x80) {
                /* Extension headers are present */
                exthdr = (uint64_t *)((char *)packet->header + dag_record_size);
                extsize += 8;

                firstbyte = (uint8_t *)exthdr;
                while ((*firstbyte & 0x80) == 0x80) {
                        extsize += 8;
                        exthdr ++;
                        firstbyte = (uint8_t *)exthdr;
			if (extsize > ntohs(erfptr->rlen)) {
				trace_set_err(packet->trace, TRACE_ERR_BAD_PACKET, "Extension size is greater than dag record record length in erf_get_framing_length()");
				return -1;
			}
                }
        }
	return dag_record_size + extsize + erf_get_padding(packet);
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
	if ((erf->type & 0x7f) > ERF_TYPE_MAX) {
		return 0;
	}
	/* We should put some more tests in here. */
	/* Yeah, this is probably ERF */
	return 1;
}

static int erf_init_input(libtrace_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct erf_format_data_t));

	if (!libtrace->format_data) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable to allocate memory for "
			"format data inside erf_init_input()");
		return -1;
	}

	IN_OPTIONS.real_time = 0;
	DATA(libtrace)->drops = 0;

	DATA(libtrace)->discard_meta = 0;

	return 0; /* success */
}

static int erf_config_input(libtrace_t *libtrace, trace_option_t option,
		void *value) {

	switch (option) {
		case TRACE_OPTION_EVENT_REALTIME:
			IN_OPTIONS.real_time = *(int *)value;
			return 0;
                case TRACE_OPTION_CONSTANT_ERF_FRAMING:
                        trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                                        "Setting constant framing length is not supported for %s:", libtrace->format->name);
                        return -1;
		case TRACE_OPTION_SNAPLEN:
		case TRACE_OPTION_PROMISC:
		case TRACE_OPTION_FILTER:
		case TRACE_OPTION_META_FREQ:
			trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
					"Unsupported option");
			return -1;
		case TRACE_OPTION_DISCARD_META:
			if (*(int *)value > 0) {
				DATA(libtrace)->discard_meta = true;
			} else {
				DATA(libtrace)->discard_meta = false;
			}
			return 0;
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
			trace_set_err(libtrace, TRACE_ERR_SEEK_ERF, "Cannot seek to erf timestamp with unknown index in erf_seek_erf()");
			return -1;
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

	if (!libtrace->format_data) {
		trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "Unable to allocate memory for "
			"format data inside erf_init_output()");
		return -1;
	}

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
		packet->payload = ((char*)packet->buffer) + trace_get_framing_length(packet);
	}

	if (erfptr->rlen == 0) {
		trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "ERF packet has an invalid record "
			"length: zero, in erf_prepare_packet()\n");
		return -1;
	}

	if (libtrace->format_data == NULL) {
		/* Allocates the format_data structure */
		if (erf_init_input(libtrace)) 
			return -1;
	}

	/* Check for loss */
	if (erf_is_color_type(erfptr->type)) {
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
	libtrace_rt_types_t linktype;
	int gotpacket = 0;

	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
		packet->buffer = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
		if (!packet->buffer) {
			trace_set_err(libtrace, errno, "Cannot allocate memory");
			return -1;
		}
	}

	flags |= TRACE_PREP_OWN_BUFFER;

	while (!gotpacket) {

		if ((numbytes=wandio_read(libtrace->io, packet->buffer,
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
		if ((((dag_record_t *)packet->buffer)->type & 0x7f) > ERF_TYPE_MAX) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, 
				"Corrupt or Unknown ERF type");
			return -1;
		}

		/* read in the rest of the packet */
		if ((numbytes=wandio_read(libtrace->io, buffer2,
			(size_t)size)) != (int)size) {

			if (numbytes==-1) {
				trace_set_err(libtrace,errno, "read(%s)", 
					libtrace->uridata);
				return -1;
			}

			trace_set_err(libtrace,EIO,
				"Truncated packet (wanted %d, got %d)", size, numbytes);

			/* Failed to read the full packet?  must be EOF */
			return -1;
		}

        	if (numbytes < (int)size) {
                	trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Incomplete ERF record");
                	return -1;
        	}

		/* If a provenance packet make sure correct rt linktype is set.
	 	 * Only bits 0-6 are used for the type */
		if ((((dag_record_t *)packet->buffer)->type & 127) == ERF_META_TYPE) {
			linktype = TRACE_RT_ERF_META;
		} else { linktype = TRACE_RT_DATA_ERF; }

		/* If this is a meta packet and TRACE_OPTION_DISCARD_META is set
		 * ignore this packet and get another */
		if ((linktype == TRACE_RT_ERF_META && !DATA(libtrace)->discard_meta) ||
			linktype == TRACE_RT_DATA_ERF) {
			gotpacket = 1;

			if (erf_prepare_packet(libtrace, packet, packet->buffer, linktype, flags)) {
				return -1;
			}
		}
	}

	return rlen;
}

bool find_compatible_linktype(libtrace_out_t *libtrace,
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

static int libtrace_to_erf_hdr(libtrace_out_t *libtrace, libtrace_packet_t *packet,
    dag_record_t *erf, int *framinglen, int *caplen) {

    // populate erf header if this is not a erf packet
    if (packet->type != TRACE_RT_DATA_ERF) {
        /* Populate metadata from the packet before demoting and possibly losing it */
        libtrace_direction_t dir = trace_get_direction(packet);
        memset(&erf->flags, 0, sizeof(erf->flags));
        erf->ts = bswap_host_to_le64(trace_get_erf_timestamp(packet));
        if (dir != TRACE_DIR_UNKNOWN)
            erf->flags.iface = dir;
        else
            /* Probably uneeded, the original memset would (unintentionally?) set this to 1 */
            erf->flags.iface = TRACE_DIR_INCOMING;

        /* Demote the packet to a linktype we can send, e.g. find Ethernet */
        if (!find_compatible_linktype(libtrace,packet))
            return -1;

        /* Fill in the packet size, it may have changed after demotion */
        *framinglen = dag_record_size + erf_get_padding(packet);
    } else {
        *framinglen = trace_get_framing_length(packet);
    }

    /* If we've had an rxerror, we have no payload to write.
     *
     * I Think this is bogus, we should somehow figure out
     * a way to write out the payload even if it is gibberish -- Perry
     */
    if (packet->payload == NULL)
        caplen = 0;
    else
        *caplen = trace_get_capture_length(packet);

    if (*caplen <= 0 || *caplen > 65536) {
        trace_set_err_out(libtrace, TRACE_ERR_BAD_PACKET,
            "Capture length is out of range in libtrace_to_erf_hdr()");
        return -1;
    }

    if (*framinglen > 65536) {
        trace_set_err_out(libtrace, TRACE_ERR_BAD_PACKET,
            "Framing length is to large in libtrace_to_erf_hdr()");
        return -1;
    }

    if (*caplen + *framinglen <= 0 || *caplen + *framinglen > 65536) {
        trace_set_err_out(libtrace, TRACE_ERR_BAD_PACKET,
            "Capture + framing length is out of range in libtrace_to_erf_hdr()");
        return -1;
    }

    erf->type = libtrace_to_erf_type(trace_get_link_type(packet));
    erf->rlen = htons(*framinglen + *caplen);
    // loss counter. Can't do this
    erf->lctr = 0;
    erf->wlen = htons(trace_get_wire_length(packet));

    return 0;
}

static int erf_dump_packet(libtrace_out_t *libtrace, dag_record_t *erfptr,
	int framinglen, void *buffer, int caplen) {

	int numbytes;

	// write out ERF header
	numbytes = wandio_wwrite(OUTPUT->file, erfptr, (size_t)(framinglen));
	if (numbytes != framinglen) {
		trace_set_err_out(libtrace,errno,
			"write(%s)",libtrace->uridata);
		return -1;
	}

	// write out packet payload
	numbytes = wandio_wwrite(OUTPUT->file, buffer, (size_t)caplen);
	if (numbytes != caplen) {
		trace_set_err_out(libtrace,errno,
			"write(%s)",libtrace->uridata);
		return -1;
	}

	return framinglen + caplen;
}

static int erf_flush_output(libtrace_out_t *libtrace) {
        return wandio_wflush(OUTPUT->file);
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

static int erf_write_packet(libtrace_out_t *libtrace, 
		libtrace_packet_t *packet) 
{

	/* Check erf can write this type of packet */
	if (!erf_can_write(packet)) {
		return 0;
	}

	int framinglen;
	int caplen;
	dag_record_t *dag_hdr;

	if (!OUTPUT->file) {
		trace_set_err_out(libtrace, TRACE_ERR_BAD_IO, "Attempted to write ERF packets to a "
			"closed file, must call trace_create_output() before calling trace_write_output()");
		return -1;
	}

	if (!packet->header) {
		return -1;
	}

	if (packet->type == TRACE_RT_DATA_ERF) {
                dag_hdr = (dag_record_t *)packet->header;
                if (libtrace_to_erf_hdr(libtrace, packet, dag_hdr, &framinglen, &caplen) < 0)
                        return -1;
		return erf_dump_packet(libtrace,
				       dag_hdr,
				       framinglen,
				       packet->payload,
				       caplen);
	} else {
		dag_record_t erfhdr;
		if (libtrace_to_erf_hdr(libtrace, packet, &erfhdr, &framinglen, &caplen) < 0)
			return -1;
		return erf_dump_packet(libtrace,
				       &erfhdr,
				       framinglen,
				       packet->payload,
				       caplen);
	}
}

libtrace_linktype_t erf_get_link_type(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
        uint8_t type;

        if (packet->header == NULL) {
                return ~0;
        }

        type = (erfptr->type & 0x7f);
	if (type != TYPE_LEGACY) {
		/* The top-most bit is now used to indicate the presence of
                 * extension headers :/ */
                return erf_type_to_libtrace(type);
        }
	else {
                if (trace_get_capture_length(packet) < 5 ||
                                packet->payload == NULL) {
                        return ~0;
                }

		/* Sigh, lets start wildly guessing */
		if (((char*)packet->payload)[4]==0x45)
			return TRACE_TYPE_PPP;
		return ~0;
	}
}

libtrace_direction_t erf_get_direction(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;
        if (packet->header) {
        	return erfptr->flags.iface;
        }
        return TRACE_DIR_UNKNOWN;
}

libtrace_direction_t erf_set_direction(libtrace_packet_t *packet, libtrace_direction_t direction) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;

        if (packet->header == NULL) {
                return TRACE_DIR_UNKNOWN;
        }
	erfptr->flags.iface = direction;
	return erfptr->flags.iface;
}

uint64_t erf_get_erf_timestamp(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;

        if (erfptr == NULL) {
                return 0;
        }
	return bswap_le_to_host64(erfptr->ts);
}

int erf_get_capture_length(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	int caplen;
        size_t framinglen;
        uint16_t wlen, rlen;

	if (packet->payload == NULL || packet->header == NULL)
		return 0;

	erfptr = (dag_record_t *)packet->header;
        framinglen = trace_get_framing_length(packet);
        rlen = ntohs(erfptr->rlen);
        wlen = ntohs(erfptr->wlen);

        caplen = rlen - framinglen;

	if (wlen < caplen)
		return wlen;

        return caplen;
}

int erf_get_wire_length(const libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->header;

        if (packet->header == NULL) {
                return 0;
        }

	if ((erfptr->type & 0x7f) == TYPE_META)
		return 0;

	return ntohs(erfptr->wlen);
}

size_t erf_set_capture_length(libtrace_packet_t *packet, size_t size) {
	dag_record_t *erfptr = 0;
        uint16_t wlen;

	if (!packet) {
		fprintf(stderr, "NULL packet passed to erf_set_capture_length()\n");
		return ~0U;
	}
	erfptr = (dag_record_t *)packet->header;

        if (packet->header == NULL) {
                return ~0U;
        }

	if(size > trace_get_capture_length(packet) || (erfptr->type & 0x7f) == TYPE_META) {
		/* Can't make a packet larger */
		return trace_get_capture_length(packet);
	}

	/* Reset cached capture length - otherwise we will both return the
	 * wrong value here and subsequent get_capture_length() calls will
	 * return the wrong value. */
	packet->cached.capture_length = -1;
	erfptr->rlen = htons(size + trace_get_framing_length(packet));
        wlen = ntohs(erfptr->wlen);

        if (wlen < size) {
                return wlen;
        }

	return size;
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

static void erf_get_statistics(libtrace_t *trace, libtrace_stat_t *stat) {

        if (trace->format_data) {
                stat->dropped_valid = 1;
                stat->dropped = DATA(trace)->drops;
        }
}

static char *erf_get_option_name(uint32_t option) {
	switch(option) {
		case (ERF_PROV_COMMENT): return "Comment";
                case (ERF_PROV_GEN_TIME): return "Time generated";
                case (ERF_PROV_FCS_LEN): return "FCS Length";
                case (ERF_PROV_MASK_CIDR): return "Subnet CIDR";
                case (ERF_PROV_NAME): return "Name";
                case (ERF_PROV_DESCR): return "Description";
                case (ERF_PROV_APP_NAME): return "Application Name";
                case (ERF_PROV_HOSTNAME): return "Hostname";
                case (ERF_PROV_OS): return "Operating System";
                case (ERF_PROV_MODEL): return "Model";
                case (ERF_PROV_FW_VERSION): return "Firmware Version";
                case (ERF_PROV_SERIAL_NO): return "Serial Number";
                case (ERF_PROV_ORG_NAME): return "Organisation Name";
                case (ERF_PROV_SNAPLEN): return "Snap length";
                case (ERF_PROV_CARD_NUM): return "DAG Card Number";
                case (ERF_PROV_MODULE_NUM): return "DAG Module Number";
                case (ERF_PROV_LOC_NAME): return "Capture Location";
                case (ERF_PROV_FLOW_HASH_MODE): return "Flow Hash Mode";
		case (ERF_PROV_FILTER): return "Filter";
                case (ERF_PROV_TUNNELING_MODE): return "Tunneling Mode";
		case (ERF_PROV_ROTFILE_NAME): return "Rotfile Name";
                case (ERF_PROV_LOC_DESCR): return "Location Description";
                case (ERF_PROV_MEM): return "Stream Buffer Memory";
                case (ERF_PROV_DEV_NAME): return "DAG Device Name";
                case (ERF_PROV_DEV_PATH): return "DAG Device Path";
                case (ERF_PROV_APP_VERSION): return "Capture Application Version";
                case (ERF_PROV_CPU): return "CPU";
                case (ERF_PROV_CPU_PHYS_CORES): return "CPU Cores";
                case (ERF_PROV_CPU_NUMA_NODES): return "CPU NUMA Nodes";
                case (ERF_PROV_DAG_VERSION): return "DAG Software Version";
                case (ERF_PROV_IF_NUM): return "Interface Number";
                case (ERF_PROV_IF_SPEED): return "Interface Speed";
                case (ERF_PROV_IF_IPV4): return "Interface IPv4";
                case (ERF_PROV_IF_IPV6): return "Interface IPv6";
                case (ERF_PROV_IF_MAC): return "Interface MAC";
                case (ERF_PROV_IF_SFP_TYPE): return "Transceiver Type";
                case (ERF_PROV_IF_LINK_STATUS): return "Link Status";
                case (ERF_PROV_IF_PHY_MODE): return "PHY Mode";
                case (ERF_PROV_IF_PORT_TYPE): return "Port Type";
		case (ERF_PROV_IF_RX_LATENCY): return "Latency";
                case (ERF_PROV_IF_RX_POWER): return "Optical RX Power";
                case (ERF_PROV_IF_TX_POWER): return "Optical TX Power";
                case (ERF_PROV_CLK_SOURCE): return "CLK Source";
                case (ERF_PROV_CLK_STATE): return "CLK State";
                case (ERF_PROV_CLK_THRESHOLD): return "CLK Threshold";
                case (ERF_PROV_CLK_CORRECTION): return "CLK Correction";
                case (ERF_PROV_CLK_FAILURES): return "CLK Failures";
                case (ERF_PROV_CLK_RESYNCS): return "CLK Resyncs";
                case (ERF_PROV_CLK_PHASE_ERROR): return "CLK Phase Errors";
                case (ERF_PROV_CLK_INPUT_PULSES): return "CLK Input Pulses";
                case (ERF_PROV_CLK_REJECTED_PULSES): return "CLK Rejected Pulses";
                case (ERF_PROV_CLK_PHC_INDEX): return "CLK PHC Index";
                case (ERF_PROV_CLK_PHC_OFFSET): return "CLK PHC Offset";
                case (ERF_PROV_CLK_TIMEBASE): return "CLK Timebase";
                case (ERF_PROV_CLK_DESCR): return "CLK Description";
                case (ERF_PROV_CLK_OUT_SOURCE): return "CLK Output Source" ;
                case (ERF_PROV_CLK_LINK_MODE): return "CLK Link Mode";
                case (ERF_PROV_PTP_DOMAIN_NUM): return "PTP Domain Number";
                case (ERF_PROV_PTP_STEPS_REMOVED): return "PTP Steps removed";
                case (ERF_PROV_CLK_PORT_PROTO): return "CLK Port Protocol";
                case (ERF_PROV_STREAM_NUM): return "Stream Number";
                case (ERF_PROV_STREAM_DROP): return "Stream Dropped Records";
                case (ERF_PROV_STREAM_BUF_DROP): return "Stream Dropped Records (Buffer Overflow)";
		default:
			return "Unknown";
	}
	return "duno";
}

static libtrace_meta_datatype_t erf_get_datatype(uint32_t option) {
	switch(option) {
		case (ERF_PROV_COMMENT): return TRACE_META_STRING;
                case (ERF_PROV_GEN_TIME): return TRACE_META_UINT64;
		case (ERF_PROV_FCS_LEN): return TRACE_META_UINT32;
		case (ERF_PROV_MASK_CIDR): return TRACE_META_UINT32;
		case (ERF_PROV_NAME): return TRACE_META_STRING;
		case (ERF_PROV_DESCR): return TRACE_META_STRING;
		case (ERF_PROV_APP_NAME): return TRACE_META_STRING;
		case (ERF_PROV_HOSTNAME): return TRACE_META_STRING;
		case (ERF_PROV_OS): return TRACE_META_STRING;
		case (ERF_PROV_MODEL): return TRACE_META_STRING;
		case (ERF_PROV_FW_VERSION): return TRACE_META_STRING;
		case (ERF_PROV_SERIAL_NO): return TRACE_META_STRING;
		case (ERF_PROV_ORG_NAME): return TRACE_META_STRING;
		case (ERF_PROV_SNAPLEN): return TRACE_META_UINT32;
		case (ERF_PROV_CARD_NUM): return TRACE_META_UINT32;
		case (ERF_PROV_MODULE_NUM): return TRACE_META_UINT32;
		case (ERF_PROV_LOC_NAME): return TRACE_META_STRING;
		case (ERF_PROV_FILTER): return TRACE_META_STRING;
		case (ERF_PROV_FLOW_HASH_MODE): return TRACE_META_UINT32;
		case (ERF_PROV_TUNNELING_MODE): return TRACE_META_UINT32;
		case (ERF_PROV_ROTFILE_NAME): return TRACE_META_STRING;
		case (ERF_PROV_LOC_DESCR): return TRACE_META_STRING;
		case (ERF_PROV_MEM): return TRACE_META_UINT64;
		case (ERF_PROV_DEV_NAME): return TRACE_META_STRING;
		case (ERF_PROV_DEV_PATH): return TRACE_META_STRING;
		case (ERF_PROV_APP_VERSION): return TRACE_META_STRING;
		case (ERF_PROV_CPU): return TRACE_META_STRING;
		case (ERF_PROV_CPU_PHYS_CORES): return TRACE_META_UINT32;
		case (ERF_PROV_CPU_NUMA_NODES): return TRACE_META_UINT32;
		case (ERF_PROV_DAG_VERSION): return TRACE_META_STRING;
		case (ERF_PROV_IF_NUM): return TRACE_META_UINT32;
		case (ERF_PROV_IF_SPEED): return TRACE_META_UINT64;
		case (ERF_PROV_IF_IPV4): return TRACE_META_IPV4;
		case (ERF_PROV_IF_IPV6): return TRACE_META_IPV6;
		case (ERF_PROV_IF_MAC): return TRACE_META_MAC;
		case (ERF_PROV_IF_SFP_TYPE): return TRACE_META_STRING;
		case (ERF_PROV_IF_LINK_STATUS): return TRACE_META_UINT32;
		case (ERF_PROV_IF_PHY_MODE): return TRACE_META_STRING;
		case (ERF_PROV_IF_PORT_TYPE): return TRACE_META_UINT32;
		/* this is a ts_rel, need to double check */
		case (ERF_PROV_IF_RX_LATENCY): return TRACE_META_UINT64;
		case (ERF_PROV_IF_RX_POWER): return TRACE_META_UINT32;
		case (ERF_PROV_IF_TX_POWER): return TRACE_META_UINT32;
		case (ERF_PROV_CLK_SOURCE): return TRACE_META_UINT32;
		case (ERF_PROV_CLK_STATE): return TRACE_META_UINT32;
		/* this is a ts_rel, need to double check */
		case (ERF_PROV_CLK_THRESHOLD): return TRACE_META_UINT64;
		/* this is a ts_rel, need to double check */
		case (ERF_PROV_CLK_CORRECTION): return TRACE_META_UINT64;
		case (ERF_PROV_CLK_FAILURES): return TRACE_META_UINT32;
		case (ERF_PROV_CLK_RESYNCS): return TRACE_META_UINT32;
		/* this is a ts_rel, need to double check */
		case (ERF_PROV_CLK_PHASE_ERROR): return TRACE_META_UINT64;
		case (ERF_PROV_CLK_INPUT_PULSES): return TRACE_META_UINT32;
		case (ERF_PROV_CLK_REJECTED_PULSES): return TRACE_META_UINT32;
		case (ERF_PROV_CLK_PHC_INDEX): return TRACE_META_UINT32;
		/* this is a ts_rel, need to double check */
		case (ERF_PROV_CLK_PHC_OFFSET): return TRACE_META_UINT64;
		case (ERF_PROV_CLK_TIMEBASE): return TRACE_META_STRING;
		case (ERF_PROV_CLK_DESCR): return TRACE_META_STRING;
		case (ERF_PROV_CLK_OUT_SOURCE): return TRACE_META_UINT32;
		case (ERF_PROV_CLK_LINK_MODE): return TRACE_META_UINT32;
		case (ERF_PROV_PTP_DOMAIN_NUM): return TRACE_META_UINT32;
		case (ERF_PROV_PTP_STEPS_REMOVED): return TRACE_META_UINT32;
		case (ERF_PROV_CLK_PORT_PROTO): return TRACE_META_UINT32;
                case (ERF_PROV_STREAM_NUM): return TRACE_META_UINT32;
                case (ERF_PROV_STREAM_DROP): return TRACE_META_UINT32;
                case (ERF_PROV_STREAM_BUF_DROP): return TRACE_META_UINT32;
		default:
			return TRACE_META_UNKNOWN;
	}
}

/* An ERF provenance packet can contain multiple sections of the same type per packet */
libtrace_meta_t *erf_get_all_meta(libtrace_packet_t *packet) {

	void *ptr;
	dag_record_t *hdr;
	dag_sec_t *sec;
	uint16_t tmp;
	uint16_t remaining;
	uint16_t curr_sec = 0;

	if (packet == NULL) {
		fprintf(stderr, "NULL packet passed into erf_get_all_meta()\n");
		return NULL;
	}
	if (packet->buffer == NULL) { return NULL; }

	hdr = (dag_record_t *)packet->buffer;
	ptr = packet->payload;

	/* ensure this packet is a meta packet */
	if ((hdr->type & 127) != ERF_META_TYPE) { return NULL; }
	/* set remaining to size of packet minus header length */
	remaining = ntohs(hdr->rlen) - 24;

	/* setup structure to hold the result */
        libtrace_meta_t *result = malloc(sizeof(libtrace_meta_t));
        result->num = 0;

	while (remaining > sizeof(dag_sec_t)) {
                uint16_t sectype;
		/* Get the current section/option header */
		sec = (dag_sec_t *)ptr;
                sectype = ntohs(sec->type);

		if (sectype == ERF_PROV_SECTION_CAPTURE
                        || sectype == ERF_PROV_SECTION_HOST
                        || sectype == ERF_PROV_SECTION_MODULE
                        || sectype == ERF_PROV_SECTION_STREAM
                        || sectype == ERF_PROV_SECTION_INTERFACE) {

                        /* Section header */
			curr_sec = sectype;
                } else {
			result->num += 1;
                        if (result->num == 1) {
                                result->items = malloc(sizeof(libtrace_meta_item_t));
                        } else {
                                result->items = realloc(result->items,
                                        result->num*sizeof(libtrace_meta_item_t));
                        }
                        result->items[result->num-1].section = curr_sec;
                        result->items[result->num-1].option = ntohs(sec->type);
			result->items[result->num-1].option_name =
                                erf_get_option_name(ntohs(sec->type));

                        result->items[result->num-1].len = ntohs(sec->len);
                        result->items[result->num-1].datatype =
				erf_get_datatype(ntohs(sec->type));

			/* If the datatype is a string allow for a null terminator */
                        if (result->items[result->num-1].datatype == TRACE_META_STRING) {
                                result->items[result->num-1].data =
                                        calloc(1, ntohs(sec->len)+1);
				((char *)result->items[result->num-1].data)[ntohs(sec->len)] = '\0';
				/* and copy the utf8 string */
				memcpy(result->items[result->num-1].data,
                                	ptr+sizeof(struct dag_opthdr), ntohs(sec->len));
                        } else {
                                result->items[result->num-1].data =
                                        calloc(1, ntohs(sec->len));
				/* depending on the datatype we need to ensure the data is
				 * in host byte ordering */
				if (result->items[result->num-1].datatype == TRACE_META_UINT32) {
					uint32_t t = *(uint32_t *)(ptr+sizeof(struct dag_opthdr));
					t = ntohl(t);
					memcpy(result->items[result->num-1].data,
						&t, sizeof(uint32_t));
				} else if(result->items[result->num-1].datatype == TRACE_META_UINT64) {
					uint64_t t = *(uint64_t *)(ptr+sizeof(struct dag_opthdr));
					t = bswap_be_to_host64(t);
					memcpy(result->items[result->num-1].data,
                                                &t, sizeof(uint64_t));
				} else {
					memcpy(result->items[result->num-1].data,
                                        	ptr+sizeof(struct dag_opthdr), ntohs(sec->len));
				}
                        }
                }

		/* Update remaining and ptr. Also account for any padding */
                if ((ntohs(sec->len) % 4) != 0) {
                        tmp = ntohs(sec->len) + (4 - (ntohs(sec->len) % 4)) + sizeof(dag_sec_t);
                } else {
                        tmp = ntohs(sec->len) + sizeof(dag_sec_t);
                }
                remaining -= tmp;
                ptr += tmp;
	}

	/* If the result num > 0 matches were found */
        if (result->num > 0) {
                return (void *)result;
        } else {
                free(result);
                return NULL;
        }
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
        NULL,                           /* can_hold_packet */
	erf_write_packet,		/* write_packet */
	erf_flush_output,		/* flush_output */
	erf_get_link_type,		/* get_link_type */
	erf_get_direction,		/* get_direction */
	erf_set_direction,		/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_timespec */
	NULL,				/* get_seconds */
	erf_get_all_meta,           /* get_all_meta */
	erf_seek_erf,			/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	erf_get_capture_length,		/* get_capture_length */
	erf_get_wire_length,		/* get_wire_length */
	erf_get_framing_length,		/* get_framing_length */
	erf_set_capture_length,		/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,	                        /* get_dropped_packets */
	erf_get_statistics,		/* get_statistics */
	NULL,				/* get_fd */
	erf_event,			/* trace_event */
	erf_help,			/* help */
	NULL,				/* next pointer */
	NON_PARALLEL(false)
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
        NULL,                           /* can_hold_packet */
	erf_write_packet,		/* write_packet */
	erf_flush_output,		/* flush_output */
	erf_get_link_type,		/* get_link_type */
	erf_get_direction,		/* get_direction */
	erf_set_direction,		/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_timespec */
	NULL,				/* get_seconds */
	erf_get_all_meta,		/* get_all_meta */
	erf_seek_erf,			/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	erf_get_capture_length,		/* get_capture_length */
	erf_get_wire_length,		/* get_wire_length */
	erf_get_framing_length,		/* get_framing_length */
	erf_set_capture_length,		/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,	                        /* get_dropped_packets */
	erf_get_statistics,		/* get_statistics */
	NULL,				/* get_fd */
	erf_event,			/* trace_event */
	erf_help,			/* help */
	NULL,				/* next pointer */
	NON_PARALLEL(false)
};



void erf_constructor(void) {
	register_format(&erfformat);
	register_format(&rawerfformat);
}
