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
#include "common.h"
#include "config.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "format_pcapng.h"

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <math.h>

static char *pcapng_parse_next_option(libtrace_t *libtrace, char **pktbuf,
                uint16_t *code, uint16_t *length, pcapng_hdr_t *blockhdr);

static bool pcapng_can_write(libtrace_packet_t *packet) {
	/* Get the linktype */
        libtrace_linktype_t ltype = trace_get_link_type(packet);

        /* TODO convert erf meta to pcapng meta? */
        if (ltype == TRACE_TYPE_CONTENT_INVALID
                || ltype == TRACE_TYPE_UNKNOWN
                || ltype == TRACE_TYPE_ERF_META
                || ltype == TRACE_TYPE_NONDATA) {

                return false;
        }

        return true;
}

static pcapng_interface_t *lookup_interface(libtrace_t *libtrace,
                uint32_t intid) {

       	if (intid >= DATA(libtrace)->nextintid) {
               	return NULL;
       	}

       	return DATA(libtrace)->interfaces[intid];
}

static inline uint32_t pcapng_get_record_type(const libtrace_packet_t *packet) {
        uint32_t *btype = (uint32_t *)packet->header;

	/* only check for byteswapped if input format is pcapng */
	if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
        	if (DATA(packet->trace)->byteswapped)
			return byteswap32(*btype);
	}

        return *btype;
}

static inline uint32_t pcapng_swap32(libtrace_out_t *libtrace, uint32_t value) {
	if (DATAOUT(libtrace)->byteswapped) {
		return byteswap32(value);
	} else {
		return value;
	}
}
static inline uint32_t pcapng_swap16(libtrace_out_t *libtrace, uint32_t value) {
	if (DATAOUT(libtrace)->byteswapped) {
		return byteswap16(value);
	} else {
		return value;
	}
}
static inline uint32_t pcapng_get_blocklen(const libtrace_packet_t *packet) {
        struct pcapng_peeker *hdr = (struct pcapng_peeker *)packet->buffer;

	/* only check for byteswapped if input format is pcapng */
        if (packet->trace->format->type == TRACE_FORMAT_PCAPNG) {
        	if (DATA(packet->trace)->byteswapped)
                	return byteswap32(hdr->blocklen);
	}

	return hdr->blocklen;

}

#if 0
static inline uint16_t pcapng_get_customdata_len(libtrace_packet_t *packet, char *ptr) {
	struct pcapng_custom_optheader *hdr = (struct pcapng_custom_optheader *)ptr;

	if (DATA(packet->trace)->byteswapped) {
		return byteswap16(hdr->optlen);
	} else {
		return hdr->optlen;
	}
}
static inline uint16_t pcapng_get_customdata_optcode(libtrace_packet_t *packet, char *ptr) {
	struct pcapng_custom_optheader *hdr = (struct pcapng_custom_optheader *)ptr;

	if (DATA(packet->trace)->byteswapped) {
		return byteswap16(hdr->optcode);
	} else {
		return hdr->optcode;
	}
}
#endif

static inline uint16_t pcapng_get_nrb_record_type(libtrace_packet_t *packet, char *ptr) {
	struct pcapng_nrb_record *hdr = (struct pcapng_nrb_record *)ptr;
	if (DATA(packet->trace)->byteswapped) {
		return byteswap16(hdr->recordtype);
	} else {
		return hdr->recordtype;
	}
}
static inline uint16_t pcapng_get_nrb_record_len(libtrace_packet_t *packet, char *ptr) {
	struct pcapng_nrb_record *hdr = (struct pcapng_nrb_record *)ptr;
	if (DATA(packet->trace)->byteswapped) {
		return byteswap16(hdr->recordlen);
	} else {
		return hdr->recordlen;
	}
}
static uint32_t pcapng_output_options(libtrace_out_t *libtrace, libtrace_packet_t *packet,
	char *ptr) {

	struct pcapng_optheader opthdr;
	uint16_t optcode, optlen;
        char *optval = NULL;
	char *bodyptr = NULL;
        int padding;
        void *padding_data;
	uint32_t len = 0;

	bodyptr = ptr;

	while ((optval = pcapng_parse_next_option(packet->trace, &bodyptr,
                        &optcode, &optlen, (pcapng_hdr_t *) packet->buffer))) {

		/* pcapng_parse_next_option byteswaps the opcode and len for us */
                opthdr.optcode = optcode;
                opthdr.optlen = optlen;

		/* output the header */
                wandio_wwrite(DATAOUT(libtrace)->file, &opthdr, sizeof(opthdr));

		/* If this is a custom option */
		if (optcode == PCAPNG_CUSTOM_OPTION_UTF8 ||
                        optcode == PCAPNG_CUSTOM_OPTION_BIN ||
			optcode == PCAPNG_CUSTOM_OPTION_UTF8_NONCOPY ||
                        optcode == PCAPNG_CUSTOM_OPTION_BIN_NONCOPY) {
			/* flip the pen and output the option value */
			//uint32_t pen = byteswap32((uint32_t)*optval);
			wandio_wwrite(DATAOUT(libtrace)->file, optval, sizeof(uint32_t));

			/* the len for custom options include pen */
			optval += sizeof(uint32_t);
			optlen -= sizeof(uint32_t);
		}

		/* output the rest of the data */
		wandio_wwrite(DATAOUT(libtrace)->file, &optval, optlen);

                /* calculate any required padding */
                padding = optlen % 4;
                if (padding) { padding = 4 - padding; }
                padding_data = calloc(1, padding);
                /* output the padding */
                wandio_wwrite(DATAOUT(libtrace)->file, padding_data, padding);
                free(padding_data);

		len += sizeof(opthdr) + optlen;
        }

	return len;
}
static uint32_t pcapng_output_interface_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	pcapng_int_t *cur = (pcapng_int_t *)packet->header;
	pcapng_int_t hdr;
	char *bodyptr = NULL;

	/* If the input trace is not pcapng we have no way of finding the byteordering
	 * this can occur if a packet is reconstructed with a deadtrace. Or if the packet
	 * is in the correct byte ordering just output it */
	if ((packet->trace->format->type != TRACE_FORMAT_PCAPNG) ||
		(DATA(packet->trace)->byteswapped == DATAOUT(libtrace)->byteswapped)) {
		uint32_t len = pcapng_get_blocklen(packet);
                wandio_wwrite(DATAOUT(libtrace)->file, packet->buffer, len);
                return len;
	}

	/* Byteswap the headers */
	hdr.blocktype = byteswap32(cur->blocktype);
	hdr.blocklen = byteswap32(cur->blocklen);
	hdr.linktype = byteswap16(cur->linktype);
	hdr.reserved = byteswap16(cur->reserved);
	hdr.snaplen = byteswap32(cur->snaplen);

	wandio_wwrite(DATAOUT(libtrace)->file, &hdr, sizeof(hdr));
	/* output any options */
	bodyptr = (char *)packet->buffer + sizeof(hdr);
	pcapng_output_options(libtrace, packet, bodyptr);
	wandio_wwrite(DATAOUT(libtrace)->file, &hdr.blocklen, sizeof(hdr.blocklen));

	return hdr.blocklen;
}
static uint32_t pcapng_output_simple_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	pcapng_spkt_t *cur = (pcapng_spkt_t *)packet->header;
	pcapng_spkt_t hdr;
	uint32_t len;
	char *bodyptr = NULL;

	/* If the input trace is not pcapng we have no way of finding the byteordering
         * this can occur if a packet is reconstructed with a deadtrace. Or if the packet
         * is in the correct byte ordering just output it */
        if ((packet->trace->format->type != TRACE_FORMAT_PCAPNG) ||
                (DATA(packet->trace)->byteswapped == DATAOUT(libtrace)->byteswapped)) {
		len = pcapng_get_blocklen(packet);
                wandio_wwrite(DATAOUT(libtrace)->file, packet->buffer, len);
                return len;
	}

	hdr.blocktype = byteswap32(cur->blocktype);
	hdr.blocklen = byteswap32(cur->blocklen);
	hdr.wlen = byteswap32(cur->wlen);

	wandio_wwrite(DATAOUT(libtrace)->file, &hdr, sizeof(hdr));

	/* output the packet payload */
        bodyptr = (char *)packet->buffer + sizeof(hdr);
        len = pcapng_get_blocklen(packet) - sizeof(hdr) - sizeof(hdr.blocklen);
        wandio_wwrite(DATAOUT(libtrace)->file, bodyptr, len);

	wandio_wwrite(DATAOUT(libtrace)->file, &hdr.blocklen, sizeof(hdr.blocklen));

	return hdr.blocklen;
}
static uint32_t pcapng_output_old_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	pcapng_opkt_t *cur = (pcapng_opkt_t *)packet->header;
	pcapng_opkt_t hdr;
	uint32_t len;
	char *bodyptr = NULL;

	/* If the input trace is not pcapng we have no way of finding the byteordering
         * this can occur if a packet is reconstructed with a deadtrace. Or if the packet
         * is in the correct byte ordering just output it */
        if ((packet->trace->format->type != TRACE_FORMAT_PCAPNG) ||
                (DATA(packet->trace)->byteswapped == DATAOUT(libtrace)->byteswapped)) {
                len = pcapng_get_blocklen(packet);
                wandio_wwrite(DATAOUT(libtrace)->file, packet->buffer, len);
                return len;
        }

	hdr.blocktype = byteswap32(cur->blocktype);
        hdr.blocklen = byteswap32(cur->blocklen);
        hdr.interfaceid = byteswap16(cur->interfaceid);
	hdr.drops = byteswap16(cur->drops);
	hdr.timestamp_high = byteswap32(cur->timestamp_high);
	hdr.timestamp_low = byteswap32(cur->timestamp_low);
	hdr.caplen = byteswap32(cur->caplen);
	hdr.wlen = byteswap32(cur->wlen);

	wandio_wwrite(DATAOUT(libtrace)->file, &hdr, sizeof(hdr));

	/* output the packet payload */
        bodyptr = (char *)packet->buffer + sizeof(hdr);
        len = pcapng_get_blocklen(packet) - sizeof(hdr) - sizeof(hdr.blocklen);
        wandio_wwrite(DATAOUT(libtrace)->file, bodyptr, len);

	/* output any options if present */
	pcapng_output_options(libtrace, packet, bodyptr);

	wandio_wwrite(DATAOUT(libtrace)->file, &hdr.blocklen, sizeof(hdr.blocklen));


	return hdr.blocklen;
}
static uint32_t pcapng_output_nameresolution_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	pcapng_nrb_t *cur = (pcapng_nrb_t *)packet->buffer;
	pcapng_nrb_t hdr;
	char *bodyptr = NULL;
	int padding;
	void *padding_data;

	/* If the input trace is not pcapng we have no way of finding the byteordering
         * this can occur if a packet is reconstructed with a deadtrace. Or if the packet
         * is in the correct byte ordering just output it */
        if ((packet->trace->format->type != TRACE_FORMAT_PCAPNG) ||
                (DATA(packet->trace)->byteswapped == DATAOUT(libtrace)->byteswapped)) {
                uint32_t len = pcapng_get_blocklen(packet);
                wandio_wwrite(DATAOUT(libtrace)->file, packet->buffer, len);
                return len;
        }

	hdr.blocktype = byteswap32(cur->blocktype);
	hdr.blocklen = byteswap32(cur->blocklen);

	/* output the header */
	wandio_wwrite(DATAOUT(libtrace)->file, &hdr, sizeof(hdr));
	bodyptr = (char *)packet->buffer + sizeof(hdr);

	struct pcapng_nrb_record *nrbr = (struct pcapng_nrb_record *)bodyptr;

	uint16_t record_type = pcapng_get_nrb_record_type(packet, bodyptr);
	while (record_type != PCAPNG_NRB_RECORD_END) {

		struct pcapng_nrb_record nrb;

		/* recordlen contains only the length of the record value without
		 * any padding */
		uint16_t recordlen = pcapng_get_nrb_record_len(packet, bodyptr);

		nrb.recordtype = byteswap16(nrbr->recordtype);
		nrb.recordlen = byteswap16(nrbr->recordlen);

		/* output the record header */
		wandio_wwrite(DATAOUT(libtrace)->file, &nrb, sizeof(nrb));
		bodyptr += sizeof(nrb);

		/* output the record data */
		wandio_wwrite(DATAOUT(libtrace)->file, bodyptr, recordlen);
		bodyptr += recordlen;

		/* calculate any required padding. record also contains the 8 byte header
                 * but we dont need to subtract it because it will be removed with % 4 */
                padding = recordlen % 4;
                if (padding) { padding = 4 - padding; }
                padding_data = calloc(1, padding);
                /* output the padding */
                wandio_wwrite(DATAOUT(libtrace)->file, padding_data, padding);
                free(padding_data);
		bodyptr += padding;

		/* get the next record if it exists */
		nrbr = (struct pcapng_nrb_record *)bodyptr;
		record_type = pcapng_get_nrb_record_type(packet, bodyptr);
	}

	/* output nrb record end block */
	struct pcapng_nrb_record nrbftr;
	nrbftr.recordtype = PCAPNG_NRB_RECORD_END;
	nrbftr.recordlen = 0;
	wandio_wwrite(DATAOUT(libtrace)->file, &nrbftr, sizeof(nrbftr));
	bodyptr += sizeof(nrbftr);

	/* output any options if present */
        pcapng_output_options(libtrace, packet, bodyptr);

        /* and print out rest of the header */
        wandio_wwrite(DATAOUT(libtrace)->file, &hdr.blocklen, sizeof(hdr.blocklen));

	return hdr.blocklen;
}
static uint32_t pcapng_output_custom_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	pcapng_custom_t *cur = (pcapng_custom_t *)packet->buffer;
	pcapng_custom_t hdr;
	char *bodyptr = (char *)packet->buffer;

	/* If the input trace is not pcapng we have no way of finding the byteordering
         * this can occur if a packet is reconstructed with a deadtrace. Or if the packet
         * is in the correct byte ordering just output it */
        if ((packet->trace->format->type != TRACE_FORMAT_PCAPNG) ||
                (DATA(packet->trace)->byteswapped == DATAOUT(libtrace)->byteswapped)) {
                uint32_t len = pcapng_get_blocklen(packet);
                wandio_wwrite(DATAOUT(libtrace)->file, packet->buffer, len);
                return len;
        }

	hdr.blocktype = byteswap32(cur->blocktype);
	hdr.blocklen = byteswap32(cur->blocklen);
	hdr.pen = byteswap32(cur->blocklen);

	/* output the header */
	wandio_wwrite(DATAOUT(libtrace)->file, &hdr, sizeof(hdr));
	bodyptr += sizeof(hdr);

	/* now print out any options */
	pcapng_output_options(libtrace, packet, bodyptr);

	/* and print out rest of the header */
	wandio_wwrite(DATAOUT(libtrace)->file, &hdr.blocklen, sizeof(hdr.blocklen));

	return hdr.blocklen;
}
static uint32_t pcapng_output_enhanced_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	pcapng_epkt_t *cur = (pcapng_epkt_t *)packet->buffer;
	pcapng_epkt_t hdr;
	char *bodyptr = NULL;
	uint32_t len;

	/* If the input trace is not pcapng we have no way of finding the byteordering
         * this can occur if a packet is reconstructed with a deadtrace. Or if the packet
         * is in the correct byte ordering just output it */
        if ((packet->trace->format->type != TRACE_FORMAT_PCAPNG) ||
                (DATA(packet->trace)->byteswapped == DATAOUT(libtrace)->byteswapped)) {
                len = pcapng_get_blocklen(packet);
                wandio_wwrite(DATAOUT(libtrace)->file, packet->buffer, len);
                return len;
        }

	hdr.blocktype = byteswap32(cur->blocktype);
	hdr.blocklen = byteswap32(cur->blocklen);
	hdr.interfaceid = byteswap32(cur->interfaceid);
	hdr.timestamp_high = byteswap32(cur->timestamp_high);
	hdr.timestamp_low = byteswap32(cur->timestamp_low);
	hdr.caplen = byteswap32(cur->caplen);
	hdr.wlen = byteswap32(cur->wlen);

	/* output beginning of header */
	wandio_wwrite(DATAOUT(libtrace)->file, &hdr, sizeof(hdr));

	/* output the packet payload */
	bodyptr = (char *)packet->buffer + sizeof(hdr);
	len = pcapng_get_blocklen(packet) - sizeof(hdr) - sizeof(hdr.blocklen);
	wandio_wwrite(DATAOUT(libtrace)->file, bodyptr, len);

	/* output any options */
	pcapng_output_options(libtrace, packet, bodyptr);

	/* output end of header */
	wandio_wwrite(DATAOUT(libtrace)->file, &hdr.blocklen, sizeof(hdr.blocklen));

	return hdr.blocklen;
}
static uint32_t pcapng_output_interfacestats_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	pcapng_stats_t *cur = (pcapng_stats_t *)packet->header;
	pcapng_stats_t hdr;
	char *bodyptr = NULL;

	/* If the input trace is not pcapng we have no way of finding the byteordering
         * this can occur if a packet is reconstructed with a deadtrace. Or if the packet
         * is in the correct byte ordering just output it */
        if ((packet->trace->format->type != TRACE_FORMAT_PCAPNG) ||
                (DATA(packet->trace)->byteswapped == DATAOUT(libtrace)->byteswapped)) {
                uint32_t len = pcapng_get_blocklen(packet);
                wandio_wwrite(DATAOUT(libtrace)->file, packet->buffer, len);
                return len;
        }

	hdr.blocktype = byteswap32(cur->blocktype);
	hdr.blocklen = byteswap32(cur->blocklen);
	hdr.interfaceid = byteswap32(cur->interfaceid);
	hdr.timestamp_high = byteswap32(cur->timestamp_high);
	hdr.timestamp_low = byteswap32(cur->timestamp_low);

	/* output interface stats header */
	wandio_wwrite(DATAOUT(libtrace)->file, &hdr, sizeof(hdr));
	/* output any options if present */
	bodyptr = (char *)packet->buffer + sizeof(hdr);
	pcapng_output_options(libtrace, packet, bodyptr);
	/* output rest of interface stats header */
	wandio_wwrite(DATAOUT(libtrace)->file, &hdr.blocklen, sizeof(hdr.blocklen));

	return hdr.blocklen;
}

static void pcapng_create_output_sectionheader_packet(libtrace_out_t *libtrace) {
	/* Create section block */
	pcapng_sec_t sechdr;
	sechdr.blocktype = pcapng_swap32(libtrace, PCAPNG_SECTION_TYPE);
	sechdr.blocklen = pcapng_swap32(libtrace, 28);
	sechdr.ordering = pcapng_swap32(libtrace, 0x1A2B3C4D);
	sechdr.majorversion = pcapng_swap16(libtrace, 1);
	sechdr.minorversion = 0;
	sechdr.sectionlen = 0xFFFFFFFFFFFFFFFF;

	wandio_wwrite(DATAOUT(libtrace)->file, &sechdr, sizeof(sechdr));
	wandio_wwrite(DATAOUT(libtrace)->file, &sechdr.blocklen, sizeof(sechdr.blocklen));

	DATAOUT(libtrace)->sechdr_count += 1;
}

static void pcapng_create_output_interface_packet(libtrace_out_t *libtrace, libtrace_linktype_t linktype) {
	/* Create interface block*/
	pcapng_int_t inthdr;
	inthdr.blocktype = pcapng_swap32(libtrace, PCAPNG_INTERFACE_TYPE);
	inthdr.blocklen = pcapng_swap32(libtrace, 20);
	inthdr.linktype = pcapng_swap16(libtrace, libtrace_to_pcap_dlt(linktype));
	inthdr.reserved = 0;
	inthdr.snaplen = 0;

	wandio_wwrite(DATAOUT(libtrace)->file, &inthdr, sizeof(inthdr));
	wandio_wwrite(DATAOUT(libtrace)->file, &inthdr.blocklen, sizeof(inthdr.blocklen));

	/* increment the interface counter */
	DATAOUT(libtrace)->nextintid += 1;
	/* update the last linktype */
	DATAOUT(libtrace)->lastdlt = linktype;
}

static int pcapng_probe_magic(io_t *io) {

        pcapng_sec_t sechdr;
        int len;

        len = wandio_peek(io, &sechdr, sizeof(sechdr));
        if (len < (int)sizeof(sechdr)) {
                return 0;
        }

        if (sechdr.blocktype == PCAPNG_SECTION_TYPE) {
                return 1;
        }
        return 0;
}

static struct pcapng_timestamp pcapng_get_timestamp(libtrace_packet_t *packet) {
	struct timeval tv = trace_get_timeval(packet);
	uint64_t time = ((uint64_t)tv.tv_sec * (uint64_t)1000000) + tv.tv_usec;

	struct pcapng_timestamp timestamp;
	timestamp.timehigh = time >> 32;
	timestamp.timelow = time & 0xFFFFFFFF;

	return timestamp;
}


static int pcapng_init_input(libtrace_t *libtrace) {
        libtrace->format_data = malloc(sizeof(struct pcapng_format_data_t));
        if (!libtrace->format_data) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable to allocate memory for "
			"format data inside pcapng_init_input()");
                return -1;
        }

        DATA(libtrace)->started = false;
        DATA(libtrace)->realtime = false;
	DATA(libtrace)->discard_meta = false;
        DATA(libtrace)->byteswapped = true;
        DATA(libtrace)->interfaces = (pcapng_interface_t **)calloc(10, \
                        sizeof(pcapng_interface_t));
        DATA(libtrace)->allocatedinterfaces = 10;
        DATA(libtrace)->nextintid = 0;

        return 0;
}

static int pcapng_config_output(libtrace_out_t *libtrace, trace_option_output_t option,
	void *value) {

	switch (option) {
		case TRACE_OPTION_OUTPUT_COMPRESS:
			DATAOUT(libtrace)->compress_level = *(int *)value;
			return 0;
		case TRACE_OPTION_OUTPUT_COMPRESSTYPE:
			DATAOUT(libtrace)->compress_type = *(int *)value;
			return 0;
		case TRACE_OPTION_OUTPUT_FILEFLAGS:
			DATAOUT(libtrace)->flag = *(int *)value;
			return 0;
		default:
			trace_set_err_out(libtrace, TRACE_ERR_UNKNOWN_OPTION,
				"Unknown option");
			return -1;
	}
}

static int pcapng_start_input(libtrace_t *libtrace) {

        if (!libtrace->io) {
                libtrace->io = trace_open_file(libtrace);
        }

        if (!libtrace->io)
                return -1;

        return 0;
}

static int pcapng_config_input(libtrace_t *libtrace, trace_option_t option,
                void *data) {

        switch(option) {
                case TRACE_OPTION_EVENT_REALTIME:
                        if (*(int *)data != 0) {
                                DATA(libtrace)->realtime = true;
                        } else {
                                DATA(libtrace)->realtime = false;
                        }
                        return 0;
                case TRACE_OPTION_META_FREQ:
                case TRACE_OPTION_SNAPLEN:
                case TRACE_OPTION_PROMISC:
                case TRACE_OPTION_FILTER:
                case TRACE_OPTION_HASHER:
                case TRACE_OPTION_REPLAY_SPEEDUP:
                case TRACE_OPTION_CONSTANT_ERF_FRAMING:
                        break;
		case TRACE_OPTION_DISCARD_META:
                        if (*(int *)data > 0) {
                                DATA(libtrace)->discard_meta = true;
                        } else {
                                DATA(libtrace)->discard_meta = false;
                        }
			return 0;
                case TRACE_OPTION_XDP_HARDWARE_OFFLOAD:
                    break;
        }

        trace_set_err(libtrace, TRACE_ERR_UNKNOWN_OPTION, "Unknown option %i",
                        option);
        return -1;
}

static int pcapng_init_output(libtrace_out_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct pcapng_format_data_out_t));

	DATAOUT(libtrace)->file = NULL;
	DATAOUT(libtrace)->compress_level = 0;
	DATAOUT(libtrace)->compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
	DATAOUT(libtrace)->flag = O_CREAT|O_WRONLY;

	DATAOUT(libtrace)->sechdr_count = 0;
	DATAOUT(libtrace)->byteswapped = false;

	DATAOUT(libtrace)->nextintid = 0;
	DATAOUT(libtrace)->lastdlt = 0;

	return 0;
}

static int pcapng_fin_input(libtrace_t *libtrace) {

        int i = 0;

        for (i = 0; i < DATA(libtrace)->allocatedinterfaces; i++) {
                free(DATA(libtrace)->interfaces[i]);
        }

        free(DATA(libtrace)->interfaces);

        if (libtrace->io) {
                wandio_destroy(libtrace->io);
        }
        free(libtrace->format_data);
        return 0;
}

static int pcapng_fin_output(libtrace_out_t *libtrace) {
	if (DATAOUT(libtrace)->file) {
		wandio_wdestroy(DATAOUT(libtrace)->file);
	}
	free(libtrace->format_data);
	libtrace->format_data = NULL;
	return 0;
}

static char *pcapng_parse_next_option(libtrace_t *libtrace, char **pktbuf,
                uint16_t *code, uint16_t *length, pcapng_hdr_t *blockhdr) {

        struct pcapng_optheader *opthdr = (struct pcapng_optheader *)*pktbuf;
        int to_skip;
        int padding = 0;
        char *eob; //end of block
        char *optval;
        if (DATA(libtrace)->byteswapped) {
                eob = ((char *) blockhdr) + byteswap32(blockhdr->blocklen);
        } else {
                eob = ((char *) blockhdr) + blockhdr->blocklen;
        }

	if ((char *)blockhdr >= *pktbuf) {
		return NULL;
	}
        // Check if we have reached the end of the block, +4 for trailing block-size
        // We cannot assume a endofopt, so we add one
        if (eob == (*pktbuf) + 4) {
                *code = 0;
                *length = 0;
                return *pktbuf;
        }
        // If there is not enough space for another header we've encountered an error
        if (eob < (*pktbuf) + 4 + sizeof(struct pcapng_optheader)) {
                return NULL;
        }

        if (DATA(libtrace)->byteswapped) {
                *code = byteswap16(opthdr->optcode);
                *length = byteswap16(opthdr->optlen);
        } else {
                *code = opthdr->optcode;
                *length = opthdr->optlen;
        }

        optval = *pktbuf + sizeof(struct pcapng_optheader);

        if ((*length % 4) > 0) {
                padding = (4 - (*length % 4));
        } else {
                padding = 0;
        }

        to_skip = (*length) + padding;
        // Check the value we return is within the block length
        if (eob < optval + to_skip + 4) {
                return NULL;
        }
        *pktbuf = optval + to_skip;

        return optval;
}

static inline int pcapng_read_body(libtrace_t *libtrace, char *body,
                uint32_t to_read) {

        int err;

        err = wandio_read(libtrace->io, body, to_read);
        if (err < 0) {
                trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED,
                        "Failed reading pcapng block");
                return err;
        }

        if (err == 0) {
                return err;
        }

        if (err < (int)to_read) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                        "Incomplete pcapng block");
                return -1;
        }

        return to_read;
}

static int pcapng_get_framing_length(const libtrace_packet_t *packet) {

	switch(pcapng_get_record_type(packet)) {
                case PCAPNG_SECTION_TYPE:
                        return sizeof(pcapng_sec_t);
                case PCAPNG_INTERFACE_TYPE:
                        return sizeof(pcapng_int_t);
                case PCAPNG_ENHANCED_PACKET_TYPE:
                        return sizeof(pcapng_epkt_t);
                case PCAPNG_SIMPLE_PACKET_TYPE:
                        return sizeof(pcapng_spkt_t);
                case PCAPNG_OLD_PACKET_TYPE:
                        return sizeof(pcapng_opkt_t);
                case PCAPNG_INTERFACE_STATS_TYPE:
                        return sizeof(pcapng_stats_t);
                case PCAPNG_NAME_RESOLUTION_TYPE:
                        return sizeof(pcapng_nrb_t);
                case PCAPNG_CUSTOM_TYPE:
			return sizeof(pcapng_custom_t);
                case PCAPNG_CUSTOM_NONCOPY_TYPE:
                        return sizeof(pcapng_custom_t);
		case PCAPNG_DECRYPTION_SECRETS_TYPE:
			return sizeof(pcapng_secrets_t);
	}

        /* If we get here, we aren't a valid pcapng packet */
        trace_set_err(packet->trace, TRACE_ERR_BAD_PACKET,
                        "Invalid RT type for pcapng packet: %u",
                        packet->type);
        return -1;

}

static int pcapng_prepare_packet(libtrace_t *libtrace,
                libtrace_packet_t *packet, void *buffer,
                libtrace_rt_types_t rt_type, uint32_t flags) {

        int hdrlen;

        if (packet->buffer != buffer &&
                        packet->buf_control == TRACE_CTRL_PACKET) {
                free(packet->buffer);
        }

        if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER) {
                packet->buf_control = TRACE_CTRL_PACKET;
        } else {
                packet->buf_control = TRACE_CTRL_EXTERNAL;
        }

        packet->type = rt_type;
        packet->buffer = buffer;
        packet->header = buffer;

        hdrlen = pcapng_get_framing_length(packet);
        if (hdrlen < 0) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "X Invalid RT type for pcapng packet: %u",
                                packet->type);
                return -1;
        }
        packet->payload = ((char *)packet->buffer) + hdrlen;

        return 0;
}

static int pcapng_write_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {

	if (!libtrace) {
		fprintf(stderr, "NULL trace passed into pcapng_write_packet()\n");
		return TRACE_ERR_NULL_TRACE;
	}
	if (!packet) {
		trace_set_err_out(libtrace, TRACE_ERR_NULL_PACKET, "NULL packet passed "
			"into pcapng_write_packet()\n");
		return -1;
	}

	/* Check pcapng can write this type of packet */
	if (!pcapng_can_write(packet)) {
		return 0;
	}

	libtrace_linktype_t linktype = trace_get_link_type(packet);

	/* If the file is not open, open it */
	if (!DATAOUT(libtrace)->file) {
		DATAOUT(libtrace)->file = trace_open_file_out(libtrace,
			DATAOUT(libtrace)->compress_type,
			DATAOUT(libtrace)->compress_level,
			DATAOUT(libtrace)->flag);
	}

	/* If the packet is already encapsulated in a pcapng frame just output it */
	switch (pcapng_get_record_type(packet)) {
		case PCAPNG_SECTION_TYPE: {
			/* If the section header passed in is byteswapped, everything we output
			 * till the next section header needs to be byteswapped. The next header
			 * will determine if we need to continue swapping bytes */
			if (DATA(packet->trace)->byteswapped) {
				DATAOUT(libtrace)->byteswapped = true;
			} else {
				DATAOUT(libtrace)->byteswapped = false;
			}

			wandio_wwrite(DATAOUT(libtrace)->file, packet->buffer,
				pcapng_get_blocklen(packet));

			DATAOUT(libtrace)->sechdr_count += 1;

			return pcapng_get_blocklen(packet);
		}
		case PCAPNG_INTERFACE_TYPE: {
			/* increment the interface id */
        		DATAOUT(libtrace)->nextintid += 1;

			return pcapng_output_interface_packet(libtrace, packet);
		}
		case PCAPNG_OLD_PACKET_TYPE: {
			return pcapng_output_old_packet(libtrace, packet);
		}
		case PCAPNG_SIMPLE_PACKET_TYPE: {
			/* If no section header or interface packets have been received create and
			 * output them. This can occur when discard meta is enabled and the input
			 * format is also pcapng */
			if (DATAOUT(libtrace)->sechdr_count == 0) {
				pcapng_create_output_sectionheader_packet(libtrace);
			}
			if (DATAOUT(libtrace)->nextintid == 0) {
				pcapng_create_output_interface_packet(libtrace, linktype);
			}
			return pcapng_output_simple_packet(libtrace, packet);
		}
		case PCAPNG_NAME_RESOLUTION_TYPE: {
			return pcapng_output_nameresolution_packet(libtrace, packet);
		}
		case PCAPNG_INTERFACE_STATS_TYPE: {
			/* If no section header or interface packets have been received create and
                         * output them. This can occur when discard meta is enabled and the input
                         * format is also pcapng */
			if (DATAOUT(libtrace)->sechdr_count == 0) {
                                pcapng_create_output_sectionheader_packet(libtrace);
                        }
                        if (DATAOUT(libtrace)->nextintid == 0) {
                                pcapng_create_output_interface_packet(libtrace, linktype);
                        }
                       	return pcapng_output_interfacestats_packet(libtrace, packet);
		}
		case PCAPNG_ENHANCED_PACKET_TYPE: {
			/* If no section header or interface packets have been received create and
                         * output them. This can occur when discard meta is enabled and the input
                         * format is also pcapng */
			if (DATAOUT(libtrace)->sechdr_count == 0) {
                                pcapng_create_output_sectionheader_packet(libtrace);
                        }
                        if (DATAOUT(libtrace)->nextintid == 0) {
                                pcapng_create_output_interface_packet(libtrace, linktype);
                        }
	                return pcapng_output_enhanced_packet(libtrace, packet);
		}
		case PCAPNG_CUSTOM_TYPE: {
			return pcapng_output_custom_packet(libtrace, packet);
		}
		case PCAPNG_DECRYPTION_SECRETS_TYPE: {
			return 0;
		}
		case PCAPNG_CUSTOM_NONCOPY_TYPE: {
			/* This custom block type is not ment to be copied */
			return 0;
		}
		default: {

			/* create and output section header if none have occured yet */
			if (DATAOUT(libtrace)->sechdr_count == 0) {
				pcapng_create_output_sectionheader_packet(libtrace);
			}

			/* create and output interface header if not already or if the
			 * linktype has changed */
			if (DATAOUT(libtrace)->nextintid == 0
				|| DATAOUT(libtrace)->lastdlt != linktype) {

				pcapng_create_output_interface_packet(libtrace, linktype);
			}

			break;
		}
	}

	/* If we get this far the packet is not a pcapng type so we need to encapsulate it
	 * within a enhanced pcapng packet */
	uint32_t remaining;
        void *link;
	uint32_t blocklen;
	uint32_t padding;
	uint32_t caplen;
	uint32_t wirelen;
	void *padding_data;
	pcapng_epkt_t epkthdr;

	link = trace_get_packet_buffer(packet, &linktype, &remaining);

	wirelen = trace_get_wire_length(packet);
	caplen = trace_get_capture_length(packet);

	/* trace_get_wirelength includes FCS, while pcapng doesn't */
	if (trace_get_link_type(packet)==TRACE_TYPE_ETH) {
		if (wirelen >= 4) {
			wirelen -= 4;
		} else {
			wirelen = 0;
		}
	}
	/* capture length should always be less than the wirelength */
	if (caplen > wirelen) {
		caplen = wirelen;
	}

	/* calculate padding to 32bits */
	padding = caplen % 4;
	if (padding) { padding = 4 - padding; }
	padding_data = calloc(1, padding);

	/* get pcapng_timestamp */
        struct pcapng_timestamp ts = pcapng_get_timestamp(packet);

	/* calculate the block length */
	blocklen = sizeof(epkthdr) + sizeof(epkthdr.blocklen) + caplen + padding;

	/* construct the packet */
	epkthdr.blocktype = pcapng_swap32(libtrace, PCAPNG_ENHANCED_PACKET_TYPE);
	epkthdr.blocklen = pcapng_swap32(libtrace, blocklen);
	epkthdr.interfaceid = pcapng_swap32(libtrace, DATAOUT(libtrace)->nextintid-1);
	epkthdr.timestamp_high = pcapng_swap32(libtrace, ts.timehigh);
	epkthdr.timestamp_low = pcapng_swap32(libtrace, ts.timelow);
	epkthdr.wlen = pcapng_swap32(libtrace, wirelen);
        epkthdr.caplen = pcapng_swap32(libtrace, caplen);

	/* output enhanced packet header */
	wandio_wwrite(DATAOUT(libtrace)->file, &epkthdr, sizeof(epkthdr));
	/* output the packet */
	wandio_wwrite(DATAOUT(libtrace)->file, link, (size_t)caplen);
	/* output padding */
	wandio_wwrite(DATAOUT(libtrace)->file, padding_data, (size_t)padding);
	/* output rest of the enhanced packet */
	wandio_wwrite(DATAOUT(libtrace)->file, &epkthdr.blocklen, sizeof(epkthdr.blocklen));

	/* release padding memory */
	free(padding_data);

	return blocklen;
}

static int pcapng_flush_output(libtrace_out_t *libtrace) {
	return wandio_wflush(DATAOUT(libtrace)->file);
}

static int pcapng_read_section(libtrace_t *libtrace,
                libtrace_packet_t *packet, uint32_t flags) {

        pcapng_sec_t *sechdr;
        int err;
        uint32_t to_read, blocklen;
        char *bodyptr = NULL;

        err = wandio_read(libtrace->io, packet->buffer, sizeof(pcapng_sec_t));
        sechdr = (pcapng_sec_t *)packet->buffer;

        if (err < 0) {
                trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED,
                        "Reading pcapng section header block");
                return -1;
        }

        if (err == 0) {
                return 0;
        }

        if (err < (int)(sizeof(pcapng_sec_t))) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                        "Incomplete pcapng section header block");
                return -1;
        }

	if (sechdr->blocktype != PCAPNG_SECTION_TYPE) {
		trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid block type in pcapng section block");
		return -1;
	}

        if (sechdr->ordering == 0x1A2B3C4D) {
                DATA(libtrace)->byteswapped = false;
        } else if (sechdr->ordering == 0x4D3C2B1A) {
                DATA(libtrace)->byteswapped = true;
        } else {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Parsing pcapng section header block");
                return -1;
        }


        if (DATA(libtrace)->byteswapped) {
                if (byteswap16(sechdr->majorversion) != 1 && byteswap16(sechdr->minorversion) != 0) {
                        trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Parsing pcapng version numbers");
                        return -1;
                }
                blocklen = byteswap32(sechdr->blocklen);

        } else {
                if (sechdr->majorversion != 1 && sechdr->minorversion != 0) {
                        trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Parsing pcapng version numbers");
                        return -1;
                }
                blocklen = sechdr->blocklen;
        }

        if (blocklen < sizeof(pcapng_sec_t)) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Block length in pcapng section header is invalid.");
                return -1;
        }
        to_read = blocklen - sizeof(pcapng_sec_t);
        /* Read all of the options etc. -- we don't need them for now, but
         * we have to skip forward to the next useful header. */
        bodyptr = (char *) packet->buffer + sizeof(pcapng_sec_t);

        if (to_read > LIBTRACE_PACKET_BUFSIZE) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Excessively large section header contents of %u bytes, likely a corrupt trace.", to_read);
                return -1;
        }

        err = pcapng_read_body(libtrace, bodyptr, to_read);
        if (err <= 0) {
                return err;
        }

        packet->type = TRACE_RT_PCAPNG_META;
        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }

        return 1;
}

static int pcapng_read_interface(libtrace_t *libtrace,
                libtrace_packet_t *packet, uint32_t blocklen, uint32_t flags) {

        pcapng_int_t *inthdr;
        pcapng_interface_t *newint;
        uint16_t optcode, optlen;
        char *optval = NULL;
        char *bodyptr = NULL;

        if (blocklen < sizeof(pcapng_int_t) + 4) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                        "Incomplete pcapng interface header block");
                return -1;
        }
        inthdr = (pcapng_int_t *)packet->buffer;

        newint = (pcapng_interface_t *)malloc(sizeof(pcapng_interface_t));

        newint->id = DATA(libtrace)->nextintid;

        newint->received = 0;
        newint->dropped = 0;
        newint->dropcounter = 0;
        newint->accepted = 0;
        newint->osdropped = 0;
        newint->laststats = 0;
        newint->tsresol = 1000000;

        if (DATA(libtrace)->byteswapped) {
		if (byteswap32(inthdr->blocktype) != PCAPNG_INTERFACE_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid block type in pcapng interface");
			return -1;
		}
                newint->snaplen = byteswap32(inthdr->snaplen);
                newint->linktype = byteswap16(inthdr->linktype);
        } else {
		if (inthdr->blocktype != PCAPNG_INTERFACE_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid block type in pcapng interface");
			return -1;
		}
                newint->snaplen = inthdr->snaplen;
                newint->linktype = inthdr->linktype;
        }

        if (DATA(libtrace)->nextintid == DATA(libtrace)->allocatedinterfaces) {
                DATA(libtrace)->allocatedinterfaces += 10;
                DATA(libtrace)->interfaces = (pcapng_interface_t **)realloc(
                        DATA(libtrace)->interfaces,
                        DATA(libtrace)->allocatedinterfaces * sizeof(
                                pcapng_interface_t *));
                memset(&DATA(libtrace)->interfaces[DATA(libtrace)->nextintid], 0, sizeof(void *) * 10);
        }

        DATA(libtrace)->interfaces[newint->id] = newint;
        DATA(libtrace)->nextintid += 1;

        bodyptr = (char *) packet->buffer + sizeof(pcapng_int_t);

        packet->type = TRACE_RT_PCAPNG_META;

        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }

        do {
                optval = pcapng_parse_next_option(libtrace, &bodyptr,
                                &optcode, &optlen, (pcapng_hdr_t *) packet->buffer);
                if (optval == NULL) {
                        trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Failed to read options for pcapng interface");
                        return -1;
                }

                if (optcode == PCAPNG_IFOPT_TSRESOL) {
                        uint8_t *resol = (uint8_t *)optval;

                        if ((*resol & 0x80) != 0) {
                                newint->tsresol = pow(2, *resol & 0x7f);

                        } else {
                                newint->tsresol = pow(10, *resol & 0x7f);
                        }
                }

        } while (optcode != 0);

        return (int) blocklen;

}

static int pcapng_read_nrb(libtrace_t *libtrace, libtrace_packet_t *packet,
                uint32_t blocklen, uint32_t flags) {

        /* Just read the NR records and pass them off to the caller. If
         * they want to do anything with them, they can parse the records
         * themselves.
         */
        pcapng_nrb_t *hdr = NULL;

        if (blocklen < sizeof(pcapng_nrb_t) + 4) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Incomplete pcapng name resolution block");
                return -1;
        }

        hdr = (pcapng_nrb_t *)packet->buffer;

        /* Read the rest of the packet into the buffer */
        if (DATA(libtrace)->byteswapped) {
		if (byteswap32(hdr->blocktype) != PCAPNG_NAME_RESOLUTION_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid block type in pcapng name "
				"resolution block");
			return -1;
		}
        } else {
		if (hdr->blocktype != PCAPNG_NAME_RESOLUTION_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid block type in pcapng name "
				"resolution block");
			return -1;
		}
        }

        packet->type = TRACE_RT_PCAPNG_META;
        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }

        return (int) blocklen;

}

static int pcapng_read_custom(libtrace_t *libtrace, libtrace_packet_t *packet,
                uint32_t blocklen, uint32_t flags) {

        /* Just read the custom records and pass them off to the caller. If
         * they want to do anything with them, they can parse the records
         * themselves.
         */
        pcapng_custom_t *hdr = NULL;

        if (blocklen < sizeof(pcapng_custom_t) + 4) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Incomplete pcapng custom block");
                return -1;
        }

        hdr = (pcapng_custom_t *)packet->buffer;

        /* Read the rest of the packet into the buffer */
        if (DATA(libtrace)->byteswapped) {
		if (byteswap32(hdr->blocktype) != PCAPNG_CUSTOM_TYPE &&
                        byteswap32(hdr->blocktype) != PCAPNG_CUSTOM_NONCOPY_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid blocktype "
				"in pcapng custom block");
			return -1;
		}
        } else {
		if (hdr->blocktype != PCAPNG_CUSTOM_TYPE &&
                        hdr->blocktype != PCAPNG_CUSTOM_NONCOPY_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid blocktype "
				"in pcapng custom block");
			return -1;
		}
        }

        packet->type = TRACE_RT_PCAPNG_META;
        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }

        return (int) blocklen;

}

static int pcapng_read_stats(libtrace_t *libtrace, libtrace_packet_t *packet,
                uint32_t blocklen, uint32_t flags) {
        pcapng_stats_t *hdr = NULL;
        uint32_t ifaceid;
        uint64_t timestamp;
        pcapng_interface_t *interface;
        uint16_t optcode, optlen;
        char *optval;
        char *bodyptr;

        if (blocklen < sizeof(pcapng_stats_t) + 4) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Incomplete pcapng interface stats header");
                return -1;
        }

        hdr = (pcapng_stats_t *)packet->buffer;

        /* Read the rest of the packet into the buffer */
        if (DATA(libtrace)->byteswapped) {
		if (byteswap32(hdr->blocktype) != PCAPNG_INTERFACE_STATS_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid block type "
				"in pcapng statistics block");
			return -1;
		}
                ifaceid = byteswap32(hdr->interfaceid);
                timestamp = ((uint64_t)(byteswap32(hdr->timestamp_high)) << 32) + byteswap32(hdr->timestamp_low);
        } else {
             	if (hdr->blocktype != PCAPNG_INTERFACE_STATS_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid block type "
				"in pcapng statistics block");
			return -1;
		}
                ifaceid = hdr->interfaceid;
                timestamp = ((uint64_t)(hdr->timestamp_high) << 32) +
                                hdr->timestamp_low;
        }

        /* Set packet type based on interface linktype */
        interface = lookup_interface(libtrace, ifaceid);
        if (interface == NULL) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Unknown pcapng interface id: %u", ifaceid);
                return -1;
        }
        packet->type = TRACE_RT_PCAPNG_META;

        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }

        if (timestamp < interface->laststats) {
                return (int) blocklen;
        }

        /* All of the stats are stored as options */
        bodyptr = packet->payload;

        do {
                optval = pcapng_parse_next_option(packet->trace, &bodyptr,
                                &optcode, &optlen, (pcapng_hdr_t *) packet->buffer);
                if (optval == NULL) {
                        trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Failed to read options for pcapng interface stats");
                        return -1;
                }

                if (optcode == PCAPNG_STATOPT_IFRECV) {
                        uint64_t *recvd = (uint64_t *)optval;
                        if (DATA(packet->trace)->byteswapped) {
                                interface->received = byteswap64(*recvd);
                        } else {
                                interface->received = *recvd;
                        }
                }

                if (optcode == PCAPNG_STATOPT_IFDROP) {
                        uint64_t *drops = (uint64_t *)optval;
                        if (DATA(packet->trace)->byteswapped) {
                                interface->dropped = byteswap64(*drops);
                        } else {
                                interface->dropped = *drops;
                        }
                }

                if (optcode == PCAPNG_STATOPT_OSDROP) {
                        uint64_t *drops = (uint64_t *)optval;
                        if (DATA(packet->trace)->byteswapped) {
                                interface->osdropped = byteswap64(*drops);
                        } else {
                                interface->osdropped = *drops;
                        }
                }

                if (optcode == PCAPNG_STATOPT_FILTERACCEPT) {
                        uint64_t *accepts = (uint64_t *)optval;
                        if (DATA(packet->trace)->byteswapped) {
                                interface->accepted = byteswap64(*accepts);
                        } else {
                                interface->accepted = *accepts;
                        }
                }

        } while (optcode != 0);
        interface->laststats = timestamp;

        return (int) blocklen;

}

static int pcapng_read_simple(libtrace_t *libtrace, libtrace_packet_t *packet,
                uint32_t blocklen, uint32_t flags) {

        uint32_t caplen;
        pcapng_spkt_t *hdr = NULL;
        pcapng_interface_t *interface;

        if (blocklen < sizeof(pcapng_spkt_t) + 4) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Incomplete pcapng simple packet header");
                return -1;
        }

        hdr = (pcapng_spkt_t *)packet->buffer;

        /* Read the rest of the packet into the buffer */
        if (DATA(libtrace)->byteswapped) {
		if (byteswap32(hdr->blocktype) != PCAPNG_SIMPLE_PACKET_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid block type in "
				"pcapng simple packet block");
			return -1;
		}
                caplen = byteswap32(hdr->blocklen) - sizeof(pcapng_spkt_t) - 4;
                         /* account for trailing length field */
        } else {
		if (hdr->blocktype != PCAPNG_SIMPLE_PACKET_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid block type in "
				"pcapng simple packet block");
			return -1;
		}
                caplen = hdr->blocklen - sizeof(pcapng_spkt_t) - 4;
                         /* account for trailing length field */
        }

        /* Set packet type based on interface linktype.
         * Assume interface 0, since we have no interface field */
        interface = lookup_interface(libtrace, 0);
        if (interface == NULL) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Unknown pcapng interface id: %u", 0);
                return -1;
        }
        packet->type = pcapng_linktype_to_rt(interface->linktype);

        /* May as well cache the capture length now, since we've
         * already got it in the right byte order */
        packet->cached.capture_length = caplen;

        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }
        return (int) blocklen;

}

static int pcapng_read_enhanced(libtrace_t *libtrace, libtrace_packet_t *packet,
                uint32_t blocklen, uint32_t flags) {
        pcapng_epkt_t *hdr = NULL;
        uint32_t caplen;
        uint32_t ifaceid;
        pcapng_interface_t *interface;
        uint16_t optcode, optlen;
        char *optval;
        char *bodyptr;

        if (blocklen < (int)sizeof(pcapng_epkt_t) + 4) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Incomplete pcapng enhanced packet header");
                return -1;
        }

        hdr = (pcapng_epkt_t *)packet->buffer;

        /* Read the rest of the packet into the buffer */
        if (DATA(libtrace)->byteswapped) {
		if (byteswap32(hdr->blocktype) != PCAPNG_ENHANCED_PACKET_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid block type in "
				"pcapng enhanced packet block");
			return -1;
		}
                caplen = byteswap32(hdr->caplen);
                ifaceid = byteswap32(hdr->interfaceid);
        } else {
		if (hdr->blocktype != PCAPNG_ENHANCED_PACKET_TYPE) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Invalid block type in "
				"pcapng enhanced packet block");
			return -1;
		}
                caplen = hdr->caplen;
                ifaceid = hdr->interfaceid;
        }

        bodyptr = (char *) packet->buffer + sizeof(pcapng_epkt_t);

        /* Set packet type based on interface linktype */
        interface = lookup_interface(libtrace, ifaceid);
        if (interface == NULL) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Unknown pcapng interface id: %u", ifaceid);
                return -1;
        }
        packet->type = pcapng_linktype_to_rt(interface->linktype);

        /* May as well cache the capture length now, since we've
         * already got it in the right byte order */
        packet->cached.capture_length = caplen;

        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }

        /* Make sure to parse any useful options */
        if ((caplen % 4) == 0) {
                bodyptr = (char *) packet->payload + caplen;
        } else {
                bodyptr = (char *) packet->payload + caplen + (4 - (caplen % 4));
        }
        // Check the packet caplen actually fits within the block we read
        if ((char *) packet->buffer + blocklen < bodyptr + 4) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Incomplete pcapng enhanced packet header");
                return -1;
        }

        do {
                optval = pcapng_parse_next_option(packet->trace, &bodyptr,
                                &optcode, &optlen, (pcapng_hdr_t *) packet->buffer);
                if (optval == NULL) {
                        trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Failed to read options for pcapng enhanced packet");
                        return -1;
                }

                if (optcode == PCAPNG_PKTOPT_DROPCOUNT) {
                        uint64_t *drops = (uint64_t *)optval;
                        if (DATA(packet->trace)->byteswapped) {
                                interface->dropcounter += byteswap64(*drops);
                        } else {
                                interface->dropcounter += *drops;
                        }
                }

        } while (optcode != 0);
        return (int) blocklen;

}

static int pcapng_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet)
{
        struct pcapng_peeker peeker;
        int err = 0;
        uint32_t flags = 0;
        uint32_t to_read;
        uint32_t btype = 0;
        int gotpacket = 0;

	/* Ensure trace and packet are not NULL */
	if (!libtrace) {
		fprintf(stderr, "NULL trace passed into pcapng_read_packet()\n");
		return TRACE_ERR_NULL_TRACE;
	}
	if (!packet) {
		trace_set_err(libtrace, TRACE_ERR_NULL_PACKET, "NULL packet passed into "
			"pcapng_read_packet()\n");
		return -1;
	}

        /* Peek to get next block type */
	if (!libtrace->format_data) {
		trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, "Trace has no format data in "
			"pcapng_read_packet()");
		return -1;
	}
	if (!libtrace->io) {
		trace_set_err(libtrace, TRACE_ERR_BAD_IO, "Trace has no valid file handle "
			"attached to it in pcapng_read_packet()");
		return -1;
	}

        if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
                packet->buffer = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
        }

        flags |= TRACE_PREP_OWN_BUFFER;

        while (!gotpacket) {

                if ((err=is_halted(libtrace)) != -1) {
                        return err;
                }

                err = wandio_peek(libtrace->io, &peeker, sizeof(peeker));
                if (err < 0) {
                        trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED, "reading pcapng packet");
                        return -1;
                }

                if (err == 0) {
                        return 0;
                }

                if (err < (int)sizeof(struct pcapng_peeker)) {
                        trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED, "Incomplete pcapng block");
                        return -1;
                }

                // Warning: the byteorder might not be set yet, the section header sets this
                if (DATA(libtrace)->byteswapped) {
                        btype = byteswap32(peeker.blocktype);
                        to_read = byteswap32(peeker.blocklen);
                } else {
                        btype = peeker.blocktype;
                        to_read = peeker.blocklen;
                }

                // Check we won't read off the end of the packet buffer. Assuming corruption.
                // Exclude the SECTION header, as this is used to identify the byteorder
                if (to_read > LIBTRACE_PACKET_BUFSIZE && btype != PCAPNG_SECTION_TYPE) {
                        trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                      "Oversized pcapng block found, is the trace corrupted?");
                        return -1;
                }
                if (btype != PCAPNG_SECTION_TYPE) {
                        // Read the entire block, unless it is a section as our byte ordering has
                        // not been set yet.
                        err = pcapng_read_body(libtrace, packet->buffer, to_read);
                        if (err <= 0) {
                                return err;
                        }
                        if (*((uint32_t *)((char *)packet->buffer+to_read-4)) != peeker.blocklen) {
                                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                              "Mismatched pcapng block sizes found, trace is invalid.");
                                return -1;
                        }
                }

                switch (btype) {
                        /* Section Header */
                        case PCAPNG_SECTION_TYPE:
				/* Section header packets are required for PCAPNG so even if discard_meta
				 * option is set it still needs to be processed. Not setting gotpacket will
				 * prevent triggering the meta callback */
                               	err = pcapng_read_section(libtrace, packet, flags);
				if (!DATA(libtrace)->discard_meta) {
                               		gotpacket = 1;
				}

                                break;

                        /* Interface Header */
                        case PCAPNG_INTERFACE_TYPE:
				/* Same applies here for Interface packets */
                                err = pcapng_read_interface(libtrace, packet, to_read, flags);
				if (!DATA(libtrace)->discard_meta) {
                                	gotpacket = 1;
				}
                                break;


                        case PCAPNG_ENHANCED_PACKET_TYPE:
                                err = pcapng_read_enhanced(libtrace, packet,
                                                to_read, flags);
                                gotpacket = 1;
                                break;

                        case PCAPNG_SIMPLE_PACKET_TYPE:
                                err = pcapng_read_simple(libtrace, packet, to_read, flags);
                                gotpacket = 1;
                                break;

                        case PCAPNG_INTERFACE_STATS_TYPE:
				/* If discard_meta is set ignore this packet type */
				if (!DATA(libtrace)->discard_meta) {
                                	err = pcapng_read_stats(libtrace, packet, to_read, flags);
                                	gotpacket = 1;
				}
                                break;

                        case PCAPNG_NAME_RESOLUTION_TYPE:
				/* If discard meta is set ignore this packet type */
				if (!DATA(libtrace)->discard_meta) {
                                	err = pcapng_read_nrb(libtrace, packet, to_read, flags);
                                	gotpacket = 1;
				}
                                break;

                        case PCAPNG_CUSTOM_TYPE:
                        case PCAPNG_CUSTOM_NONCOPY_TYPE:
				/* If discard meta is set ignore this packet type */
				if (!DATA(libtrace)->discard_meta) {
                                	err = pcapng_read_custom(libtrace, packet, to_read, flags);
                                	gotpacket = 1;
				}
                                break;


                        case PCAPNG_OLD_PACKET_TYPE:
                                /* TODO */

                        /* Everything else -- don't care, skip it */
                        default:
                                break;
                }
        }

        if (err <= 0) {
                return err;
        }

        if (DATA(libtrace)->byteswapped)
                return byteswap32(peeker.blocklen);
        return peeker.blocklen;

}

static libtrace_linktype_t pcapng_get_link_type(const libtrace_packet_t *packet) {

	if (packet->type == TRACE_RT_PCAPNG_META) {
		return TRACE_TYPE_PCAPNG_META;
	}

        return pcap_linktype_to_libtrace(rt_to_pcap_linktype(packet->type));
}

static libtrace_direction_t pcapng_get_direction(const libtrace_packet_t
                *packet) {
	libtrace_direction_t direction = -1;

        /* Defined in format_helper.c */
	if (PACKET_IS_ENHANCED || PACKET_IS_SIMPLE || PACKET_IS_OLD) {
        	direction = pcap_get_direction(packet);
	}

	return direction;
}

static struct timespec pcapng_get_timespec(const libtrace_packet_t *packet) {

        struct timespec ts;
        uint64_t timestamp = 0;
        uint32_t interfaceid = 0;
        pcapng_interface_t *interface;

        memset(&ts, 0, sizeof(struct timespec));

	if (!packet) {
		fprintf(stderr, "NULL packet passed into pcapng_get_timespec()");
		/* Return default timespec on error? */
		return ts;
	}
	if (!packet->header) {
		trace_set_err(packet->trace, TRACE_ERR_BAD_PACKET, "NULL header in packet in pcapng_get_timespec()");
		/* Return default timespec on error? */
		return ts;
	}

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        /* No timestamps in simple packets :( */
        if (PACKET_IS_SIMPLE) {
                return ts;
        }

        if (PACKET_IS_ENHANCED) {
                pcapng_epkt_t *ehdr = (pcapng_epkt_t *)packet->header;

                if (DATA(packet->trace)->byteswapped) {
                        timestamp = ((uint64_t)(byteswap32(ehdr->timestamp_high)) << 32) + byteswap32(ehdr->timestamp_low);
                        interfaceid = byteswap32(ehdr->interfaceid);
                } else {
                        timestamp = ((uint64_t)(ehdr->timestamp_high) << 32) +
                                        ehdr->timestamp_low;
                        interfaceid = ehdr->interfaceid;
                }
        } else if (PACKET_IS_OLD) {
                pcapng_opkt_t *ohdr = (pcapng_opkt_t *)packet->header;

                if (DATA(packet->trace)->byteswapped) {
                        timestamp = ((uint64_t)(byteswap32(ohdr->timestamp_high)) << 32) + byteswap32(ohdr->timestamp_low);
                        interfaceid = byteswap16(ohdr->interfaceid);
                } else {
                        timestamp = ((uint64_t)(ohdr->timestamp_high) << 32) +
                                        ohdr->timestamp_low;
                        interfaceid = ohdr->interfaceid;
                }

        }

        if (timestamp == 0)
                return ts;


        interface = lookup_interface(packet->trace, interfaceid);
        if (interface == NULL) {
                trace_set_err(packet->trace, TRACE_ERR_BAD_PACKET,
                                "Bad interface %u on pcapng packet",
                                interfaceid);
                return ts;
        }

        ts.tv_sec = (timestamp / interface->tsresol);
        ts.tv_nsec = (uint64_t)(timestamp - (ts.tv_sec * interface->tsresol))
                        / ((double)interface->tsresol) * 1000000000;

        return ts;

}

static inline int pcapng_get_wlen_header(const libtrace_packet_t *packet) {

        if (PACKET_IS_ENHANCED) {
                pcapng_epkt_t *ehdr = (pcapng_epkt_t *)packet->header;

                if (DATA(packet->trace)->byteswapped) {
                        return byteswap32(ehdr->wlen);
                } else {
                        return ehdr->wlen;
                }
        } else if (PACKET_IS_SIMPLE) {
                pcapng_spkt_t *shdr = (pcapng_spkt_t *)packet->header;

                if (DATA(packet->trace)->byteswapped) {
                        return byteswap32(shdr->wlen);
                } else {
                        return shdr->wlen;
                }
        } else if (PACKET_IS_OLD) {
                pcapng_opkt_t *ohdr = (pcapng_opkt_t *)packet->header;

                if (DATA(packet->trace)->byteswapped) {
                        return byteswap32(ohdr->wlen);
                } else {
                        return ohdr->wlen;
                }
        } else if (PACKET_IS_SECTION || PACKET_IS_INTERFACE || PACKET_IS_NAME_RESOLUTION
		|| PACKET_IS_INTERFACE_STATS || PACKET_IS_CUSTOM ||
		PACKET_IS_CUSTOM_NONCOPY || PACKET_IS_DECRYPTION_SECRETS) {
		/* meta packet are not transmitted on the wire hence the 0 wirelen */
		return 0;
	}

        /* If we get here, we aren't a valid pcapng packet */
        trace_set_err(packet->trace, TRACE_ERR_BAD_PACKET,
                        "Invalid RT type for pcapng packet: %u",
                        packet->type);
        return -1;
}

static int pcapng_get_wire_length(const libtrace_packet_t *packet) {

        /* First, get the wire length from the packet header */
        int baselen = pcapng_get_wlen_header(packet);

        if (baselen == -1)
                return -1;

	/* if packet was a meta packet baselen should be zero so return it */
	if (baselen == 0) {
		return 0;
	}

        /* Then, account for the vagaries of different DLTs */
        if (rt_to_pcap_linktype(packet->type) == TRACE_DLT_EN10MB) {
                /* Include the missing FCS */
                baselen += 4;
        } else if (rt_to_pcap_linktype(packet->type) ==
                        TRACE_DLT_IEEE802_11_RADIO) {
                /* If the packet is Radiotap and the flags field indicates
                 * that the FCS is not included in the 802.11 frame, then
                 * we need to add 4 to the wire-length to account for it.
                 */
                uint8_t flags;
                void *link;
                libtrace_linktype_t linktype;
                link = trace_get_packet_buffer(packet, &linktype, NULL);
                trace_get_wireless_flags(link, linktype, &flags);
                if ((flags & TRACE_RADIOTAP_F_FCS) == 0) {
                        baselen += 4;
                }
        } else if (rt_to_pcap_linktype(packet->type) == TRACE_DLT_LINUX_SLL) {
                libtrace_sll_header_t *sll;
                sll = (libtrace_sll_header_t *)packet->payload;

                /* Account for FCS when dealing with Ethernet packets that are
                 * encapsulated in Linux SLL. This should fix the problem
                 * where the wire lengths differ if we convert the packet to
                 * ERF */
                if (ntohs(sll->protocol) == TRACE_ETHERTYPE_LOOPBACK) {
                        baselen += 4;
                }
        }

        return baselen;
}

static int pcapng_get_capture_length(const libtrace_packet_t *packet) {

        if (PACKET_IS_ENHANCED) {
                pcapng_epkt_t *ehdr = (pcapng_epkt_t *)packet->header;

                if (DATA(packet->trace)->byteswapped) {
                        return byteswap32(ehdr->caplen);
                } else {
                        return ehdr->caplen;
                }
        } else if (PACKET_IS_SIMPLE) {
                pcapng_spkt_t *shdr = (pcapng_spkt_t *)packet->header;

                /* Have to calculate this one by removing all the headers.
                 * Don't forget the extra length field at the end!
                 */
                if (DATA(packet->trace)->byteswapped) {
                        return byteswap32(shdr->blocklen) -
                                        sizeof(pcapng_spkt_t) - 4;
                } else {
                        return shdr->blocklen - sizeof(pcapng_spkt_t) - 4;
                }
        } else if (PACKET_IS_OLD) {
                pcapng_opkt_t *ohdr = (pcapng_opkt_t *)packet->header;

                if (DATA(packet->trace)->byteswapped) {
                        return byteswap32(ohdr->caplen);
                } else {
                        return ohdr->caplen;
                }
        } else if (PACKET_IS_SECTION || PACKET_IS_INTERFACE || PACKET_IS_NAME_RESOLUTION
                || PACKET_IS_INTERFACE_STATS || PACKET_IS_CUSTOM ||
                PACKET_IS_CUSTOM_NONCOPY || PACKET_IS_DECRYPTION_SECRETS) {

                struct pcapng_peeker *hdr = (struct pcapng_peeker *)packet->header;
		if (DATA(packet->trace)->byteswapped) {
			return byteswap32(hdr->blocklen) - trace_get_framing_length(packet);
		} else {
			return hdr->blocklen - trace_get_framing_length(packet);
		}
	}

        /* If we get here, we aren't a valid pcapng packet */
        trace_set_err(packet->trace, TRACE_ERR_BAD_PACKET,
                        "Invalid RT type for pcapng packet: %u",
                        packet->type);
        return -1;
}

static size_t pcapng_set_capture_length(libtrace_packet_t *packet,
                size_t size) {
        uint32_t current;
        char *copyto, *copyfrom;
        uint32_t tocopy;

        if (!(PACKET_IS_SIMPLE) && !(PACKET_IS_ENHANCED)) {
                return 0;
        }

        current = pcapng_get_capture_length(packet);

        if (current <= size)
                return current;

        copyto = (char *)packet->payload + size;
        copyfrom = (char *)packet->payload + current;

        /* Need to make sure we keep the options and trailing length... */

        if (PACKET_IS_SIMPLE) {
                tocopy = 4;
        } else {
                pcapng_epkt_t *ehdr = (pcapng_epkt_t *)packet->header;
                if (DATA(packet->trace)->byteswapped) {
                        tocopy =  byteswap32(ehdr->blocklen) -
                                        sizeof(pcapng_epkt_t) - current;
                } else {
                        tocopy = ehdr->blocklen - sizeof(pcapng_epkt_t) -
                                        current;
                }
        }

        memmove(copyto, copyfrom, tocopy);

        if (PACKET_IS_SIMPLE) {
                pcapng_spkt_t *shdr = (pcapng_spkt_t *)packet->header;

                if (DATA(packet->trace)->byteswapped) {
                        shdr->blocklen = byteswap32(size + sizeof(pcapng_spkt_t) + tocopy);
                } else {
                        shdr->blocklen = size + sizeof(pcapng_spkt_t) + tocopy;
                }
        }

        if (PACKET_IS_ENHANCED) {
                pcapng_epkt_t *ehdr = (pcapng_epkt_t *)packet->header;

                if (DATA(packet->trace)->byteswapped) {
                        ehdr->blocklen = byteswap32(size + sizeof(pcapng_epkt_t) + tocopy);
                        ehdr->caplen = byteswap32(size);
                } else {
                        ehdr->blocklen = size + sizeof(pcapng_epkt_t) + tocopy;
                        ehdr->caplen = size;
                }
        }
        packet->cached.capture_length = -1;
        return trace_get_capture_length(packet);
}


static struct libtrace_eventobj_t pcapng_event(libtrace_t *libtrace,
                libtrace_packet_t *packet) {

        libtrace_eventobj_t event = {0,0,0.0,0};

        if (DATA(libtrace)->realtime) {
                event.size = trace_read_packet(libtrace, packet);
                if (event.size < 1) {
                        event.type = TRACE_EVENT_TERMINATE;
                } else {
                        event.type = TRACE_EVENT_PACKET;
                }
        } else {
                event = trace_event_trace(libtrace, packet);
        }

        return event;
}

static void pcapng_get_statistics(libtrace_t *trace, libtrace_stat_t *stat) {

        int i = 0;
        uint64_t drops = 0;
        uint64_t accepted = 0;
        uint64_t osdrops = 0;
        uint64_t received = 0;

        if (!trace->format_data) {
                return;
        }

        /* Add up all known interface stats */
        for (i = 0; i < DATA(trace)->nextintid; i++) {
                pcapng_interface_t *interface;

                interface = lookup_interface(trace, i);
                if (interface == NULL) {
                        continue;
                }

                received += interface->received;
                osdrops += interface->osdropped;
                accepted += interface->accepted;
                drops += interface->dropped;

        }

        stat->dropped = drops + osdrops;
        stat->dropped_valid = 1;

        stat->received = received;
        stat->received_valid = 1;

        stat->filtered = received - accepted;
        stat->filtered_valid = 1;

        stat->captured = accepted;
        stat->captured_valid = 1;


}

static libtrace_meta_datatype_t pcapng_get_datatype(uint32_t section, uint32_t option) {
	switch(section) {
		case(PCAPNG_SECTION_TYPE):
			return TRACE_META_STRING;
		case(PCAPNG_INTERFACE_TYPE):
			switch(option) {
				case(PCAPNG_META_IF_NAME): return TRACE_META_STRING;
				case(PCAPNG_META_IF_DESCR): return TRACE_META_STRING;
				case(PCAPNG_META_IF_IP4): return TRACE_META_IPV4;
				case(PCAPNG_META_IF_IP6): return TRACE_META_IPV6;
				case(PCAPNG_META_IF_MAC): return TRACE_META_MAC;
				case(PCAPNG_META_IF_EUI): return TRACE_META_UINT64;
				case(PCAPNG_META_IF_SPEED): return PCAPNG_META_IF_SPEED;
				case(PCAPNG_META_IF_TSRESOL): return TRACE_META_UINT8;
				case(PCAPNG_META_IF_TZONE): return TRACE_META_UINT32;
				case(PCAPNG_META_IF_FILTER): return TRACE_META_STRING;
				case(PCAPNG_META_IF_OS): return TRACE_META_STRING;
				case(PCAPNG_META_IF_FCSLEN): return TRACE_META_UINT8;
				case(PCAPNG_META_IF_TSOFFSET): return TRACE_META_UINT64;
				case(PCAPNG_META_IF_HARDWARE): return TRACE_META_STRING;
			}
                        break;
		case(PCAPNG_OLD_PACKET_TYPE):
			switch(option) {
				case(PCAPNG_META_OLD_FLAGS): return TRACE_META_UINT32;
				case(PCAPNG_META_OLD_HASH): return TRACE_META_STRING;
			}
                        break;
		case(PCAPNG_SIMPLE_PACKET_TYPE):
			/* simple packets should not contain any options */
			return TRACE_META_UNKNOWN;
		case(PCAPNG_NAME_RESOLUTION_TYPE):
			/* todo - needs to handle name resolution options along with
			 * normal options */
			return TRACE_META_UNKNOWN;
		case(PCAPNG_INTERFACE_STATS_TYPE):
			return TRACE_META_UINT64;
		case(PCAPNG_ENHANCED_PACKET_TYPE):
			switch(option) {
				case(PCAPNG_META_EPB_FLAGS): return TRACE_META_UINT32;
				case(PCAPNG_META_EPB_HASH): return TRACE_META_STRING;
				case(PCAPNG_META_EPB_DROPCOUNT): return TRACE_META_UINT64;
			}
                        break;
		case(PCAPNG_DECRYPTION_SECRETS_TYPE):
			/* todo - needs to handle decryption secrets options along with
                         * normal options */
			return TRACE_META_UNKNOWN;
		default:
			return TRACE_META_UNKNOWN;
	}
        return TRACE_META_UNKNOWN;
}

static void *pcapng_jump_to_options(libtrace_packet_t *packet) {

	struct pcapng_peeker *hdr = (struct pcapng_peeker *)packet->buffer;
	void *ptr = packet->buffer;
	uint32_t blocktype;

	if (DATA(packet->trace)->byteswapped) {
                blocktype = byteswap32(hdr->blocktype);
        } else {
                blocktype = hdr->blocktype;
        }

	/* Skip x bytes to the options depending on what kind of packet this is */
        if (blocktype == PCAPNG_SECTION_TYPE) { ptr += sizeof(pcapng_sec_t); }
        else if (blocktype == PCAPNG_INTERFACE_TYPE) { ptr += sizeof(pcapng_int_t); }
        else if (blocktype == PCAPNG_OLD_PACKET_TYPE) { ptr += sizeof(pcapng_opkt_t); }
        else if (blocktype == PCAPNG_NAME_RESOLUTION_TYPE) { ptr += sizeof(pcapng_nrb_t); }
        else if (blocktype == PCAPNG_INTERFACE_STATS_TYPE) { ptr += sizeof(pcapng_stats_t); }
        else if (blocktype == PCAPNG_ENHANCED_PACKET_TYPE) {
                /* jump over the the enchanced packet header and data to the options */
                pcapng_epkt_t *epkthdr = (pcapng_epkt_t *)ptr;
                uint32_t seclen;
                if (DATA(packet->trace)->byteswapped) {
                        seclen = byteswap32(epkthdr->caplen);
                } else {
                        seclen = epkthdr->caplen;
                }
                if ((seclen % 4) != 0) {
                        ptr += seclen + (4 -(seclen % 4)) + sizeof(pcapng_secrets_t);
                } else {
                        ptr += seclen + sizeof(pcapng_secrets_t);
                }
        } 
        else if (blocktype == PCAPNG_DECRYPTION_SECRETS_TYPE) {
                /* jump over the decryption secrets header and data to the options */
                pcapng_secrets_t *sechdr = (pcapng_secrets_t *)ptr;
                uint32_t seclen;
                if (DATA(packet->trace)->byteswapped) {
                        seclen = byteswap32(sechdr->secrets_len);
                } else {
                        seclen = sechdr->secrets_len;
                }
                if ((seclen % 4) != 0) {
                        ptr += seclen + (4 -(seclen % 4)) + sizeof(pcapng_secrets_t);
                } else {
                        ptr += seclen + sizeof(pcapng_secrets_t);
                }
        }
        else { return NULL; }

	return ptr;
}

libtrace_meta_t *pcapng_get_all_meta(libtrace_packet_t *packet) {

	struct pcapng_peeker *hdr;
	uint32_t remaining;
	void *ptr;
	uint32_t blocktype;
	uint16_t optcode;
	uint16_t len;
	uint16_t tmp;

	if (packet == NULL) {
		fprintf(stderr, "NULL packet passed into pcapng_get_all_meta()\n");
		return NULL;
	}
	if (packet->buffer == NULL) { return NULL; }

	hdr = (struct pcapng_peeker *)packet->buffer;
        ptr = pcapng_jump_to_options(packet);

	if (DATA(packet->trace)->byteswapped) {
                blocktype = byteswap32(hdr->blocktype);
                remaining = byteswap32(hdr->blocklen);
        } else {
                blocktype = hdr->blocktype;
                remaining = hdr->blocklen;
        }

        if (ptr == NULL) {
                return NULL;
        }
	/* update remaining to account for header and any payload */
        remaining -= (ptr - packet->buffer);

        struct pcapng_optheader *opthdr = ptr;
        if (DATA(packet->trace)->byteswapped) {
                optcode = byteswap16(opthdr->optcode);
                len  = byteswap16(opthdr->optlen);
        } else {
                optcode = opthdr->optcode;
                len = opthdr->optlen;
        }

	/* setup structure to hold the result */
        libtrace_meta_t *result = malloc(sizeof(libtrace_meta_t));
        result->num = 0;

	while (optcode != PCAPNG_OPTION_END && remaining > sizeof(struct pcapng_optheader)) {

		result->num += 1;
                if (result->num == 1) {
                	result->items = malloc(sizeof(libtrace_meta_item_t));
                } else {
                        result->items = realloc(result->items,
                	        result->num*sizeof(libtrace_meta_item_t));
                }
                result->items[result->num-1].section = blocktype;
                result->items[result->num-1].option = optcode;
                result->items[result->num-1].len = len;
                result->items[result->num-1].datatype =
			pcapng_get_datatype(blocktype, optcode);

		/* If the datatype is a string allow for a null terminator */
		if (result->items[result->num-1].datatype == TRACE_META_STRING) {
			result->items[result->num-1].data =
				calloc(1, len+1);
			((char *)result->items[result->num-1].data)[len] = '\0';
			/* and copy the utf8 string */
			memcpy(result->items[result->num-1].data,
				ptr+sizeof(struct pcapng_optheader), len);
		} else {
			result->items[result->num-1].data =
				calloc(1, len);
			/* depending on the datatype we need to ensure the data is
			 * in host byte ordering */
			if (result->items[result->num-1].datatype == TRACE_META_UINT32) {
				uint32_t t = *(uint32_t *)(ptr+sizeof(struct pcapng_optheader));
				t = ntohl(t);
				memcpy(result->items[result->num-1].data,
					&t, sizeof(uint32_t));
			} else if(result->items[result->num-1].datatype == TRACE_META_UINT64) {
				uint64_t t = *(uint64_t *)(ptr+sizeof(struct pcapng_optheader));
				t = bswap_be_to_host64(t);
				memcpy(result->items[result->num-1].data,
					&t, sizeof(uint64_t));
			} else {
				memcpy(result->items[result->num-1].data,
					ptr+sizeof(struct pcapng_optheader), len);
			}

		}

		/* work out any padding */
                if ((len % 4) != 0) {
			tmp = len + (4 - (len % 4)) + sizeof(struct pcapng_optheader);
                } else {
			tmp = len + sizeof(struct pcapng_optheader);
		}
                ptr += tmp;
		remaining -= tmp;

                /* get the next option */
                opthdr = (struct pcapng_optheader *)ptr;
                if (DATA(packet->trace)->byteswapped) {
                        optcode = byteswap16(opthdr->optcode);
                        len = byteswap16(opthdr->optlen);
                } else {
                        optcode = opthdr->optcode;
                        len = opthdr->optlen;
                }
	}

	/* if any data was found result->num will be greater than 0 */
	if (result->num > 0) {
		return (void *)result;
	} else {
		free(result);
		return NULL;
	}

}

static void pcapng_help(void) {
        printf("pcapng format module: \n");
        printf("Supported input URIs:\n");
        printf("\tpcapng:/path/to/file\n");
        printf("\tpcapng:/path/to/file.gz\n");
        printf("\n");
        printf("\te.g.: pcapng:/tmp/trace.pcap\n");
        printf("\n");
}

static struct libtrace_format_t pcapng = {
        "pcapng",
        "$Id$",
        TRACE_FORMAT_PCAPNG,
        NULL,                           /* probe filename */
        pcapng_probe_magic,             /* probe magic */
        pcapng_init_input,              /* init_input */
        pcapng_config_input,            /* config_input */
        pcapng_start_input,             /* start_input */
        NULL,                           /* pause_input */
        pcapng_init_output,             /* init_output */
        pcapng_config_output,           /* config_output */
        NULL,                           /* start_output */
        pcapng_fin_input,               /* fin_input */
        pcapng_fin_output,              /* fin_output */
        pcapng_read_packet,             /* read_packet */
        pcapng_prepare_packet,          /* prepare_packet */
        NULL,                           /* fin_packet */
        pcapng_write_packet,            /* write_packet */
        pcapng_flush_output,            /* flush_output */
        pcapng_get_link_type,           /* get_link_type */
        pcapng_get_direction,           /* get_direction */
        NULL,                           /* set_direction */
        NULL,                           /* get_erf_timestamp */
        NULL,                           /* get_timeval */
        pcapng_get_timespec,            /* get_timespec */
        NULL,                           /* get_seconds */
	pcapng_get_all_meta,        /* get_all_meta */
        NULL,                           /* seek_erf */
        NULL,                           /* seek_timeval */
        NULL,                           /* seek_seconds */
        pcapng_get_capture_length,      /* get_capture_length */
        pcapng_get_wire_length,         /* get_wire_length */
        pcapng_get_framing_length,      /* get_framing_length */
        pcapng_set_capture_length,      /* set_capture_length */
        NULL,                           /* get_received_packets */
        NULL,                           /* get_filtered_packets */
        NULL,                           /* get_dropped_packets */
        pcapng_get_statistics,          /* get_statistics */
        NULL,                           /* get_fd */
        pcapng_event,                   /* trace_event */
        pcapng_help,                    /* help */
        NULL,                           /* next pointer */
        NON_PARALLEL(false)
};

void pcapng_constructor(void) {
        register_format(&pcapng);
}
