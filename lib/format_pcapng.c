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

#include <sys/stat.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <math.h>

#define PCAPNG_SECTION_TYPE 0x0A0D0D0A
#define PCAPNG_INTERFACE_TYPE 0x00000001
#define PCAPNG_OLD_PACKET_TYPE 0x00000002
#define PCAPNG_SIMPLE_PACKET_TYPE 0x00000003
#define PCAPNG_NAME_RESOLUTION_TYPE 0x00000004
#define PCAPNG_INTERFACE_STATS_TYPE 0x00000005
#define PCAPNG_ENHANCED_PACKET_TYPE 0x00000006
#define PCAPNG_CUSTOM_TYPE 0x00000BAD
#define PCAPNG_CUSTOM_NONCOPY_TYPE 0x40000BAD

#define PACKET_IS_ENHANCED (pcapng_get_record_type(packet) == PCAPNG_ENHANCED_PACKET_TYPE)

#define PACKET_IS_SIMPLE (pcapng_get_record_type(packet) == PCAPNG_SIMPLE_PACKET_TYPE)

#define PACKET_IS_OLD (pcapng_get_record_type(packet) == PCAPNG_OLD_PACKET_TYPE)


#define PCAPNG_IFOPT_TSRESOL 9

#define PCAPNG_PKTOPT_DROPCOUNT 4

#define PCAPNG_STATOPT_START 2
#define PCAPNG_STATOPT_END 3
#define PCAPNG_STATOPT_IFRECV 4
#define PCAPNG_STATOPT_IFDROP 5
#define PCAPNG_STATOPT_FILTERACCEPT 6
#define PCAPNG_STATOPT_OSDROP 7
#define PCAPNG_STATOPT_USRDELIV 8

typedef struct pcagng_section_header_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint32_t ordering;
        uint16_t majorversion;
        uint16_t minorversion;
        uint64_t sectionlen;
} pcapng_sec_t;

typedef struct pcapng_interface_header_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint16_t linktype;
        uint16_t reserved;
        uint32_t snaplen;
} pcapng_int_t;

typedef struct pcapng_nrb_header_t {
        uint32_t blocktype;
        uint32_t blocklen;
} pcapng_nrb_t;

typedef struct pcapng_enhanced_packet_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint32_t interfaceid;
        uint32_t timestamp_high;
        uint32_t timestamp_low;
        uint32_t caplen;
        uint32_t wlen;
} pcapng_epkt_t;

typedef struct pcapng_simple_packet_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint32_t wlen;
} pcapng_spkt_t;

typedef struct pcapng_old_packet_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint16_t interfaceid;
        uint16_t drops;
        uint32_t timestamp_high;
        uint32_t timestamp_low;
        uint32_t caplen;
        uint32_t wlen;
} pcapng_opkt_t;

typedef struct pcapng_stats_header_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint32_t interfaceid;
        uint32_t timestamp_high;
        uint32_t timestamp_low;
} pcapng_stats_t;

typedef struct pcapng_custom_header_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint32_t pen;
} pcapng_custom_t;

typedef struct pcapng_interface_t pcapng_interface_t;

struct pcapng_interface_t {

        uint16_t id;
        libtrace_dlt_t linktype;
        uint32_t snaplen;
        uint32_t tsresol;

        uint64_t received;
        uint64_t dropped;       /* as reported by interface stats */
        uint64_t dropcounter;   /* as reported by packet records */
        uint64_t accepted;
        uint64_t osdropped;
        uint64_t laststats;

};

struct pcapng_format_data_t {
        bool started;
        bool realtime;

        /* Section data */
        bool byteswapped;

        /* Interface data */
        pcapng_interface_t **interfaces;
        uint16_t allocatedinterfaces;
        uint16_t nextintid;
};

struct pcapng_optheader {
        uint16_t optcode;
        uint16_t optlen;
};

struct pcapng_peeker {
        uint32_t blocktype;
        uint32_t blocklen;
};


#define DATA(x) ((struct pcapng_format_data_t *)((x)->format_data))

static pcapng_interface_t *lookup_interface(libtrace_t *libtrace,
                uint32_t intid) {


        if (intid >= DATA(libtrace)->nextintid) {
                return NULL;
        }

        return DATA(libtrace)->interfaces[intid];

}

static inline uint32_t pcapng_get_record_type(const libtrace_packet_t *packet) {

        uint32_t *btype = (uint32_t *)packet->header;

        if (DATA(packet->trace)->byteswapped)
                return byteswap32(*btype);
        return *btype;
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


static int pcapng_init_input(libtrace_t *libtrace) {
        libtrace->format_data = malloc(sizeof(struct pcapng_format_data_t));
        if (libtrace->format_data == NULL) {
                trace_set_err(libtrace, ENOMEM, "Out of memory!");
                return -1;
        }

        DATA(libtrace)->started = false;
        DATA(libtrace)->realtime = false;
        DATA(libtrace)->byteswapped = true;
        DATA(libtrace)->interfaces = (pcapng_interface_t **)calloc(10, \
                        sizeof(pcapng_interface_t));
        DATA(libtrace)->allocatedinterfaces = 10;
        DATA(libtrace)->nextintid = 0;

        return 0;
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
                        break;
        }

        trace_set_err(libtrace, TRACE_ERR_UNKNOWN_OPTION, "Unknown option %i",
                        option);
        return -1;
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

static char *pcapng_parse_next_option(libtrace_t *libtrace, char **pktbuf,
                uint16_t *code, uint16_t *length) {

        struct pcapng_optheader *opthdr = (struct pcapng_optheader *)*pktbuf;
        int to_skip;
        int padding = 0;
        char *optval;

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
        *pktbuf = optval + to_skip;

        return optval;
}

static inline int skip_block(libtrace_t *libtrace, uint32_t toread) {
        int err;

        while (toread > 0) {
                char buf[4096];
                int nextread;

                if (toread < 4096) {
                        nextread = toread;
                } else {
                        nextread = 4096;
                }

                err = wandio_read(libtrace->io, buf, nextread);
                if (err < 0) {
                        trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED,
                                "Reading section header options");
                        return -1;
                }
                if (err == 0) {
                        return 0;
                }
                toread -= err;
        }

        return 1;

}

static inline int pcapng_read_body(libtrace_t *libtrace, char *body,
                uint32_t to_read) {

        int err;

        err = wandio_read(libtrace->io, body, to_read);
        if (err < 0) {
                trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED,
                        "Failed to read pcapng interface options");
                return err;
        }

        if (err == 0) {
                return err;
        }

        if (err < (int)to_read) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                        "Incomplete pcapng interface header block");
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
                case PCAPNG_CUSTOM_NONCOPY_TYPE:
                        return sizeof(pcapng_custom_t);
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

static int pcapng_read_section(libtrace_t *libtrace,
                libtrace_packet_t *packet, uint32_t flags) {

        pcapng_sec_t *sechdr;
        int err;
        uint32_t to_read;
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

        if (err < (int)(sizeof(sechdr))) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                        "Incomplete pcapng section header block");
                return -1;
        }

        assert(sechdr->blocktype == PCAPNG_SECTION_TYPE);

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
                to_read = byteswap32(sechdr->blocklen) - sizeof(pcapng_sec_t);
        } else {
                if (sechdr->majorversion != 1 && sechdr->minorversion != 0) {
                        trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Parsing pcapng version numbers");
                        return -1;
                }
                to_read = sechdr->blocklen - sizeof(pcapng_sec_t);
        }

        /* Read all of the options etc. -- we don't need them for now, but
         * we have to skip forward to the next useful header. */
        bodyptr = packet->buffer + sizeof(pcapng_sec_t);
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
                libtrace_packet_t *packet, uint32_t flags) {

        pcapng_int_t *inthdr;
        int err;
        uint32_t to_read;
        pcapng_interface_t *newint;
        uint16_t optcode, optlen;
        char *optval = NULL;
        char *bodyptr = NULL;

        err = wandio_read(libtrace->io, packet->buffer, sizeof(pcapng_int_t));

        if (err < 0) {
                trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED,
                        "Reading pcapng interface header block");
                return -1;
        }

        if (err == 0) {
                return 0;
        }

        if (err < (int)sizeof(inthdr)) {
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
                assert(byteswap32(inthdr->blocktype) == PCAPNG_INTERFACE_TYPE);
                newint->snaplen = byteswap32(inthdr->snaplen);
                newint->linktype = byteswap16(inthdr->linktype);
                to_read = byteswap32(inthdr->blocklen) - sizeof(pcapng_int_t);
        } else {
                assert(inthdr->blocktype == PCAPNG_INTERFACE_TYPE);
                newint->snaplen = inthdr->snaplen;
                newint->linktype = inthdr->linktype;
                to_read = inthdr->blocklen - sizeof(pcapng_int_t);
        }

        if (DATA(libtrace)->nextintid == DATA(libtrace)->allocatedinterfaces) {
                DATA(libtrace)->allocatedinterfaces += 10;
                DATA(libtrace)->interfaces = (pcapng_interface_t **)realloc(
                        DATA(libtrace)->interfaces,
                        DATA(libtrace)->allocatedinterfaces * sizeof(
                                pcapng_interface_t *));

                /* Could memset the new memory to zero, if required */
        }

        DATA(libtrace)->interfaces[newint->id] = newint;
        DATA(libtrace)->nextintid += 1;

        bodyptr = packet->buffer + sizeof(pcapng_int_t);
        err = pcapng_read_body(libtrace, bodyptr, to_read);
        if (err <= 0) {
                return err;
        }

        packet->type = TRACE_RT_PCAPNG_META;

        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }

        do {
                optval = pcapng_parse_next_option(libtrace, &bodyptr,
                                &optcode, &optlen);
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

        return 1;

}

static int pcapng_read_nrb(libtrace_t *libtrace, libtrace_packet_t *packet,
                uint32_t flags) {

        /* Just read the NR records and pass them off to the caller. If
         * they want to do anything with them, they can parse the records
         * themselves.
         */
        pcapng_nrb_t *hdr = NULL;
        int err;
        uint32_t to_read;
        char *bodyptr;

        err = wandio_read(libtrace->io, packet->buffer, sizeof(pcapng_nrb_t));

        if (err < 0) {
                trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED, "reading pcapng name resolution block");
                return -1;
        }

        if (err == 0) {
                return 0;
        }

        if (err < (int)sizeof(pcapng_nrb_t)) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Incomplete pcapng name resolution block");
                return -1;
        }

        hdr = (pcapng_nrb_t *)packet->buffer;

        /* Read the rest of the packet into the buffer */
        if (DATA(libtrace)->byteswapped) {
                assert(byteswap32(hdr->blocktype) == PCAPNG_NAME_RESOLUTION_TYPE);
                to_read = byteswap32(hdr->blocklen) - sizeof(pcapng_nrb_t);
        } else {
                assert(hdr->blocktype == PCAPNG_NAME_RESOLUTION_TYPE);
                to_read = hdr->blocklen - sizeof(pcapng_nrb_t);
        }

        bodyptr = packet->buffer + sizeof(pcapng_nrb_t);
        err = pcapng_read_body(libtrace, bodyptr, to_read);
        if (err <= 0) {
                return err;
        }

        packet->type = TRACE_RT_PCAPNG_META;
        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }

        return sizeof(pcapng_nrb_t) + to_read;

}

static int pcapng_read_custom(libtrace_t *libtrace, libtrace_packet_t *packet,
                uint32_t flags) {

        /* Just read the custom records and pass them off to the caller. If
         * they want to do anything with them, they can parse the records
         * themselves.
         */
        pcapng_custom_t *hdr = NULL;
        int err;
        uint32_t to_read;
        char *bodyptr;

        err = wandio_read(libtrace->io, packet->buffer, sizeof(pcapng_custom_t));

        if (err < 0) {
                trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED, "reading pcapng custom block");
                return -1;
        }

        if (err == 0) {
                return 0;
        }

        if (err < (int)sizeof(pcapng_custom_t)) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Incomplete pcapng custom block");
                return -1;
        }

        hdr = (pcapng_custom_t *)packet->buffer;

        /* Read the rest of the packet into the buffer */
        if (DATA(libtrace)->byteswapped) {
                assert(byteswap32(hdr->blocktype) == PCAPNG_CUSTOM_TYPE ||
                        byteswap32(hdr->blocktype) == PCAPNG_CUSTOM_NONCOPY_TYPE);
                to_read = byteswap32(hdr->blocklen) - sizeof(pcapng_custom_t);
        } else {
                assert(hdr->blocktype == PCAPNG_NAME_RESOLUTION_TYPE ||
                        hdr->blocktype == PCAPNG_CUSTOM_NONCOPY_TYPE);
                to_read = hdr->blocklen - sizeof(pcapng_custom_t);
        }

        bodyptr = packet->buffer + sizeof(pcapng_custom_t);
        err = pcapng_read_body(libtrace, bodyptr, to_read);
        if (err <= 0) {
                return err;
        }

        packet->type = TRACE_RT_PCAPNG_META;
        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }

        return sizeof(pcapng_custom_t) + to_read;

}

static int pcapng_read_stats(libtrace_t *libtrace, libtrace_packet_t *packet,
                uint32_t flags) {
        pcapng_stats_t *hdr = NULL;
        int err;
        uint32_t to_read;
        uint32_t ifaceid;
        uint64_t timestamp;
        pcapng_interface_t *interface;
        uint16_t optcode, optlen;
        char *optval;
        char *bodyptr;

        err = wandio_read(libtrace->io, packet->buffer, sizeof(pcapng_stats_t));

        if (err < 0) {
                trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED, "reading pcapng interface stats");
                return -1;
        }

        if (err == 0) {
                return 0;
        }

        if (err < (int)sizeof(pcapng_stats_t)) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Incomplete pcapng interface stats header");
                return -1;
        }

        hdr = (pcapng_stats_t *)packet->buffer;

        /* Read the rest of the packet into the buffer */
        if (DATA(libtrace)->byteswapped) {
                assert(byteswap32(hdr->blocktype) == PCAPNG_INTERFACE_STATS_TYPE);
                to_read = byteswap32(hdr->blocklen) - sizeof(pcapng_stats_t);
                ifaceid = byteswap32(hdr->interfaceid);
                timestamp = ((uint64_t)(byteswap32(hdr->timestamp_high)) << 32) + byteswap32(hdr->timestamp_low);
        } else {
                assert(hdr->blocktype == PCAPNG_INTERFACE_STATS_TYPE);
                to_read = hdr->blocklen - sizeof(pcapng_stats_t);
                ifaceid = hdr->interfaceid;
                timestamp = ((uint64_t)(hdr->timestamp_high) << 32) +
                                hdr->timestamp_low;
        }

        bodyptr = packet->buffer + sizeof(pcapng_stats_t);
        err = pcapng_read_body(libtrace, bodyptr, to_read);
        if (err <= 0) {
                return err;
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
                return sizeof(pcapng_stats_t) + to_read;
        }

        /* All of the stats are stored as options */
        bodyptr = packet->payload;

        do {
                optval = pcapng_parse_next_option(packet->trace, &bodyptr,
                                &optcode, &optlen);
                if (optval == NULL) {
                        trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Failed to read options for pcapng enhanced packet");
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

        return sizeof(pcapng_stats_t) + to_read;

}

static int pcapng_read_simple(libtrace_t *libtrace, libtrace_packet_t *packet,
                uint32_t flags) {

        int err;
        uint32_t to_read;
        uint32_t caplen;
        pcapng_spkt_t *hdr = NULL;
        pcapng_interface_t *interface;
        char *bodyptr;

        err = wandio_read(libtrace->io, packet->buffer, sizeof(pcapng_spkt_t));

        if (err < 0) {
                trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED, "reading pcapng simple packet");
                return -1;
        }

        if (err == 0) {
                return 0;
        }

        if (err < (int)sizeof(pcapng_spkt_t)) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Incomplete pcapng simple packet header");
                return -1;
        }

        hdr = (pcapng_spkt_t *)packet->buffer;

        /* Read the rest of the packet into the buffer */
        if (DATA(libtrace)->byteswapped) {
                assert(byteswap32(hdr->blocktype) == PCAPNG_SIMPLE_PACKET_TYPE);
                to_read = byteswap32(hdr->blocklen) - sizeof(pcapng_spkt_t);
                caplen = to_read - 4;   /* account for trailing length field */
        } else {
                assert(hdr->blocktype == PCAPNG_SIMPLE_PACKET_TYPE);
                to_read = hdr->blocklen - sizeof(pcapng_spkt_t);
                caplen = to_read - 4; /* account for trailing length field */
        }

        bodyptr = packet->buffer + sizeof(pcapng_spkt_t);
        err = pcapng_read_body(libtrace, bodyptr, to_read);
        if (err <= 0) {
                return err;
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
        packet->capture_length = caplen;

        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }
        return sizeof(pcapng_spkt_t) + to_read;

}

static int pcapng_read_enhanced(libtrace_t *libtrace, libtrace_packet_t *packet,
                uint32_t flags) {
        pcapng_epkt_t *hdr = NULL;
        int err;
        uint32_t to_read;
        uint32_t caplen;
        uint32_t ifaceid;
        pcapng_interface_t *interface;
        uint16_t optcode, optlen;
        char *optval;
        char *bodyptr;

        err = wandio_read(libtrace->io, packet->buffer, sizeof(pcapng_epkt_t));

        if (err < 0) {
                trace_set_err(libtrace, TRACE_ERR_WANDIO_FAILED, "reading pcapng enhanced packet");
                return -1;
        }

        if (err == 0) {
                return 0;
        }

        if (err < (int)sizeof(pcapng_epkt_t)) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                                "Incomplete pcapng enhanced packet header");
                return -1;
        }

        hdr = (pcapng_epkt_t *)packet->buffer;

        /* Read the rest of the packet into the buffer */
        if (DATA(libtrace)->byteswapped) {
                assert(byteswap32(hdr->blocktype) == PCAPNG_ENHANCED_PACKET_TYPE);
                caplen = byteswap32(hdr->caplen);
                to_read = byteswap32(hdr->blocklen) - sizeof(pcapng_epkt_t);
                ifaceid = byteswap32(hdr->interfaceid);
        } else {
                assert(hdr->blocktype == PCAPNG_ENHANCED_PACKET_TYPE);
                caplen = hdr->caplen;
                to_read = hdr->blocklen - sizeof(pcapng_epkt_t);
                ifaceid = hdr->interfaceid;
        }

        bodyptr = packet->buffer + sizeof(pcapng_epkt_t);
        err = pcapng_read_body(libtrace, bodyptr, to_read);
        if (err <= 0) {
                return err;
        }

        /* Set packet type based on interface linktype */
        interface = lookup_interface(libtrace, ifaceid);
        if (interface == NULL) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Unknown pcapng interface id: %u", ifaceid);
                return -1;
        }
        packet->type = pcapng_linktype_to_rt(interface->linktype);

        /* May as well cache the capture length now, since we've
         * already got it in the right byte order */
        packet->capture_length = caplen;

        if (pcapng_prepare_packet(libtrace, packet, packet->buffer,
                        packet->type, flags)) {
                return -1;
        }

        /* Make sure to parse any useful options */
        if ((caplen % 4) == 0) {
                bodyptr = packet->payload + caplen;
        } else {
                bodyptr = packet->payload + caplen + (4 - (caplen % 4));
        }

        do {
                optval = pcapng_parse_next_option(packet->trace, &bodyptr,
                                &optcode, &optlen);
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
        return sizeof(pcapng_epkt_t) + to_read;

}

static int pcapng_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet)
{
        struct pcapng_peeker peeker;
        int err = 0;
        uint32_t flags = 0;
        uint32_t to_read;
        uint32_t btype = 0;
        int gotpacket = 0;

        /* Peek to get next block type */
        assert(libtrace->format_data);
        assert(libtrace->io);

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

                if (DATA(libtrace)->byteswapped) {
                        btype = byteswap32(peeker.blocktype);
                } else {
                        btype = peeker.blocktype;
                }

                switch (btype) {
                        /* Section Header */
                        case PCAPNG_SECTION_TYPE:
                                err = pcapng_read_section(libtrace, packet, flags);
                                gotpacket = 1;
                                break;

                        /* Interface Header */
                        case PCAPNG_INTERFACE_TYPE:
                                err = pcapng_read_interface(libtrace, packet, flags);
                                gotpacket = 1;
                                break;


                        case PCAPNG_ENHANCED_PACKET_TYPE:
                                err = pcapng_read_enhanced(libtrace, packet,
                                                flags);
                                gotpacket = 1;
                                break;

                        case PCAPNG_SIMPLE_PACKET_TYPE:
                                err = pcapng_read_simple(libtrace, packet, flags);
                                gotpacket = 1;
                                break;

                        case PCAPNG_INTERFACE_STATS_TYPE:
                                err = pcapng_read_stats(libtrace, packet, flags);
                                gotpacket = 1;
                                break;

                        case PCAPNG_NAME_RESOLUTION_TYPE:
                                err = pcapng_read_nrb(libtrace, packet, flags);
                                gotpacket = 1;
                                break;

                        case PCAPNG_CUSTOM_TYPE:
                        case PCAPNG_CUSTOM_NONCOPY_TYPE:
                                err = pcapng_read_custom(libtrace, packet, flags);
                                gotpacket = 1;
                                break;


                        case PCAPNG_OLD_PACKET_TYPE:
                                /* TODO */

                        /* Everything else -- don't care, skip it */
                        default:
                                if (DATA(libtrace)->byteswapped) {
                                        to_read = byteswap32(peeker.blocklen);
                                } else {
                                        to_read = peeker.blocklen;
                                }
                                err = skip_block(libtrace, to_read);
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

static libtrace_linktype_t pcapng_get_link_type(const libtrace_packet_t *packet)
{

        return pcap_linktype_to_libtrace(rt_to_pcap_linktype(packet->type));

}

static libtrace_direction_t pcapng_get_direction(const libtrace_packet_t
                *packet) {

        /* Defined in format_helper.c */
        return pcap_get_direction(packet);
}

static struct timespec pcapng_get_timespec(const libtrace_packet_t *packet) {

        struct timespec ts;
        uint64_t timestamp = 0;
        uint32_t interfaceid = 0;
        pcapng_interface_t *interface;

        assert(packet->header);

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
        ts.tv_nsec = (uint64_t)(timestamp - (ts.tv_sec * interface->tsresol)) / interface->tsresol * 1000000000;

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
        packet->capture_length = -1;
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
        NULL,                           /* init_output */
        NULL,                           /* config_output */
        NULL,                           /* start_output */
        pcapng_fin_input,               /* fin_input */
        NULL,                           /* fin_output */
        pcapng_read_packet,             /* read_packet */
        pcapng_prepare_packet,          /* prepare_packet */
        NULL,                           /* fin_packet */
        NULL,                           /* write_packet */
        pcapng_get_link_type,           /* get_link_type */
        pcapng_get_direction,           /* get_direction */
        NULL,                           /* set_direction */
        NULL,                           /* get_erf_timestamp */
        NULL,                           /* get_timeval */
        pcapng_get_timespec,            /* get_timespec */
        NULL,                           /* get_seconds */
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

