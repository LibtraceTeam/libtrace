/*
 *
 * Copyright (c) 2023, Shane Alcock.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * Libtrace was originally developed by the University of Waikato WAND
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
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "format_etsi.h"

#include <libwandder.h>
#include <libwandder_etsili.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#define DATAOUT(x) ((struct etsifile_format_data_out_t *)x->format_data)
#define OUTPUT DATAOUT(libtrace)

#define DATA(x) ((struct etsifile_format_data_t *)x->format_data)
#define INPUT DATA(libtrace)

struct etsifile_format_data_out_t {
    iow_t *file;
    int compress_type;
    int level;
    int flag;
};

struct etsifile_format_data_t {
    int real_time_eventapi;
    wandder_etsispec_t *decoder;
};

static int etsifile_init_input(libtrace_t *libtrace)
{
    libtrace->format_data = calloc(1, sizeof(struct etsifile_format_data_t));
    if (libtrace->format_data == NULL) {
        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
                      "Unable to allocate memory for format"
                      "data inside etsifile_init_input()");
        return -1;
    }

    INPUT->real_time_eventapi = 0;
    INPUT->decoder = wandder_create_etsili_decoder();
    return 0;
}

static int etsifile_config_input(libtrace_t *libtrace, trace_option_t option,
                                 void *value)
{

    switch (option) {
    case TRACE_OPTION_EVENT_REALTIME:
        INPUT->real_time_eventapi = *(int *)value;
        return 0;

    case TRACE_OPTION_CONSTANT_ERF_FRAMING:
    case TRACE_OPTION_SNAPLEN:
    case TRACE_OPTION_PROMISC:
    case TRACE_OPTION_FILTER:
    case TRACE_OPTION_META_FREQ:
    case TRACE_OPTION_DISCARD_META:
        trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL, "Unsupported option");
        return -1;
    default:
        /* Unknown option */
        trace_set_err(libtrace, TRACE_ERR_UNKNOWN_OPTION, "Unknown option");
        return -1;
    }
}

static int etsifile_start_input(libtrace_t *libtrace)
{
    if (libtrace->io) {
        return 0;
    }
    libtrace->io = trace_open_file(libtrace);
    if (!libtrace->io) {
        return -1;
    }
    return 0;
}

static int etsifile_prepare_received(libtrace_t *libtrace,
                                     libtrace_packet_t *packet, int length)
{

    struct timeval tv;

    packet->trace = libtrace;
    packet->payload = packet->buffer;
    packet->header = NULL;
    packet->type = TRACE_RT_DATA_ETSILI;
    packet->cached.link_type = TRACE_TYPE_ETSILI;

    wandder_attach_etsili_buffer(INPUT->decoder, packet->buffer, length, false);
    packet->cached.wire_length = wandder_etsili_get_pdu_length(INPUT->decoder);
    packet->cached.capture_length = packet->cached.wire_length;
    packet->error = packet->cached.capture_length;
    packet->fmtdata = NULL;

    tv = wandder_etsili_get_header_timestamp(INPUT->decoder);
    if (tv.tv_sec != 0) {
        packet->order = ((((uint64_t)tv.tv_sec) << 32) +
                         (((uint64_t)tv.tv_usec << 32) / 1000000));
    } else {
        packet->order = 0;
    }

    return length;
}

static int etsifile_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet)
{

    char *resume = NULL;
    uint8_t *ptr;
    int numbytes, toread, i;
    uint64_t length = 0;

    if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
        packet->buffer = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
        if (!packet->buffer) {
            trace_set_err(libtrace, TRACE_ERR_OUT_OF_MEMORY,
                          "OOM while allocating space for "
                          "etsifile packet");
            return -1;
        }
        packet->buf_control = TRACE_CTRL_PACKET;
    }

    memset(packet->buffer, 0, 16);
    numbytes = wandio_read(libtrace->io, packet->buffer, 16);
    if (numbytes < 0) {
        trace_set_err(libtrace, errno, "reading from etsifile");
        return -1;
    }

    if (numbytes == 0) {
        /* EOF */
        return 0;
    }

    resume = packet->buffer + numbytes;

    ptr = (uint8_t *)(packet->buffer);
    /* Try to decode enough to get the top level length */
    if (*ptr != 0x30) {
        trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                      "content from etsifile does not appear to be "
                      "an ETSI LI formatted packet?");
        return -1;
    }

    ptr += 1;
    if ((*ptr & 0x80) == 0) {
        /* length is encoded in short form */
        /* +1 for identifier, +1 for single byte length field */
        length = ((*ptr & 0x7f) + 2);
    } else {
        uint8_t lenoctets = (*ptr & 0x7f);
        if (lenoctets >= 8) {
            trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                          "bogus length field size in ETSI LI packet");
            return -1;
        }
        length = 0;
        ptr++;

        for (i = 0; i < (int)lenoctets; i++) {
            length = length << 8;
            length |= (*ptr);
            ptr++;
        }
        length += (lenoctets + 2);
    }

    if (length >= LIBTRACE_PACKET_BUFSIZE) {
        trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                      "Packet size %lu larger than supported by libtrace -- "
                      "packet is probably corrupt",
                      length);
        return -1;
    }

    if (length <= 16) {
        trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                      "Packet size %lu is too short to be a complete ETSI LI "
                      "record -- packet is probably corrupt",
                      length);
        return -1;
    }

    toread = length - numbytes;
    numbytes = wandio_read(libtrace->io, resume, toread);
    if (numbytes < 0) {
        trace_set_err(libtrace, errno, "read(%s)", libtrace->uridata);
        return -1;
    }

    if (numbytes < toread) {
        trace_set_err(libtrace, EIO, "truncated packet (wanted %d, got %d",
                      toread, numbytes);
        return -1;
    }

    return etsifile_prepare_received(libtrace, packet, length);
}

static int etsifile_prepare_packet(libtrace_t *libtrace UNUSED,
                                   libtrace_packet_t *packet UNUSED,
                                   void *buffer UNUSED,
                                   libtrace_rt_types_t rt_type UNUSED,
                                   uint32_t flags UNUSED)
{

    return 0;
}

static int etsifile_fin_input(libtrace_t *libtrace)
{
    if (libtrace->io) {
        wandio_destroy(libtrace->io);
    }
    if (INPUT->decoder) {
        wandder_free_etsili_decoder(INPUT->decoder);
    }
    free(libtrace->format_data);
    return 0;
}

static int etsifile_init_output(libtrace_out_t *libtrace)
{
    libtrace->format_data = malloc(sizeof(struct etsifile_format_data_out_t));

    if (libtrace->format_data == NULL) {
        trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED,
                          "Unable to allocate memory for format"
                          "data inside etsifile_init_output()");
        return -1;
    }

    OUTPUT->file = NULL;
    OUTPUT->compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
    OUTPUT->flag = O_CREAT | O_WRONLY;
    OUTPUT->level = 0;
    return 0;
}

static int etsifile_config_output(libtrace_out_t *libtrace,
                                  trace_option_output_t option, void *value)
{

    switch (option) {
    case TRACE_OPTION_OUTPUT_COMPRESS:
        OUTPUT->level = *(int *)value;
        return 0;
    case TRACE_OPTION_OUTPUT_COMPRESSTYPE:
        OUTPUT->compress_type = *(int *)value;
        return 0;
    case TRACE_OPTION_OUTPUT_FILEFLAGS:
        OUTPUT->flag = *(int *)value;
        return 0;
    default:
        /* Unknown option */
        trace_set_err_out(libtrace, TRACE_ERR_UNKNOWN_OPTION, "Unknown option");
        return -1;
    }
}

static int etsifile_flush_output(libtrace_out_t *libtrace)
{
    if (OUTPUT->file) {
        return wandio_wflush(OUTPUT->file);
    }
    return 0;
}

static int etsifile_fin_output(libtrace_out_t *libtrace)
{
    if (OUTPUT->file) {
        wandio_wdestroy(OUTPUT->file);
    }
    free(libtrace->format_data);
    return 0;
}

static int etsifile_start_output(libtrace_out_t *libtrace)
{
    if (OUTPUT->file) {
        trace_set_err_out(libtrace, TRACE_ERR_OUTPUT_FILE,
                          "trace_start_output() called on a trace that "
                          "has already been started");
        return -1;
    }

    OUTPUT->file = trace_open_file_out(libtrace, OUTPUT->compress_type,
                                       OUTPUT->level, OUTPUT->flag);
    if (!OUTPUT->file) {
        trace_set_err_out(libtrace, TRACE_ERR_OUT_OF_MEMORY,
                          "Unable to open output file handle");
        return -1;
    }
    return 0;
}

static int etsifile_write_packet(libtrace_out_t *libtrace,
                                 libtrace_packet_t *packet)
{

    int written;
    int towrite;

    if (trace_get_link_type(packet) != TRACE_TYPE_ETSILI) {
        trace_set_err_out(libtrace, TRACE_ERR_NO_CONVERSION,
                          "etsifile output only works for packets read "
                          " using etsifile: or etsifile: input sources");
        return -1;
    }

    if (packet->buffer == NULL) {
        trace_set_err_out(libtrace, TRACE_ERR_BAD_PACKET,
                          "no content in packet buffer to write");
        return -1;
    }

    towrite = trace_get_capture_length(packet);
    if (towrite <= 0) {
        trace_set_err_out(libtrace, TRACE_ERR_BAD_PACKET,
                          "capture length for packet is invalid");
        return -1;
    }

    written = wandio_wwrite(OUTPUT->file, packet->buffer,
                            trace_get_capture_length(packet));
    if (written != towrite) {
        trace_set_err_out(libtrace, errno, "write(%s)", libtrace->uridata);
        return -1;
    }
    return written;
}

static void etsifile_help(void)
{
    printf("etsifile format module: \n");
    printf("Supported input URIs:\n");
    printf("\tetsifile:/path/to/file\n");
    printf("\tetsifile:/path/to/file.gz\n");
    printf("\n");
    printf("\te.g.: etsifile:/tmp/etsitrace.pcap\n");
    printf("\te.g.: etsifile:/tmp/etsitrace.pcap.gz\n");
    printf("\n");
}

static struct libtrace_format_t etsifile = {
    "etsifile",
    "$Id$",
    TRACE_FORMAT_ETSILIVE,
    NULL,                        /* probe filename */
    NULL,                        /* probe magic */
    etsifile_init_input,         /* init_input */
    etsifile_config_input,       /* config_input */
    etsifile_start_input,        /* start_input */
    NULL,                        /* pause */
    etsifile_init_output,        /* init_output */
    etsifile_config_output,      /* config_output */
    etsifile_start_output,       /* start_output */
    etsifile_fin_input,          /* fin_input */
    etsifile_fin_output,         /* fin_output */
    etsifile_read_packet,        /* read_packet */
    etsifile_prepare_packet,     /* prepare_packet */
    NULL,                        /* fin_packet */
    NULL,                        /* can_hold_packet */
    etsifile_write_packet,       /* write_packet */
    etsifile_flush_output,       /* flush_output */
    etsilive_get_link_type,      /* get_link_type */
    NULL,                        /* get_direction */
    NULL,                        /* set_direction */
    etsilive_get_erf_timestamp,  /* get_erf_timestamp */
    NULL,                        /* get_timeval */
    NULL,                        /* get_timespec */
    NULL,                        /* get_seconds */
    NULL,                        /* get_meta_section */
    NULL,                        /* seek_erf */
    NULL,                        /* seek_timeval */
    NULL,                        /* seek_seconds */
    etsilive_get_pdu_length,     /* get_capture_length */
    etsilive_get_pdu_length,     /* get_wire_length */
    etsilive_get_framing_length, /* get_framing_length */
    NULL,                        /* set_capture_length */
    NULL,                        /* get_received_packets */
    NULL,                        /* get_filtered_packets */
    NULL,                        /* get_dropped_packets */
    NULL,                        /* get_statistics */
    NULL,                        /* get_fd */
    NULL,                        /* trace_event */
	etsifile_help,                        /* help */
    NULL,                        /* next pointer */
    NON_PARALLEL(true)           /* no parallel support */
};

void etsifile_constructor(void) { register_format(&etsifile); }
