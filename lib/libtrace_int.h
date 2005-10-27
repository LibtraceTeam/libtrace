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

#ifndef LIBTRACE_INT_H
#define LIBTRACE_INT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"
#include "config.h"
#include "libtrace.h"
#include "fifo.h"

#if HAVE_PCAP_BPF_H
#  include <pcap-bpf.h>
#else
#  ifdef HAVE_NET_BPF_H
#    include <net/bpf.h>
#  endif
#endif

#if HAVE_PCAP_H
#  include <pcap.h>
#  ifdef HAVE_PCAP_INT_H
#    include <pcap-int.h>
#  endif
#endif 

#ifdef HAVE_ZLIB_H
#  include <zlib.h>
#endif


#include "wag.h"

#ifdef HAVE_DAG_API
#  include "dagnew.h"
#  include "dagapi.h"
#else
#  include "dagformat.h"
#endif
#include "daglegacy.h"

typedef enum {SOCKET, TRACE, STDIN, DEVICE, INTERFACE, RT } source_t;


extern struct trace_err_t{
	int err_num; 	// error code
	char problem[255];	// the format, uri etc that caused the error for reporting purposes
} trace_err;


#define RP_BUFSIZE 65536

struct libtrace_format_data_t;

struct libtrace_event_t {
	struct {
		void *buffer;
		int size;
	} packet;
	double tdelta;
	double trace_last_ts;
};

/** The information about traces that are open 
 * @internal
 */
struct libtrace_t {
	struct libtrace_format_t *format; /**< format driver pointer */
	struct libtrace_format_data_t *format_data; /**<format data pointer */
        source_t sourcetype;	/**< The type (device,file, etc */

	struct libtrace_event_t event;
	char *uridata;
	struct tracefifo_t *fifo;   

};

struct libtrace_out_t {
        struct libtrace_format_t *format;
	struct libtrace_format_data_out_t *format_data;

	char *uridata;
        struct tracefifo_t *fifo;
};


struct trace_sll_header_t {
	uint16_t pkttype;          	/* packet type */
	uint16_t hatype;           	/* link-layer address type */
	uint16_t halen;            	/* link-layer address length */
	char addr[8];	 		/* link-layer address */
	uint16_t protocol;         	/* protocol */
};

#ifndef PF_RULESET_NAME_SIZE
#define PF_RULESET_NAME_SIZE 16
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

struct trace_pflog_header_t {
	uint8_t	   length;
	sa_family_t   af;
	uint8_t	   action;
	uint8_t	   reason;
	char 	   ifname[IFNAMSIZ];
	char 	   ruleset[PF_RULESET_NAME_SIZE];
	uint32_t   rulenr;
	uint32_t   subrulenr;
	uint8_t	   dir;
	uint8_t	   pad[3];
};

struct libtrace_format_t {
	char *name;
	char *version;
	char *type;
	int (*init_input)(struct libtrace_t *libtrace);
	int (*init_output)(struct libtrace_out_t *libtrace);
	int (*config_output)(struct libtrace_out_t *libtrace, int argc, char *argv[]);
	int (*fin_input)(struct libtrace_t *libtrace);
	int (*fin_output)(struct libtrace_out_t *libtrace);
	int (*read_packet)(struct libtrace_t *libtrace, struct libtrace_packet_t *packet);
	int (*write_packet)(struct libtrace_out_t *libtrace, const struct libtrace_packet_t *packet);
	void* (*get_link)(const struct libtrace_packet_t *packet);
	libtrace_linktype_t (*get_link_type)(const struct libtrace_packet_t *packet);
	int8_t (*get_direction)(const struct libtrace_packet_t *packet);
	int8_t (*set_direction)(const struct libtrace_packet_t *packet, int8_t direction);
	uint64_t (*get_erf_timestamp)(const struct libtrace_packet_t *packet);
	struct timeval (*get_timeval)(const struct libtrace_packet_t *packet);
	double (*get_seconds)(const struct libtrace_packet_t *packet);
	int (*get_capture_length)(const struct libtrace_packet_t *packet);
	int (*get_wire_length)(const struct libtrace_packet_t *packet);
	int (*get_framing_length)(const struct libtrace_packet_t *packet);
	size_t (*set_capture_length)(struct libtrace_packet_t *packet,size_t size);
	int (*get_fd)(const struct libtrace_packet_t *packet);
	struct libtrace_eventobj_t (*trace_event)(struct libtrace_t *trace, struct libtrace_packet_t *packet);	
	void (*help)();
};

extern struct libtrace_format_t *form;

void register_format(struct libtrace_format_t *format);
	
#ifdef __cplusplus
}
#endif

#endif // LIBTRACE_INT_H
