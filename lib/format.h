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

#ifndef FORMAT_H
#define FORMAT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"
#include "config.h"
#include "libtrace.h"
#include "fifo.h"
#include "rtserver.h"

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

typedef enum {SOCKET, TRACE, STDIN, DEVICE, INTERFACE, RT } source_t;

#define RP_BUFSIZE 65536

/** The information about traces that are open 
 * @internal
 */
struct libtrace_t {
	struct format_t *format; /**< format driver pointer */
        source_t sourcetype;	/**< The type (device,file, etc */

        union {
		/** Information about rtclients */
                struct {
                        char *hostname;
                        short port;
                } rt;
                char *path;		/**< information for local sockets */
                char *interface;	/**< intormation for reading of network
					     interfaces */
        } conn_info;
	/** Information about the current state of the input device */
        union {
                int fd;
#if HAVE_ZLIB
                gzFile *file;
#else	
		FILE *file;
#endif
#if HAVE_PCAP 
                pcap_t *pcap;
#endif 
        } input;

	struct fifo_t *fifo;   
	struct {
		void *buf; 
		unsigned bottom;
		unsigned top;
		unsigned diff;
		unsigned curr;
		unsigned offset;
	} dag;
	struct {
		void *buffer;
		int size;
	} packet;
	double tdelta;
	double trace_start_ts;
	double real_start_ts;
	double trace_last_ts;

	double last_ts;
	double start_ts;
};

struct libtrace_out_t {
        struct format_t * format;

	char *uridata;
        union {
                struct {
                        char *hostname;
                        short port;
                } rt;
                char *path;
                char *interface;
        } conn_info;

	union {
		struct {
			int level;
		} erf;
		
	} options;
	
        union {
                int fd;
                struct rtserver_t * rtserver;
#if HAVE_ZLIB
                gzFile *file;
#else
                FILE *file;
#endif
#if HAVE_PCAP
                pcap_t *pcap;
#endif
        } output;

        struct fifo_t *fifo;


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

struct format_t {
	char *name;
	char *version;
	int (*init_input)(struct libtrace_t *libtrace);
	int (*init_output)(struct libtrace_out_t *libtrace);
	int (*config_output)(struct libtrace_out_t *libtrace, int argc, char *argv[]);
	int (*fin_input)(struct libtrace_t *libtrace);
	int (*fin_output)(struct libtrace_out_t *libtrace);
	int (*read)(struct libtrace_t *libtrace, void *buffer, size_t len);
	int (*read_packet)(struct libtrace_t *libtrace, struct libtrace_packet_t *packet);
	int (*write_packet)(struct libtrace_out_t *libtrace, struct libtrace_packet_t *packet);
	void* (*get_link)(const struct libtrace_packet_t *packet);
	libtrace_linktype_t (*get_link_type)(const struct libtrace_packet_t *packet);
	int8_t (*get_direction)(const struct libtrace_packet_t *packet);
	int8_t (*set_direction)(const struct libtrace_packet_t *packet, int8_t direction);
	uint64_t (*get_erf_timestamp)(const struct libtrace_packet_t *packet);
	struct timeval (*get_timeval)(const struct libtrace_packet_t *packet);
	double (*get_seconds)(const struct libtrace_packet_t *packet);
	int (*get_capture_length)(const struct libtrace_packet_t *packet);
	int (*get_wire_length)(const struct libtrace_packet_t *packet);
	size_t (*truncate_packet)(const struct libtrace_packet_t *packet,size_t size);
};

extern struct format_t *form;

void register_format(struct format_t *format);
	
#ifdef __cplusplus
}
#endif

#endif // FORMAT_H
