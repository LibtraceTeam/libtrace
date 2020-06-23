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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_PCAP_H
#  include <pcap.h>
#endif

/* This format module deals with traces captured using the PCAP library. This
 * format module handles both captures from a live interface and from PCAP
 * files.
 *
 * However, the PCAP file support featured in this code is superceded by our 
 * own implementation of the PCAP file format, called pcapfile. See 
 * format_pcapfile.c for more information.
 *
 * Both the live and trace formats support writing, provided your PCAP library
 * also supports it.
 *
 */

/* Formats implemented in this module:
 * 	pcap - deals with PCAP trace files
 * 	pcapint - deals with live PCAP interfaces
 */

#ifdef HAVE_LIBPCAP
static struct libtrace_format_t pcap;
static struct libtrace_format_t pcapint;

#define DATA(x) ((struct pcap_format_data_t*)((x)->format_data))
#define DATAOUT(x) ((struct pcap_format_data_out_t*)((x)->format_data))

#define INPUT DATA(libtrace)->input
#define OUTPUT DATAOUT(libtrace)->output
struct pcap_format_data_t {
	/** Information about the current state of the input trace */
        union {
                /* The PCAP input source */
		pcap_t *pcap;
        } input;
	/* A filter to be applied to all packets read from the source */
	libtrace_filter_t *filter;
	/* The snap length to be applied to all captured packets (live only) */
	int snaplen;
	/* Whether the capture interface should be set to promiscuous mode
	 * (live only) */
	int promisc;
};

struct pcap_format_data_out_t {
	/* Information about the current state of the output trace */
	union {
		struct {
			/* The PCAP output device or trace */
			pcap_t *pcap;	
			/* The PCAP dumper */
			pcap_dumper_t *dump;
		} trace;

	} output;
};

static bool pcap_can_write(libtrace_packet_t *packet) {
	/* Get the linktype */
        libtrace_linktype_t ltype = trace_get_link_type(packet);

        if (ltype == TRACE_TYPE_PCAPNG_META
                || ltype == TRACE_TYPE_CONTENT_INVALID
                || ltype == TRACE_TYPE_UNKNOWN
                || ltype == TRACE_TYPE_ERF_META
                || ltype == TRACE_TYPE_NONDATA) {

                return false;
        }

        return true;
}

static int pcap_init_input(libtrace_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct pcap_format_data_t));

	if (!libtrace->format_data) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable to allocate memory for "
			"format data inside pcap_init_input()");
		return -1;
	}

	INPUT.pcap = NULL;
	DATA(libtrace)->filter = NULL;
	DATA(libtrace)->snaplen = LIBTRACE_PACKET_BUFSIZE;
	DATA(libtrace)->promisc = 0;

	return 0;
}

static int pcap_start_input(libtrace_t *libtrace) {
	char errbuf[PCAP_ERRBUF_SIZE];


	/* Check if the file is already open */
	if (INPUT.pcap)
		return 0; /* success */

	/* Open the trace file for reading */
	if ((INPUT.pcap = 
		pcap_open_offline(libtrace->uridata,
			errbuf)) == NULL) {
		trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",
				errbuf);
		return -1;
	}

	/* If a filter has been configured, compile and apply it */
#ifdef HAVE_BPF
	if (DATA(libtrace)->filter) {
		if (DATA(libtrace)->filter->flag == 0) {
			pcap_compile(INPUT.pcap, 
					&DATA(libtrace)->filter->filter,
					DATA(libtrace)->filter->filterstring, 
					1, 0);
			DATA(libtrace)->filter->flag = 1;
		}
		if (pcap_setfilter(INPUT.pcap,&DATA(libtrace)->filter->filter) 
				== -1) {
			trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",
					pcap_geterr(INPUT.pcap));
			return -1;
		}
	}
#endif
	return 0;
}

static int pcap_config_input(libtrace_t *libtrace,
		trace_option_t option,
		void *data)
{
	switch(option) {
		case TRACE_OPTION_FILTER:
#ifdef HAVE_BPF
			DATA(libtrace)->filter=data;
			return 0;
#else
			return -1;
#endif
		case TRACE_OPTION_SNAPLEN:
			/* Snapping isn't supported directly, so fall thru
			 * and let libtrace deal with it
			 */
		case TRACE_OPTION_PROMISC:
			/* Can't do promisc on a trace! */
		case TRACE_OPTION_META_FREQ:
			/* No meta data for this format */
		case TRACE_OPTION_EVENT_REALTIME:
			/* We do not support this option for PCAP traces */
		default:
			return -1;
	}
	return -1;
}

static int pcap_init_output(libtrace_out_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct pcap_format_data_out_t));
	if (!libtrace->format_data) {
		trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "Unable to allocate memory for "
			"format data inside pcap_init_output()");
		return -1;
	}

	OUTPUT.trace.pcap = NULL;
	OUTPUT.trace.dump = NULL;
	return 0;
}

static int pcapint_init_output(libtrace_out_t *libtrace) {
#ifdef HAVE_PCAP_INJECT
	libtrace->format_data = malloc(sizeof(struct pcap_format_data_out_t));
	if (!libtrace->format_data) {
                trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "Unable to allocate memory for "
			"format data inside pcapint_init_output()");
                return -1;
        }

	OUTPUT.trace.pcap = NULL;
	OUTPUT.trace.dump = NULL;
	return 0;
#else
#ifdef HAVE_PCAP_SENDPACKET
	libtrace->format_data = malloc(sizeof(struct pcap_format_data_out_t));
	OUTPUT.trace.pcap = NULL;
	OUTPUT.trace.dump = NULL;
	return 0;
#else
	trace_set_err_out(libtrace,TRACE_ERR_UNSUPPORTED,
			"writing not supported by this version of pcap");
	return -1;
#endif
#endif
}

static int pcapint_init_input(libtrace_t *libtrace) {
	libtrace->format_data = malloc(sizeof(struct pcap_format_data_t));
	if (!libtrace->format_data) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable to allocate memory for "
			"format data inside pcapint_init_input()");
		return -1;
	}

	DATA(libtrace)->filter = NULL;
	DATA(libtrace)->snaplen = LIBTRACE_PACKET_BUFSIZE;
	DATA(libtrace)->promisc = 0;
	return 0; /* success */
}

static int pcapint_config_input(libtrace_t *libtrace,
		trace_option_t option,
		void *data)
{
	switch(option) {
		case TRACE_OPTION_FILTER:
#ifdef HAVE_BPF
			DATA(libtrace)->filter=(libtrace_filter_t*)data;
			return 0;
#else
			return -1;
#endif
		case TRACE_OPTION_SNAPLEN:
			DATA(libtrace)->snaplen=*(int*)data;
			return 0;
		case TRACE_OPTION_PROMISC:
			DATA(libtrace)->promisc=*(int*)data;
			return 0;
		case TRACE_OPTION_META_FREQ:
			/* No meta-data for this format */
		case TRACE_OPTION_EVENT_REALTIME:
			/* live interface is always real-time! */
		default:
			/* Don't set an error here - trace_config will try
			 * to handle the option when we return. If it can't
			 * deal with it, then it will do the necessary
			 * error-setting. */
			return -1;
	}
	return -1;
}

static int pcapint_start_input(libtrace_t *libtrace) {
	char errbuf[PCAP_ERRBUF_SIZE];

#ifdef HAVE_PCAP_CREATE
	int ret = 0;
	
	if ((INPUT.pcap = pcap_create(libtrace->uridata, errbuf)) == NULL) {
		trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",errbuf);
		return -1; /* failure */
	}
	if ((pcap_set_snaplen(INPUT.pcap, DATA(libtrace)->snaplen) == 
				PCAP_ERROR_ACTIVATED)) {
		trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",errbuf);
		return -1; /* failure */
	}

	if ((pcap_set_promisc(INPUT.pcap, DATA(libtrace)->promisc) == 
				PCAP_ERROR_ACTIVATED)) {
		trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",errbuf);
		return -1; /* failure */
	}
	
	if ((pcap_set_timeout(INPUT.pcap, 1) == PCAP_ERROR_ACTIVATED)) {
		trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",errbuf);
		return -1; /* failure */
	}

#ifdef HAVE_PCAP_IMMEDIATE
        if ((pcap_set_immediate_mode(INPUT.pcap, 1) == PCAP_ERROR_ACTIVATED)) {
		trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",errbuf);
		return -1; /* failure */
	}
#endif

	if ((ret = pcap_activate(INPUT.pcap)) != 0) {
		if (ret == PCAP_WARNING_PROMISC_NOTSUP) {
			trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,"Promiscuous mode unsupported");
			return -1;
		}
		if (ret == PCAP_WARNING) {
			pcap_perror(INPUT.pcap, "Pcap Warning:");
		} else {
			trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",
					pcap_geterr(INPUT.pcap));
			return -1;
		}
	}
			 
#else	

	/* Open the live device */
	if ((INPUT.pcap = 
			pcap_open_live(libtrace->uridata,
			DATA(libtrace)->snaplen,
			DATA(libtrace)->promisc,
			1,
			errbuf)) == NULL) {
		trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",errbuf);
		return -1; /* failure */
	}
#endif
#ifdef HAVE_PCAP_SETNONBLOCK
	pcap_setnonblock(INPUT.pcap,0,errbuf);
#endif
	/* Set a filter if one is defined */
#ifdef HAVE_BPF
	if (DATA(libtrace)->filter) {
		struct pcap_pkthdr *pcap_hdr = NULL;
		u_char *pcap_payload = NULL;
                int pcapret;
		
                if (DATA(libtrace)->filter->flag == 0) {
			pcap_compile(INPUT.pcap, 
					&DATA(libtrace)->filter->filter,
					DATA(libtrace)->filter->filterstring, 
					1, 0);
			DATA(libtrace)->filter->flag = 1;
		}
                if (pcap_setfilter(INPUT.pcap,&DATA(libtrace)->filter->filter)
			== -1) {
			trace_set_err(libtrace,TRACE_ERR_INIT_FAILED,"%s",
					pcap_geterr(INPUT.pcap));
			return -1; /* failure */
		}

                /* Consume the first packet in the queue, as this may not
                 * have had the filter applied to it.
                 *
                 * Otherwise we can get problems with the event API, where
                 * select tells us that there is a packet available but
                 * calling trace_read_packet will block forever because the
                 * packet in the queue didn't match the filter so
                 * pcap_next_ex returns "timed out".
                 *
                 * This does mean we may consume a legitimate packet, but
                 * that's a pretty small downside compared with trace_event
                 * getting stuck in an infinite loop because of pcap
                 * wackiness. 
                 *
                 * For some reason, we only need to consume one packet for
                 * this to work, so let's hope that holds in the future.
                 */
                do {
        		pcapret = pcap_next_ex(INPUT.pcap, &pcap_hdr, 
				(const u_char **)&pcap_payload);
		} while (0);

                if (pcapret < 0)
                        return -1;
	}
#endif
	return 0; /* success */
}

static int pcap_pause_input(libtrace_t *libtrace UNUSED)
{
	return 0; /* success */
}


static int pcap_fin_input(libtrace_t *libtrace) 
{
	pcap_close(INPUT.pcap);
	INPUT.pcap=NULL;
	free(libtrace->format_data);
	return 0; /* success */
}

static int pcap_fin_output(libtrace_out_t *libtrace) 
{
	if (OUTPUT.trace.dump) {
		pcap_dump_flush(OUTPUT.trace.dump);
		pcap_dump_close(OUTPUT.trace.dump);
	}
	if (OUTPUT.trace.pcap) {
		pcap_close(OUTPUT.trace.pcap);
	}
	free(libtrace->format_data);
	return 0;
}

static int pcapint_fin_output(libtrace_out_t *libtrace)
{
	pcap_close(OUTPUT.trace.pcap);
	free(libtrace->format_data);
	return 0;
}

static int pcap_prepare_packet(libtrace_t *libtrace, libtrace_packet_t *packet,
		void *buffer, libtrace_rt_types_t rt_type, uint32_t flags) {
	
	if (packet->buffer != buffer &&
			packet->buf_control == TRACE_CTRL_PACKET) {
			free(packet->buffer);
	}

	if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER) {
		packet->buf_control = TRACE_CTRL_PACKET;
	} else
		packet->buf_control = TRACE_CTRL_EXTERNAL;
	
	
	packet->buffer = buffer;
	packet->header = buffer;
	packet->type = rt_type;

	/* Assuming header and payload are sequential in the buffer - 
	 * regular pcap often doesn't work like this though, so hopefully
	 * we're not called by something that is reading genuine pcap! */
	packet->payload = (char *)packet->header + sizeof(struct pcap_pkthdr);

	if (libtrace->format_data == NULL) {
		if (pcap_init_input(libtrace))
			return -1;
	}
	return 0;
}

static int pcap_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int ret = 0;
	int linktype;
	uint32_t flags = 0;

	if (!libtrace->format_data) {
		trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, "Trace format data missing, "
			"call trace_create() before calling pcap_read_packet()");
		return -1;
	}
	linktype = pcap_datalink(DATA(libtrace)->input.pcap);
	packet->type = pcap_linktype_to_rt(linktype);

	/* If we're using the replacement pcap_next_ex() we need to
	 * make sure we have a buffer to *shudder* memcpy into 
	 */
	if (!packet->buffer) {
		packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
		if (!packet->buffer) {
			trace_set_err(libtrace, errno, 
					"Cannot allocate memory");
			return -1;
		}
		packet->header = packet->buffer;
		packet->payload = (char *)packet->buffer+sizeof(struct pcap_pkthdr);
			
	}

	flags |= TRACE_PREP_OWN_BUFFER;
	
	for(;;) {
		
		struct pcap_pkthdr *pcap_hdr = NULL;
		u_char *pcap_payload = NULL;

		ret = pcap_next_ex(INPUT.pcap, &pcap_hdr, 
				(const u_char **)&pcap_payload);
		
		packet->header = pcap_hdr;
		packet->payload = pcap_payload;

		switch(ret) {
			case 1: break; /* no error */
			case 0: 
				if ((ret=is_halted(libtrace)) != -1)
					return ret;
                                /* timeout, return and let libtrace check message
                                 * queue.
                                 */
                                return READ_MESSAGE;
			case -1: 
				trace_set_err(libtrace,TRACE_ERR_BAD_PACKET,
						"%s",pcap_geterr(INPUT.pcap));
				return -1; /* Error */
			case -2:
				return 0; /* EOF */
		}

		/*
		 * pcap is nasty in that the header and payload aren't 
		 * necessarily located sequentially in memory, but most
		 * sensible uses of pcap_prepare_packet will involve a
		 * buffer where header and payload are sequential. 
		 *
		 * Basically, don't call pcap_prepare_packet here! 
		 *
		if (pcap_prepare_packet(libtrace, packet, packet->buffer,
				packet->type, flags)) {
			return -1;
		}
		*/
		return ((struct pcap_pkthdr*)packet->header)->len
			+sizeof(struct pcap_pkthdr);
	}
}

static int pcap_write_packet(libtrace_out_t *libtrace, 
		libtrace_packet_t *packet) 
{

	/* Check pcap can write this type of packet */
        if (!pcap_can_write(packet)) {
                return 0;
        }

	if (!libtrace) {
		fprintf(stderr, "NULL trace passed into pcap_write_packet()\n");
		return TRACE_ERR_NULL_TRACE;
	}
	if (!packet) {
		trace_set_err_out(libtrace, TRACE_ERR_NULL_PACKET, "NULL packet passed into pcap_write_packet()\n");
		return -1;
	}

	struct pcap_pkthdr pcap_pkt_hdr;
	void *link;
	libtrace_linktype_t linktype;
	uint32_t remaining;

	link = trace_get_packet_buffer(packet,&linktype,&remaining);

	/* We may have to convert this packet into a suitable PCAP packet */

	/* If this packet cannot be converted to a pcap linktype then
	 * pop off the top header until it can be converted
	 */
	while (libtrace_to_pcap_linktype(linktype)==TRACE_DLT_ERROR) {
		if (!demote_packet(packet)) {
			trace_set_err_out(libtrace, 
				TRACE_ERR_NO_CONVERSION,
				"pcap does not support this format");
			return -1;
		}

		link = trace_get_packet_buffer(packet,&linktype,&remaining);
	}


	if (!OUTPUT.trace.pcap) {
		int linktype=libtrace_to_pcap_dlt(trace_get_link_type(packet));
		OUTPUT.trace.pcap = pcap_open_dead(linktype,65536);
		if (!OUTPUT.trace.pcap) {
			trace_set_err_out(libtrace,TRACE_ERR_INIT_FAILED,
					"Failed to open dead trace: %s\n",
					pcap_geterr(OUTPUT.trace.pcap));
		}
		OUTPUT.trace.dump = pcap_dump_open(OUTPUT.trace.pcap,
				libtrace->uridata);
		if (!OUTPUT.trace.dump) {
			char *errmsg = pcap_geterr(OUTPUT.trace.pcap);
			trace_set_err_out(libtrace,TRACE_ERR_INIT_FAILED,"Failed to open output file: %s\n",
					errmsg ? errmsg : "Unknown error");
			return -1;
		}
	}

	/* Corrupt packet, or other "non data" packet, so skip it */
	if (link == NULL) {
		/* Return "success", but nothing written */
		return 0;
	}

	/* Check if the packet was captured using one of the PCAP formats */
	if (packet->trace->format == &pcap || 
			packet->trace->format == &pcapint) {
		/* Yes - this means we can write it straight out */
		pcap_dump((u_char*)OUTPUT.trace.dump,
				(struct pcap_pkthdr *)packet->header,
				packet->payload);
	} else {
		/* No - need to fill in a PCAP header with the appropriate
		 * values */

		/* Leave the manual copy as it is, as it gets around 
		 * some OS's having different structures in pcap_pkt_hdr
		 */
		struct timeval ts = trace_get_timeval(packet);
		pcap_pkt_hdr.ts.tv_sec = ts.tv_sec;
		pcap_pkt_hdr.ts.tv_usec = ts.tv_usec;
		pcap_pkt_hdr.caplen = remaining;
		/* trace_get_wire_length includes FCS, while pcap doesn't */
		if (trace_get_link_type(packet)==TRACE_TYPE_ETH)
			if (trace_get_wire_length(packet) >= 4) { 
				pcap_pkt_hdr.len = 
					trace_get_wire_length(packet)-4;
			}
			else {
				pcap_pkt_hdr.len = 0;
			}
		else
			pcap_pkt_hdr.len = trace_get_wire_length(packet);

		if (pcap_pkt_hdr.caplen >= 65536) {
			trace_set_err_out(libtrace, TRACE_ERR_BAD_HEADER, "Header capture length is larger than it should be in pcap_write_packet()");
			return -1;
		}
		if (pcap_pkt_hdr.len >= 65536) {
			trace_set_err_out(libtrace, TRACE_ERR_BAD_HEADER, "Header wire length is larger than it should be pcap_write_packet()");
			return -1;
		}

		pcap_dump((u_char*)OUTPUT.trace.dump, &pcap_pkt_hdr, packet->payload);
	}
	return remaining;
}

static int pcap_flush_output(libtrace_out_t *libtrace) {
        return pcap_dump_flush(OUTPUT.trace.dump);
}

static int pcapint_write_packet(libtrace_out_t *libtrace,
		libtrace_packet_t *packet) 
{
	int err;
	libtrace_linktype_t linktype = trace_get_link_type(packet);

	/* Silently discard RT metadata packets and packets with an
	 * unknown linktype. */
	if (linktype == TRACE_TYPE_NONDATA || linktype == TRACE_TYPE_UNKNOWN || linktype == TRACE_TYPE_ERF_META || linktype == TRACE_TYPE_CONTENT_INVALID) {
		return 0;
	}

	if (!OUTPUT.trace.pcap) {
		OUTPUT.trace.pcap = (pcap_t *)pcap_open_live(
			libtrace->uridata,65536,0,0,NULL);
	}
#ifdef HAVE_PCAP_INJECT
	err=pcap_inject(OUTPUT.trace.pcap,
			packet->payload,
			trace_get_capture_length(packet));
	if (err!=(int)trace_get_capture_length(packet))
		err=-1;
#else 
#ifdef HAVE_PCAP_SENDPACKET
	err=pcap_sendpacket(OUTPUT.trace.pcap,
			packet->payload,
			trace_get_capture_length(packet));
#else
    trace_set_err(packet->trace,TRACE_ERR_UNSUPPORTED,"writing is not supported on this platform");
	return -1;
#endif
#endif
	return err;
}

static libtrace_linktype_t pcap_get_link_type(const libtrace_packet_t *packet) {
	/* PCAP doesn't store linktype in the framing header so we need
	 * RT to do it for us 
	 */
	int linktype = rt_to_pcap_linktype(packet->type);
	return pcap_linktype_to_libtrace(linktype);
}

static libtrace_direction_t pcap_set_direction(libtrace_packet_t *packet,
		libtrace_direction_t dir) {

	/* We only support tagging with IN or OUT return error for any others */
	if(!(dir == TRACE_DIR_OUTGOING || dir == TRACE_DIR_INCOMING))
		return -1;

	/* PCAP doesn't have a direction field in the header, so we need to
	 * promote to Linux SLL to tag it properly */
	libtrace_sll_header_t *sll;
	promote_packet(packet);
	sll=packet->payload;
	
	/* sll->pkttype should be in the endianness of the host that the
	 * trace was taken on.  This is impossible to achieve so we assume 
	 * host endianness
	 */
	if(dir==TRACE_DIR_OUTGOING)
		sll->pkttype=TRACE_SLL_OUTGOING;
	else
		sll->pkttype=TRACE_SLL_HOST;
	return dir;
}

static libtrace_direction_t pcapint_get_direction(const libtrace_packet_t *packet) {
        /* This function is defined in format_helper.c */
        return pcap_get_direction(packet);
}


static struct timeval pcap_get_timeval(const libtrace_packet_t *packet) {
	struct pcap_pkthdr *pcapptr = (struct pcap_pkthdr *)packet->header;
	struct timeval ts;
	ts.tv_sec = pcapptr->ts.tv_sec;
	ts.tv_usec = pcapptr->ts.tv_usec;
	return ts;
}


static int pcap_get_capture_length(const libtrace_packet_t *packet) {
	if (!packet) {
		fprintf(stderr, "NULL packet passed into pcapng_get_capture_length()\n");
		return TRACE_ERR_NULL_PACKET;
	}
	struct pcap_pkthdr *pcapptr = 0;
	pcapptr = (struct pcap_pkthdr *)packet->header;
	if (pcapptr->caplen > 65536) {
		trace_set_err(packet->trace, TRACE_ERR_BAD_PACKET, "Capture length is to large, Packet may be corrupt in pcap_get_capture_length()");
		return -1;
	}

	return pcapptr->caplen;
}

static int pcap_get_wire_length(const libtrace_packet_t *packet) {
	struct pcap_pkthdr *pcapptr = 0;
	pcapptr = (struct pcap_pkthdr *)packet->header;
	if (packet->type==pcap_linktype_to_rt(TRACE_DLT_EN10MB))
		return pcapptr->len+4; /* Include the missing FCS */
	else if (packet->type==pcap_linktype_to_rt(TRACE_DLT_IEEE802_11_RADIO)) {
		libtrace_linktype_t linktype;
		void *link = trace_get_packet_buffer(packet,&linktype,NULL);
		/* If the packet is Radiotap and the flags field indicates
		 * that the FCS is not included in the 802.11 frame, then
		 * we need to add 4 to the wire-length to account for it.
		 */
		uint8_t flags;
		trace_get_wireless_flags(link, 
				linktype, &flags);
		if ((flags & TRACE_RADIOTAP_F_FCS) == 0)
			return pcapptr->len + 4;
	}
	return pcapptr->len;
}

static int pcap_get_framing_length(UNUSED const libtrace_packet_t *packet) {
	return sizeof(struct pcap_pkthdr);
}

static size_t pcap_set_capture_length(libtrace_packet_t *packet,size_t size) {
	struct pcap_pkthdr *pcapptr = 0;
	if (!packet) {
		fprintf(stderr, "NULL packet passed to pcap_set_capture_length()\n");
		return TRACE_ERR_NULL_PACKET;
	}
	if (size > trace_get_capture_length(packet)) {
		/* Can't make a packet larger */
		return trace_get_capture_length(packet);
	}
	/* Reset the cached capture length */
	packet->cached.capture_length = -1;
	pcapptr = (struct pcap_pkthdr *)packet->header;
	pcapptr->caplen = size;
	return trace_get_capture_length(packet);
}

static int pcap_get_fd(const libtrace_t *trace) {
	if (!trace) {
		fprintf(stderr, "NULL trace passed to pcap_get_fd()\n");
		return TRACE_ERR_NULL_TRACE;
	}
	if (!trace->format_data) {
		/* cant do this because trace is a const? */
		/*trace_set_err(trace, TRACE_ERR_BAD_FORMAT, "Trace format data missing, call init_input() before calling pcap_get_fd()");*/
		fprintf(stderr, "Trace format data missing, call init_input() before calling pcap_get_fd()\n");
		return TRACE_ERR_BAD_FORMAT;
	}
	return pcap_fileno(DATA(trace)->input.pcap);
}

static void pcap_get_statistics(libtrace_t *trace, libtrace_stat_t *stat) {

	struct pcap_stat pcapstats;
	if (pcap_stats(DATA(trace)->input.pcap,&pcapstats)==-1) {
		char *errmsg = pcap_geterr(DATA(trace)->input.pcap);
		trace_set_err(trace,TRACE_ERR_UNSUPPORTED,
				"Failed to retrieve stats: %s\n",
				errmsg ? errmsg : "Unknown pcap error");
		return;
	}

        stat->received_valid = 1;
        stat->received = pcapstats.ps_recv;
        stat->dropped_valid = 1;
        stat->dropped = pcapstats.ps_drop;
}

static void pcap_help(void) {
	printf("pcap format module: $Revision: 1729 $\n");
	printf("Supported input URIs:\n");
	printf("\tpcap:/path/to/file\n");
	printf("\n");
	printf("\te.g.: pcap:/tmp/trace.pcap\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tnone\n");
	printf("\n");
}

static void pcapint_help(void) {
	printf("pcapint format module: $Revision: 1729 $\n");
	printf("Supported input URIs:\n");
	printf("\tpcapint:interface\n");
	printf("\n");
	printf("\te.g.: pcapint:eth0\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tnone\n");
	printf("\n");
}


static struct libtrace_format_t pcap = {
	"pcap",
	"$Id$",
	TRACE_FORMAT_PCAP,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
	pcap_init_input,		/* init_input */
	pcap_config_input,		/* config_input */
	pcap_start_input,		/* start_input */
        pcap_pause_input,		/* pause_input */
	pcap_init_output,		/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	pcap_fin_input,			/* fin_input */
	pcap_fin_output,		/* fin_output */
	pcap_read_packet,		/* read_packet */
	pcap_prepare_packet,		/* prepare_packet */
	NULL,				/* fin_packet */
	pcap_write_packet,		/* write_packet */
        pcap_flush_output,              /* flush_output */
	pcap_get_link_type,		/* get_link_type */
	pcapint_get_direction,		/* get_direction */
	pcap_set_direction,		/* set_direction */
	NULL,				/* get_erf_timestamp */
	pcap_get_timeval,		/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* get_timespec */
	NULL,                           /* get_meta_section */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	pcap_get_capture_length,	/* get_capture_length */
	pcap_get_wire_length,		/* get_wire_length */
	pcap_get_framing_length,	/* get_framing_length */
	pcap_set_capture_length,	/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	NULL,				/* get_statistics */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	pcap_help,			/* help */
	NULL,			/* next pointer */
	NON_PARALLEL(false)
};

static struct libtrace_format_t pcapint = {
	"pcapint",
	"$Id$",
	TRACE_FORMAT_PCAP,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
	pcapint_init_input,		/* init_input */
	pcapint_config_input,		/* config_input */
	pcapint_start_input,		/* start_input */
	pcap_pause_input,		/* pause_input */
	pcapint_init_output,		/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_output */
	pcap_fin_input,			/* fin_input */
	pcapint_fin_output,		/* fin_output */
	pcap_read_packet,		/* read_packet */
	pcap_prepare_packet,		/* prepare_packet */
	NULL,				/* fin_packet */
	pcapint_write_packet,		/* write_packet */
	NULL,		                /* flush_output */
	pcap_get_link_type,		/* get_link_type */
	pcapint_get_direction,		/* get_direction */
	pcap_set_direction,		/* set_direction */
	NULL,				/* get_erf_timestamp */
	pcap_get_timeval,		/* get_timeval */
	NULL,				/* get_seconds */
	NULL,				/* get_timespec */
	NULL,                           /* get_meta_section */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	pcap_get_capture_length,	/* get_capture_length */
	pcap_get_wire_length,		/* get_wire_length */
	pcap_get_framing_length,	/* get_framing_length */
	pcap_set_capture_length,	/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,	                        /* get_dropped_packets */
	pcap_get_statistics,		/* get_statistics */
	pcap_get_fd,			/* get_fd */
	trace_event_device,		/* trace_event */
	pcapint_help,			/* help */
	NULL,			/* next pointer */
	NON_PARALLEL(true)
};

void pcap_constructor(void) {
	register_format(&pcap);
	register_format(&pcapint);
}


#endif
