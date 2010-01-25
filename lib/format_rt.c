/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson
 *          Perry Lorier
 *	    Shane Alcock
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
#include "rt_protocol.h"

#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef WIN32
# include <netdb.h>
#endif

#define RT_INFO ((struct rt_format_data_t*)libtrace->format_data)

static const char *rt_deny_reason(enum rt_conn_denied_t reason) 
{
	const char *string = 0;

	switch(reason) {
		case RT_DENY_WRAPPER:
			string = "Rejected by TCP Wrappers";
			break;
		case RT_DENY_FULL:
			string = "Max connections reached on server";
			break;
		case RT_DENY_AUTH:
			string = "Authentication failed";
			break;
		default:
			string = "Unknown reason";
	}

	return string;
}


struct rt_format_data_t {
	char *hostname;
	char *pkt_buffer;
	char *buf_current;
	size_t buf_filled;
	int port;
	int input_fd;
	int reliable;
	rt_header_t rt_hdr;
	
	libtrace_t *dummy_duck;
	libtrace_t *dummy_erf;
	libtrace_t *dummy_pcap;
	libtrace_t *dummy_linux;
};

static int rt_connect(libtrace_t *libtrace) {
        struct hostent *he;
        struct sockaddr_in remote;
	rt_header_t connect_msg;
	rt_deny_conn_t deny_hdr;	
	rt_hello_t hello_opts;
	uint8_t reason;
	
	if ((he=gethostbyname(RT_INFO->hostname)) == NULL) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				"Failed to convert hostname %s to address",
				RT_INFO->hostname);
		return -1;
        }
        if ((RT_INFO->input_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				"Could not create socket");
		return -1;
        }

	memset(&remote,0, sizeof(remote));
        remote.sin_family = AF_INET;
        remote.sin_port = htons(RT_INFO->port);
        remote.sin_addr = *((struct in_addr *)he->h_addr);

        if (connect(RT_INFO->input_fd, (struct sockaddr *)&remote,
                                (socklen_t)sizeof(struct sockaddr)) == -1) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				"Could not connect to host %s on port %d",
				RT_INFO->hostname, RT_INFO->port);
		return -1;
        }

	
#if 0
	oldflags = fcntl(RT_INFO->input_fd, F_GETFL, 0);
	if (oldflags == -1) {
		trace_set_err(libtrace, errno,
				"Could not get fd flags from fd %d\n",
				RT_INFO->input_fd);
		return -1;
	}
	oldflags |= O_NONBLOCK;
	if (fcntl(RT_INFO->input_fd, F_SETFL, oldflags) == -1) {
		trace_set_err(libtrace, errno,
				"Could not set fd flags for fd %d\n",
				RT_INFO->input_fd);
		return -1;
	}
#endif
	
	
	/* We are connected, now receive message from server */
	
	if (recv(RT_INFO->input_fd, (void*)&connect_msg, sizeof(rt_header_t), 0) != sizeof(rt_header_t) ) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				"Could not receive connection message from %s",
				RT_INFO->hostname);
		return -1;
	}
	
	switch (connect_msg.type) {
		case TRACE_RT_DENY_CONN:
			
			if (recv(RT_INFO->input_fd, (void*)&deny_hdr, 
						sizeof(rt_deny_conn_t),
						0) != sizeof(rt_deny_conn_t)) {
				reason = 0;
			}	
			reason = deny_hdr.reason;
			trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				"Connection attempt is denied: %s",
				rt_deny_reason(reason));	
			return -1;
		case TRACE_RT_HELLO:
			/* do something with options */
			if (recv(RT_INFO->input_fd, (void*)&hello_opts, 
						sizeof(rt_hello_t), 0)
					!= sizeof(rt_hello_t)) {
				trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
					"Failed to receive TRACE_RT_HELLO options");
				return -1;
			}
			RT_INFO->reliable = hello_opts.reliable;
			
			return 0;
		default:
			trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
					"Unknown message type received: %d",
					connect_msg.type);
			return -1;
	}
	trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
			"Somehow you managed to reach this unreachable code");
        return -1;
}

static void rt_init_format_data(libtrace_t *libtrace) {
        libtrace->format_data = malloc(sizeof(struct rt_format_data_t));

	RT_INFO->dummy_duck = NULL;
	RT_INFO->dummy_erf = NULL;
	RT_INFO->dummy_pcap = NULL;
	RT_INFO->dummy_linux = NULL;
	RT_INFO->pkt_buffer = NULL;
	RT_INFO->buf_current = NULL;
	RT_INFO->buf_filled = 0;
	RT_INFO->hostname = NULL;
	RT_INFO->port = 0;
}

static int rt_init_input(libtrace_t *libtrace) {
        char *scan;
        char *uridata = libtrace->uridata;

	rt_init_format_data(libtrace);
	
        if (strlen(uridata) == 0) {
                RT_INFO->hostname =
                        strdup("localhost");
                RT_INFO->port =
                        COLLECTOR_PORT;
        } else {
                if ((scan = strchr(uridata,':')) == NULL) {
                        RT_INFO->hostname =
                                strdup(uridata);
                        RT_INFO->port =
                                COLLECTOR_PORT;
                } else {
                        RT_INFO->hostname =
                                (char *)strndup(uridata,
                                                (size_t)(scan - uridata));
                        RT_INFO->port =
                                atoi(++scan);
                }
        }

	return 0;
}
	
static int rt_start_input(libtrace_t *libtrace) {
	rt_header_t start_msg;

	start_msg.type = TRACE_RT_START;
	start_msg.length = 0; 

	if (rt_connect(libtrace) == -1)
		return -1;
	
	/* Need to send start message to server */
	if (send(RT_INFO->input_fd, (void*)&start_msg, sizeof(rt_header_t) +
				start_msg.length, 0) != sizeof(rt_header_t)) {
		printf("Failed to send start message to server\n");
		return -1;
	}
	RT_INFO->rt_hdr.type = TRACE_RT_LAST;

	return 0;
}

static int rt_pause_input(libtrace_t *libtrace) {
        rt_header_t close_msg;

	close_msg.type = TRACE_RT_CLOSE;
	close_msg.length = 0; 
	
	/* Send a close message to the server */
	if (send(RT_INFO->input_fd, (void*)&close_msg, sizeof(rt_header_t) + 
				close_msg.length, 0) != (int)sizeof(rt_header_t)
				+ close_msg.length) {
		printf("Failed to send close message to server\n");
	
	}

	close(RT_INFO->input_fd);
	return 0;
}

static int rt_fin_input(libtrace_t *libtrace) {
	if (RT_INFO->dummy_duck)
		trace_destroy_dead(RT_INFO->dummy_duck);

	if (RT_INFO->dummy_erf) 
		trace_destroy_dead(RT_INFO->dummy_erf);
		
	if (RT_INFO->dummy_pcap)
		trace_destroy_dead(RT_INFO->dummy_pcap);

	if (RT_INFO->dummy_linux)
		trace_destroy_dead(RT_INFO->dummy_linux);
	free(libtrace->format_data);
        return 0;
}


/* I've upped this to 10K to deal with jumbo-grams that have not been snapped
 * in any way. This means we have a much larger memory overhead per packet
 * (which won't be used in the vast majority of cases), so we may want to think
 * about doing something smarter, e.g. allocate a smaller block of memory and
 * only increase it as required.
 *
 * XXX Capturing off int: can still lead to packets that are larger than 10K,
 * in instances where the fragmentation is done magically by the NIC. This
 * is pretty nasty, but also very rare.
 */
#define RT_BUF_SIZE 10000U

static int rt_read(libtrace_t *libtrace, void **buffer, size_t len, int block) 
{
        int numbytes;
	
	assert(len <= RT_BUF_SIZE);
	
	if (!RT_INFO->pkt_buffer) {
		RT_INFO->pkt_buffer = (char*)malloc((size_t)RT_BUF_SIZE);
		RT_INFO->buf_current = RT_INFO->pkt_buffer;
		RT_INFO->buf_filled = 0;
	}

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

	if (block)
		block=0;
	else
		block=MSG_DONTWAIT;

	
	if (len > RT_INFO->buf_filled) {
		memcpy(RT_INFO->pkt_buffer, RT_INFO->buf_current, 
				RT_INFO->buf_filled);
		RT_INFO->buf_current = RT_INFO->pkt_buffer;
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif
		while (len > RT_INFO->buf_filled) {
                	if ((numbytes = recv(RT_INFO->input_fd,
                                                RT_INFO->buf_current + 
						RT_INFO->buf_filled,
                                                RT_BUF_SIZE-RT_INFO->buf_filled,
                                                MSG_NOSIGNAL|block)) <= 0) {
				if (numbytes == 0) {
					trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, 
							"No data received");
					return -1;
				}
				
                	        if (errno == EINTR) {
                	                /* ignore EINTR in case
                	                 * a caller is using signals
					 */
                	                continue;
                	        }
				if (errno == EAGAIN) {
					trace_set_err(libtrace,
							EAGAIN,
							"EAGAIN");
					return -1;
				}
				
                        	perror("recv");
				trace_set_err(libtrace, errno,
						"Failed to read data into rt recv buffer");
                        	return -1;
                	}
			/*
			buf_ptr = RT_INFO->pkt_buffer;
			for (i = 0; i < RT_BUF_SIZE ; i++) {
					
				printf("%02x", (unsigned char)*buf_ptr);
				buf_ptr ++;
			}
			printf("\n");
			*/
			RT_INFO->buf_filled+=numbytes;
		}

        }
	*buffer = RT_INFO->buf_current;
	RT_INFO->buf_current += len;
	RT_INFO->buf_filled -= len;
        return len;
}


static int rt_set_format(libtrace_t *libtrace, libtrace_packet_t *packet) 
{

	/* Try to minimize the number of corrupt packets that slip through
	 * while making it easy to identify new pcap DLTs */
	if (packet->type > TRACE_RT_DATA_DLT && 
			packet->type < TRACE_RT_DATA_DLT_END) {
		if (!RT_INFO->dummy_pcap) {
			RT_INFO->dummy_pcap = trace_create_dead("pcap:-");
		}
		packet->trace = RT_INFO->dummy_pcap;
		return 0;	
	}

	switch (packet->type) {
		case TRACE_RT_DUCK_2_4:
		case TRACE_RT_DUCK_2_5:
			if (!RT_INFO->dummy_duck) {
				RT_INFO->dummy_duck = trace_create_dead("duck:dummy");
			}
			packet->trace = RT_INFO->dummy_duck;
			break;
		case TRACE_RT_DATA_ERF:
			if (!RT_INFO->dummy_erf) {
				RT_INFO->dummy_erf = trace_create_dead("erf:-");
			}
			packet->trace = RT_INFO->dummy_erf;
			break;
		case TRACE_RT_DATA_LINUX_NATIVE:
			if (!RT_INFO->dummy_linux) {
				RT_INFO->dummy_linux = trace_create_dead("int:");
			}
			packet->trace = RT_INFO->dummy_linux;
			break;
		case TRACE_RT_STATUS:
		case TRACE_RT_METADATA:
			/* Just use the RT trace! */
			packet->trace = libtrace;
			break;
		case TRACE_RT_DATA_LEGACY_ETH:
		case TRACE_RT_DATA_LEGACY_ATM:
		case TRACE_RT_DATA_LEGACY_POS:
			printf("Sending legacy over RT is currently not supported\n");
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Legacy packet cannot be sent over rt");
			return -1;
		default:
			printf("Unrecognised format: %u\n", packet->type);
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Unrecognised packet format");
			return -1;
	}
	return 0; /* success */
}		

static int rt_send_ack(libtrace_t *libtrace, 
		uint32_t seqno)  {
	
	static char *ack_buffer = 0;
	char *buf_ptr;
	int numbytes = 0;
	size_t to_write = 0;
	rt_header_t *hdr;
	rt_ack_t *ack_hdr;
	
	if (!ack_buffer) {
		ack_buffer = (char*)malloc(sizeof(rt_header_t) 
							+ sizeof(rt_ack_t));
	}
	
	hdr = (rt_header_t *) ack_buffer;
	ack_hdr = (rt_ack_t *) (ack_buffer + sizeof(rt_header_t));
	
	hdr->type = TRACE_RT_ACK;
	hdr->length = sizeof(rt_ack_t);

	ack_hdr->sequence = seqno;
	
	to_write = hdr->length + sizeof(rt_header_t);
	buf_ptr = ack_buffer;

	while (to_write > 0) {
		numbytes = send(RT_INFO->input_fd, buf_ptr, to_write, 0); 
		if (numbytes == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			else {
				printf("Error sending ack\n");
				perror("send");
				trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, 
						"Error sending ack");
				return -1;
			}
		}
		to_write = to_write - numbytes;
		buf_ptr = buf_ptr + to_write;
		
	}

	return 1;
}

static int rt_prepare_packet(libtrace_t *libtrace, libtrace_packet_t *packet,
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
        packet->header = NULL;
        packet->type = rt_type;
	packet->payload = buffer;

	if (libtrace->format_data == NULL) {
		rt_init_format_data(libtrace);
	}

	return 0;
}	

static int rt_read_data_packet(libtrace_t *libtrace,
		libtrace_packet_t *packet, int blocking) {
	uint32_t prep_flags = 0;

	prep_flags |= TRACE_PREP_DO_NOT_OWN_BUFFER;

	if (rt_read(libtrace, &packet->buffer, (size_t)RT_INFO->rt_hdr.length, 
				blocking) != RT_INFO->rt_hdr.length) {
		return -1;
	}

        if (RT_INFO->reliable > 0 && packet->type >= TRACE_RT_DATA_SIMPLE) {
		if (rt_send_ack(libtrace, RT_INFO->rt_hdr.sequence) == -1)
                               	return -1;
	}
	
	if (rt_set_format(libtrace, packet) < 0) {
		return -1;
        }
               	
	/* Update payload pointers and loss counters correctly */
	if (trace_prepare_packet(packet->trace, packet, packet->buffer,
				packet->type, prep_flags)) {
		return -1;
	}

	return 0;
}

static int rt_read_packet_versatile(libtrace_t *libtrace,
		libtrace_packet_t *packet,int blocking) {
	rt_header_t *pkt_hdr = NULL;
	void *void_hdr;
	libtrace_rt_types_t switch_type;
	
	if (packet->buf_control == TRACE_CTRL_PACKET) {
		packet->buf_control = TRACE_CTRL_EXTERNAL;
		free(packet->buffer);
		packet->buffer = NULL;
	}

	/* RT_LAST means that the next bytes received should be a 
	 * rt header - I know it's hax and maybe I'll fix it later on */
	if (RT_INFO->rt_hdr.type == TRACE_RT_LAST) {
		void_hdr = (void *)pkt_hdr;
		/* FIXME: Better error handling required */
		if (rt_read(libtrace, &void_hdr, 
				sizeof(rt_header_t),blocking) !=
				sizeof(rt_header_t)) {
			return -1;
		}
		pkt_hdr = (rt_header_t *)void_hdr;
		
		/* Need to salvage these in case the next rt_read overwrites 
		 * the buffer they came from! */
		RT_INFO->rt_hdr.type = pkt_hdr->type;
		RT_INFO->rt_hdr.length = pkt_hdr->length;
		RT_INFO->rt_hdr.sequence = pkt_hdr->sequence;
	}
	packet->type = RT_INFO->rt_hdr.type;
	
	if (packet->type >= TRACE_RT_DATA_SIMPLE) {
		switch_type = TRACE_RT_DATA_SIMPLE;
	} else {
		switch_type = packet->type;
	}

	switch(switch_type) {
		case TRACE_RT_DATA_SIMPLE:
		case TRACE_RT_DUCK_2_4:
		case TRACE_RT_DUCK_2_5:
		case TRACE_RT_STATUS:
		case TRACE_RT_METADATA:
			if (rt_read_data_packet(libtrace, packet, blocking))
				return -1;
			break;
		case TRACE_RT_END_DATA:
		case TRACE_RT_KEYCHANGE:
		case TRACE_RT_LOSTCONN:
		case TRACE_RT_CLIENTDROP:
		case TRACE_RT_SERVERSTART:
			/* All these have no payload */
			break;
		case TRACE_RT_PAUSE_ACK:
			/* XXX: Add support for this */
			break;
		case TRACE_RT_OPTION:
			/* XXX: Add support for this */
			break;
		default:
			printf("Bad rt type for client receipt: %d\n",
					switch_type);
			return -1;
	}
				
			
		
	/* Return the number of bytes read from the stream */
	RT_INFO->rt_hdr.type = TRACE_RT_LAST;
	return RT_INFO->rt_hdr.length + sizeof(rt_header_t);
}

static int rt_read_packet(libtrace_t *libtrace,
		libtrace_packet_t *packet) {
	return rt_read_packet_versatile(libtrace,packet,1);
}


static int rt_get_capture_length(const libtrace_packet_t *packet) {
	rt_metadata_t *rt_md_hdr;
	switch (packet->type) {
		case TRACE_RT_STATUS:
			return sizeof(rt_status_t);
		case TRACE_RT_HELLO:
			return sizeof(rt_hello_t);
		case TRACE_RT_START:
			return 0;
		case TRACE_RT_ACK:
			return sizeof(rt_ack_t);
		case TRACE_RT_END_DATA:
			return 0;
		case TRACE_RT_CLOSE:
			return 0;
		case TRACE_RT_DENY_CONN:
			return sizeof(rt_deny_conn_t);
		case TRACE_RT_PAUSE:
			return 0; 
		case TRACE_RT_PAUSE_ACK:
			return 0;
		case TRACE_RT_OPTION:
			return 0; /* FIXME */
		case TRACE_RT_KEYCHANGE:
			return 0;
		case TRACE_RT_LOSTCONN:
			return 0;
		case TRACE_RT_SERVERSTART:
			return 0;
		case TRACE_RT_CLIENTDROP:
			return 0;
		case TRACE_RT_METADATA:
			/* This is a little trickier to work out */
			rt_md_hdr = (rt_metadata_t *)packet->buffer;
			return rt_md_hdr->label_len + rt_md_hdr->value_len + 
				sizeof(rt_metadata_t);
		default:
			printf("Unknown type: %d\n", packet->type);
			
	}
	return 0;
}

static int rt_get_wire_length(UNUSED const libtrace_packet_t *packet) {
	return 0;
}
			
static int rt_get_framing_length(UNUSED const libtrace_packet_t *packet) {
	return 0;
}

static libtrace_linktype_t rt_get_link_type(UNUSED const libtrace_packet_t *packet)
{
	return TRACE_TYPE_NONDATA;
}

static int rt_get_fd(const libtrace_t *trace) {
        return ((struct rt_format_data_t *)trace->format_data)->input_fd;
}

static libtrace_eventobj_t trace_event_rt(libtrace_t *trace,
					libtrace_packet_t *packet) 
{
	libtrace_eventobj_t event = {0,0,0.0,0};
	libtrace_err_t read_err;

	assert(trace);
	assert(packet);
	
	if (trace->format->get_fd) {
		event.fd = trace->format->get_fd(trace);
	} else {
		event.fd = 0;
	}

	event.size = rt_read_packet_versatile(trace, packet, 0);
	if (event.size == -1) {
		read_err = trace_get_err(trace);
		if (read_err.err_num == EAGAIN) {
			event.type = TRACE_EVENT_IOWAIT;
		}
		else {
			event.type = TRACE_EVENT_PACKET;
		}
	} else if (event.size == 0) {
		if (packet->type == TRACE_RT_END_DATA)
			event.type = TRACE_EVENT_TERMINATE;
		else
			event.type = TRACE_EVENT_PACKET;
		
	}	
	else {
		event.type = TRACE_EVENT_PACKET;
	}

	
	return event;
}

static void rt_help(void) {
        printf("rt format module\n");
        printf("Supported input URIs:\n");
        printf("\trt:hostname:port\n");
        printf("\trt:hostname (connects on default port)\n");
        printf("\n");
        printf("\te.g.: rt:localhost\n");
        printf("\te.g.: rt:localhost:32500\n");
        printf("\n");

}


static struct libtrace_format_t rt = {
        "rt",
        "$Id$",
        TRACE_FORMAT_RT,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
        rt_init_input,            	/* init_input */
        NULL,                           /* config_input */
        rt_start_input,           	/* start_input */
	rt_pause_input,			/* pause */
        NULL,                           /* init_output */
        NULL,                           /* config_output */
        NULL,                           /* start_output */
        rt_fin_input,             	/* fin_input */
        NULL,                           /* fin_output */
        rt_read_packet,           	/* read_packet */
	rt_prepare_packet,		/* prepare_packet */
	NULL,				/* fin_packet */
        NULL,                           /* write_packet */
        rt_get_link_type,	        /* get_link_type */
        NULL,  		            	/* get_direction */
        NULL,              		/* set_direction */
        NULL,          			/* get_erf_timestamp */
        NULL,                           /* get_timeval */
	NULL,				/* get_timespec */
        NULL,                           /* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
        rt_get_capture_length,        	/* get_capture_length */
        rt_get_wire_length,            		/* get_wire_length */
        rt_get_framing_length, 		/* get_framing_length */
        NULL,         			/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	NULL,				/* get_captured_packets */
        rt_get_fd,                	/* get_fd */
        trace_event_rt,             /* trace_event */
        rt_help,			/* help */
	NULL				/* next pointer */
};

void rt_constructor(void) {
	register_format(&rt);
}
