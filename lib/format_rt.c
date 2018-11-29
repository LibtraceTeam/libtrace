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

#define _GNU_SOURCE

#include "config.h"
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "rt_protocol.h"

#include "data-struct/buckets.h"

#include <sys/stat.h>
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

/* Convert the RT denial code into a nice printable and coherent string */
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
	/* Name of the host to connect to */
	char *hostname;
	/* Buffer to store received packets into */
	char *pkt_buffer;
	/* Pointer to the next packet to be read from the buffer */
	char *buf_read;
	/* Pointer to the next unused byte in the buffer */
	char *buf_write;
	/* The port to connect to */
	int port;
	/* The file descriptor for the RT connection */
	int input_fd;
	/* Flag indicating whether the server is doing reliable RT */
	int reliable;

        int unacked;
	
	/* Dummy traces that can be assigned to the received packets to ensure
	 * that the appropriate functions can be used to process them */
	libtrace_t *dummy_duck;
	libtrace_t *dummy_erf;
	libtrace_t *dummy_pcap;
	libtrace_t *dummy_linux;
	libtrace_t *dummy_ring;
	libtrace_t *dummy_bpf;

        /* Bucket structure for storing read packets until the user is
         * done with them. */
        libtrace_bucket_t *bucket;
};

/* Connects to an RT server 
 *
 * Returns -1 if an error occurs
 */
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

	/* We are connected, now receive message from server */
	
	if (recv(RT_INFO->input_fd, (void*)&connect_msg, sizeof(rt_header_t), 0) != sizeof(rt_header_t) ) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				"Could not receive connection message from %s",
				RT_INFO->hostname);
		return -1;
	}

        if (connect_msg.magic != LIBTRACE_RT_MAGIC) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
                        "RT version mismatch: magic byte is incorrect");
                return -1;
        }

        if (connect_msg.version != LIBTRACE_RT_VERSION) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
                        "RT version mismatch: version is incorrect (expected %d, got %d",
                        LIBTRACE_RT_VERSION, connect_msg.version);
                return -1;
        }

                
	
        switch (ntohl(connect_msg.type)) {
		case TRACE_RT_DENY_CONN:
			/* Connection was denied */
			
			if (recv(RT_INFO->input_fd, (void*)&deny_hdr, 
						sizeof(rt_deny_conn_t),
						0) != sizeof(rt_deny_conn_t)) {
				reason = 0;
			}	
			reason = ntohl(deny_hdr.reason);
			trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				"Connection attempt is denied: %s",
				rt_deny_reason(reason));	
			return -1;
		case TRACE_RT_HELLO:
			/* Hello message - read the options sent to us by the
			 * server */
			if (recv(RT_INFO->input_fd, (void*)&hello_opts, 
						sizeof(rt_hello_t), 0)
					!= sizeof(rt_hello_t)) {
				trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
					"Failed to receive TRACE_RT_HELLO options");
				return -1;
			}
			
                        
                        RT_INFO->reliable = hello_opts.reliable;
			RT_INFO->unacked = 0;
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
	RT_INFO->dummy_ring = NULL;
	RT_INFO->dummy_bpf = NULL;
	RT_INFO->pkt_buffer = NULL;
	RT_INFO->buf_read = NULL;
	RT_INFO->buf_write = NULL;
	RT_INFO->hostname = NULL;
	RT_INFO->port = 0;
	RT_INFO->unacked = 0;

        RT_INFO->bucket = libtrace_bucket_init();
}

static int rt_init_input(libtrace_t *libtrace) {
        char *scan;
        char *uridata = libtrace->uridata;

	rt_init_format_data(libtrace);

	/* If the user specifies "rt:" then assume localhost and the default
	 * port */
        if (strlen(uridata) == 0) {
                RT_INFO->hostname =
                        strdup("localhost");
                RT_INFO->port =
                        COLLECTOR_PORT;
        } else {
                /* If the user does not specify a port, assume the default 
		 * port */
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

	start_msg.type = htonl(TRACE_RT_START);
	start_msg.length = 0;
        start_msg.sequence = 0;
        start_msg.version = LIBTRACE_RT_VERSION;
        start_msg.magic = LIBTRACE_RT_MAGIC; 

	if (rt_connect(libtrace) == -1)
		return -1;
	
	/* Need to send start message to server */
	if (send(RT_INFO->input_fd, (void*)&start_msg, sizeof(rt_header_t) +
				start_msg.length, 0) != sizeof(rt_header_t)) {
		printf("Failed to send start message to server\n");
		return -1;
	}

	return 0;
}

static int rt_pause_input(libtrace_t *libtrace) {
        rt_header_t close_msg;

	close_msg.type = htonl(TRACE_RT_CLOSE);
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
	/* Make sure we clean up any dummy traces that we have been using */

	if (RT_INFO->dummy_duck)
		trace_destroy_dead(RT_INFO->dummy_duck);

	if (RT_INFO->dummy_erf)
		trace_destroy_dead(RT_INFO->dummy_erf);

	if (RT_INFO->dummy_pcap)
		trace_destroy_dead(RT_INFO->dummy_pcap);

	if (RT_INFO->dummy_linux)
		trace_destroy_dead(RT_INFO->dummy_linux);

	if (RT_INFO->dummy_ring)
		trace_destroy_dead(RT_INFO->dummy_ring);

	if (RT_INFO->dummy_bpf)
		trace_destroy_dead(RT_INFO->dummy_bpf);

        if (RT_INFO->bucket)
                libtrace_bucket_destroy(RT_INFO->bucket);
	free(libtrace->format_data);
        return 0;
}

/* Sends an RT ACK to the server to acknowledge receipt of packets */
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
	
	hdr->type = htonl(TRACE_RT_ACK);
	hdr->length = htons(sizeof(rt_ack_t));

	ack_hdr->sequence = htonl(seqno);
	
	to_write = sizeof(rt_ack_t) + sizeof(rt_header_t);
	buf_ptr = ack_buffer;

	/* Keep trying until we write the entire ACK */
	while (to_write > 0) {
		numbytes = send(RT_INFO->input_fd, buf_ptr, to_write, 0); 
		if (numbytes == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			else {
				printf("Error sending ack\n");
				perror("send");
				trace_set_err(libtrace, TRACE_ERR_RT_FAILURE, 
						"Error sending ack");
				return -1;
			}
		}
		to_write = to_write - numbytes;
		buf_ptr = buf_ptr + to_write;
		
	}

	return 1;
}

/* Sets the trace format for the packet to match the format it was originally
 * captured in, rather than the RT format */
static int rt_set_format(libtrace_t *libtrace, libtrace_packet_t *packet) 
{

	/* We need to assign the packet to a "dead" trace */

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

	if (packet->type > TRACE_RT_DATA_BPF &&
			packet->type < TRACE_RT_DATA_BPF_END) {

		if (!RT_INFO->dummy_bpf) {
			RT_INFO->dummy_bpf = trace_create_dead("bpf:-");
			/* This may fail on a non-BSD machine */
			if (trace_is_err(RT_INFO->dummy_bpf)) {
				trace_perror(RT_INFO->dummy_bpf, "Creating dead bpf trace");
				return -1;
			}
		}
		packet->trace = RT_INFO->dummy_bpf;
		return 0;
	}

	switch (packet->type) {
		case TRACE_RT_DUCK_2_4:
		case TRACE_RT_DUCK_2_5:
		case TRACE_RT_DUCK_5_0:
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
				/* This may fail on a non-Linux machine */
				if (trace_is_err(RT_INFO->dummy_linux)) {
					trace_perror(RT_INFO->dummy_linux, "Creating dead int trace");
					return -1;
				}
			}
			packet->trace = RT_INFO->dummy_linux;
			break;
		case TRACE_RT_DATA_LINUX_RING:
			if (!RT_INFO->dummy_ring) {
				RT_INFO->dummy_ring = trace_create_dead("ring:");
				/* This may fail on a non-Linux machine */
				if (trace_is_err(RT_INFO->dummy_ring)) {
					trace_perror(RT_INFO->dummy_ring, "Creating dead ring trace");
					return -1;
				}
			}
			packet->trace = RT_INFO->dummy_ring;
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
#define RT_BUF_SIZE (LIBTRACE_PACKET_BUFSIZE * 2)

static int rt_process_data_packet(libtrace_t *libtrace,
                libtrace_packet_t *packet) {

        uint32_t prep_flags = TRACE_PREP_DO_NOT_OWN_BUFFER;
        rt_header_t *hdr = (rt_header_t *)packet->header;

        /* Send an ACK if required */
        if (RT_INFO->reliable > 0 && packet->type >= TRACE_RT_DATA_SIMPLE) {
		RT_INFO->unacked ++;
                if (RT_INFO->unacked >= RT_ACK_FREQUENCY) {
                        if (rt_send_ack(libtrace, hdr->sequence) == -1)
                               	return -1;
                        RT_INFO->unacked = 0;
                }
	}

	/* Convert to the original capture format */
	if (rt_set_format(libtrace, packet) < 0) {
		return -1;
        }

	/* Update payload pointers and packet type to match the original
	 * format */
	if (trace_prepare_packet(packet->trace, packet, packet->payload,
				packet->type, prep_flags)) {
		return -1;
	}

        return 1;

}

/* Receives data from an RT server */
static int rt_read(libtrace_t *libtrace, int block) {
        int numbytes;

	if (!RT_INFO->pkt_buffer) {
		RT_INFO->pkt_buffer = (char*)malloc((size_t)RT_BUF_SIZE);
		RT_INFO->buf_write = RT_INFO->pkt_buffer;
                RT_INFO->buf_read = RT_INFO->pkt_buffer;
                libtrace_create_new_bucket(RT_INFO->bucket, RT_INFO->pkt_buffer);
	}

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif

	if (block)
		block=0;
	else
		block=MSG_DONTWAIT;

        /* If the current buffer has plenty of space left, we can continue to 
         * read into it, otherwise create a new buffer and move anything in
         * the old buffer over to it */
        if (RT_INFO->buf_write - RT_INFO->pkt_buffer > RT_BUF_SIZE / 2) {
                char *newbuf = (char*)malloc((size_t)RT_BUF_SIZE);

                memcpy(newbuf, RT_INFO->buf_read, RT_INFO->buf_write - RT_INFO->buf_read);
                RT_INFO->buf_write = newbuf + (RT_INFO->buf_write - RT_INFO->buf_read);
                RT_INFO->buf_read = newbuf;
                RT_INFO->pkt_buffer = newbuf;
                libtrace_create_new_bucket(RT_INFO->bucket, newbuf);

        }

        /* Attempt to fill the buffer as much as we can */
        if ((numbytes = recv(RT_INFO->input_fd, RT_INFO->buf_write,
                        RT_BUF_SIZE - (RT_INFO->buf_write-RT_INFO->pkt_buffer),
                        MSG_NOSIGNAL | block)) <= 0) {

                if (numbytes == 0) {
                        trace_set_err(libtrace, TRACE_ERR_RT_FAILURE,
                                        "No data received by RT client");
                        return -1;
                }

                if (errno == EINTR) {
                        /* Ignore EINTR in case a caller is using signals */
                        return 0;
                }

                if (errno == EAGAIN) {
                        /* No data available and we are non-blocking */
                        trace_set_err(libtrace, EAGAIN, "EAGAIN");
                        return -1;
                }

                trace_set_err(libtrace, TRACE_ERR_RT_FAILURE,
                                "Error reading from RT socket: %s",
                                strerror(errno));
                return -1;
        }

        RT_INFO->buf_write += numbytes;
        return (RT_INFO->buf_write - RT_INFO->buf_read);

}


static int rt_get_next_packet(libtrace_t *libtrace, libtrace_packet_t *packet,
                int block) {

        rt_header_t *rthdr;

        if (packet->buffer && packet->buf_control == TRACE_CTRL_PACKET)
                free(packet->buffer);

        while (RT_INFO->buf_write - RT_INFO->buf_read <
                                (uint32_t)sizeof(rt_header_t)) {
                if (rt_read(libtrace, block) == -1)
                        return -1;
        }

        rthdr = (rt_header_t *)RT_INFO->buf_read;

        /* Check if we have enough payload */
        while (RT_INFO->buf_write - (RT_INFO->buf_read + sizeof(rt_header_t))
                        < ntohs(rthdr->length)) {
                if (rt_read(libtrace, block) == -1)
                        return -1;
                rthdr = (rt_header_t *)RT_INFO->buf_read;
        }


        packet->buffer = RT_INFO->buf_read;
        packet->header = RT_INFO->buf_read;
        packet->type = ntohl(((rt_header_t *)packet->header)->type);
        packet->payload = RT_INFO->buf_read + sizeof(rt_header_t);
        packet->internalid = libtrace_push_into_bucket(RT_INFO->bucket);
	if (!packet->internalid) {
		trace_set_err(libtrace, TRACE_ERR_RT_FAILURE, "packet->internalid is 0 in rt_get_next_packet()");
		return -1;
	}
        packet->srcbucket = RT_INFO->bucket;
        packet->buf_control = TRACE_CTRL_EXTERNAL;

        RT_INFO->buf_read += ntohs(rthdr->length) + sizeof(rt_header_t);

        if (packet->type >= TRACE_RT_DATA_SIMPLE) {
                rt_process_data_packet(libtrace, packet);
        } else {
                switch(packet->type) {
                        case TRACE_RT_DUCK_2_4:
                        case TRACE_RT_DUCK_2_5:
                        case TRACE_RT_STATUS:
                        case TRACE_RT_METADATA:
                                if (rt_process_data_packet(libtrace, packet) < 0)
                                        return -1;
                                break;
                        case TRACE_RT_END_DATA:
                        case TRACE_RT_KEYCHANGE:
                        case TRACE_RT_LOSTCONN:
                        case TRACE_RT_CLIENTDROP:
                        case TRACE_RT_SERVERSTART:
                                break;
                        case TRACE_RT_PAUSE_ACK:
                        case TRACE_RT_OPTION:
                                break;
                        default:
                                fprintf(stderr, "Bad RT type for client: %d\n",
                                                packet->type);
                                return -1;
                }
        }

        return ntohs(rthdr->length);

}

/* Shouldn't need to call this too often */
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

/* Reads the next available packet in a blocking fashion */
static int rt_read_packet(libtrace_t *libtrace,
		libtrace_packet_t *packet) {
	return rt_get_next_packet(libtrace,packet,1);
}


/* This should only get called for RT messages - RT-encapsulated data records
 * should be converted to the appropriate capture format */
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

/* RT messages do not have a wire length because they were not captured from
 * the wire - they were generated by the capture process */
static int rt_get_wire_length(UNUSED const libtrace_packet_t *packet) {
	return 0;
}

/* Although RT messages do contain "framing", this framing is considered to be
 * stripped as soon as the packet is read by the RT client */			
static int rt_get_framing_length(UNUSED const libtrace_packet_t *packet) {
	return 0;
}


static libtrace_linktype_t rt_get_link_type(UNUSED const libtrace_packet_t *packet)
{
	/* RT messages don't have a link type */
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

	if (!trace) {
		fprintf(stderr, "NULL trace passed into trace_event_rt()\n");
		/* Return empty event on error? */
		return event;
	}
	if (!packet) {
		trace_set_err(trace, TRACE_ERR_NULL_PACKET, "NULL packet passed into trace_event_rt()");
		/* Return empty event on error? */
		return event;
	}

	if (trace->format->get_fd) {
		event.fd = trace->format->get_fd(trace);
	} else {
		event.fd = 0;
	}

	do {

		event.size = rt_get_next_packet(trace, packet, 0);
		if (event.size == -1) {
			read_err = trace_get_err(trace);
			if (read_err.err_num == EAGAIN) {
				/* No data available - do an IOWAIT */
				event.type = TRACE_EVENT_IOWAIT;
			}
			else {
				trace_perror(trace, "Error doing a non-blocking read from rt");
				event.type = TRACE_EVENT_PACKET;
				break;
			}
		} else if (event.size == 0) {
			/* RT gives us a specific indicator that there will be 
			 * no more packets. */
			if (packet->type == TRACE_RT_END_DATA)
				event.type = TRACE_EVENT_TERMINATE;
			else {
				/* Since several RT messages can have zero-byte
				 * length (once the framing is removed), an 
				 * event size of zero can still indicate a 
				 * PACKET event */
				event.type = TRACE_EVENT_PACKET;
                                trace->accepted_packets ++;
                        }

		}	
		else {
			event.type = TRACE_EVENT_PACKET;
                        trace->accepted_packets ++;
		}

		if (trace->filter && event.type == TRACE_EVENT_PACKET) {
			if (!trace_apply_filter(trace->filter, packet)) {
				trace_clear_cache(packet);
				trace->filtered_packets ++;
                                continue;
			}
		}

		break;	
	} while (1);

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
	NULL,   			/* fin_packet */
        NULL,                           /* write_packet */
        NULL,                           /* flush_output */
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
	NULL,				/* get_statistics */
        rt_get_fd,                	/* get_fd */
        trace_event_rt,             /* trace_event */
        rt_help,			/* help */
	NULL,			/* next pointer */
	NON_PARALLEL(true) /* This is normally live */
};

void rt_constructor(void) {
	register_format(&rt);
}
