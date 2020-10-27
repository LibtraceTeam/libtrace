#include "libtrace.h"
#include "libtrace_int.h"
#include "format_tzsplive.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#define FORMAT_DATA ((tzsp_format_data_t *)libtrace->format_data)
#define FORMAT_DATA_OUT ((tzsp_format_data_out_t *)libtrace->format_data)

#define TZSP_RECVBUF_SIZE (64 * 1024 * 1024)
#define TZSP_SENDBUF_SIZE (64 * 1024 * 1024)

static int tzsplive_get_framing_length(const libtrace_packet_t *packet);

typedef struct tzsp_format_data {
	char *listenaddr;
	char *listenport;

	int socket;
	uint8_t *buf;
} tzsp_format_data_t;

typedef struct tzsp_format_data_out {
	char *outaddr;
	char *outport;

	int outsocket;
	uint8_t *buf;
	struct addrinfo *listenai;
} tzsp_format_data_out_t;

typedef struct tzsp_header {
	uint8_t version;
	uint8_t type;
	uint16_t encap;
} PACKED tzsp_header_t;

typedef struct tzsp_tagfield {
	uint8_t type;
	uint8_t length;
} PACKED tzsp_tagfield_t;

static bool tzsplive_can_write(libtrace_packet_t *packet) {
	libtrace_linktype_t ltype = trace_get_link_type(packet);

	if (ltype == TRACE_TYPE_CONTENT_INVALID
		|| ltype == TRACE_TYPE_UNKNOWN
		|| ltype == TRACE_TYPE_ERF_META
		|| ltype == TRACE_TYPE_NONDATA
		|| ltype == TRACE_TYPE_PCAPNG_META) {

		return false;
	}

	return true;
}

static int tzsplive_create_socket(libtrace_t *libtrace) {
	struct addrinfo hints, *listenai;
	int reuse = 1;
	int recvbuf = TZSP_RECVBUF_SIZE;

	hints.ai_family = PF_UNSPEC;
	/* UDP socket */
	hints.ai_socktype = SOCK_DGRAM;
	/* listen for connections */
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;

	listenai = NULL;

	if (getaddrinfo(FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
		&hints, &listenai) != 0) {

		fprintf(stderr, "Call to getaddrinfo failed for %s:%s -- %s\n",
			FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
			strerror(errno));
		goto listenerror;
	}

	FORMAT_DATA->socket = socket(listenai->ai_family, listenai->ai_socktype, 0);
	if (FORMAT_DATA->socket < 0) {
		fprintf(stderr, "Failed to create socket for %s:%s -- %s\n",
			FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
			strerror(errno));
		goto listenerror;
	}

	if (setsockopt(FORMAT_DATA->socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		fprintf(stderr, "Failed to configure socket for %s:%s -- %s\n",
			FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
			strerror(errno));
		goto listenerror;
	}

	if (setsockopt(FORMAT_DATA->socket, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf)) < 0) {
		fprintf(stderr, "Failed to set receive buffer for %s:%s -- %s\n",
			FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
			strerror(errno));
		goto listenerror;
	}

	if (bind(FORMAT_DATA->socket, (struct sockaddr *)listenai->ai_addr, listenai->ai_addrlen) < 0) {
		fprintf(stderr, "Failed to bind socket for %s:%s -- %s\n",
			FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
			strerror(errno));
		goto listenerror;
	}

	freeaddrinfo(listenai);
	return 1;

listenerror:
	trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable to create listening "
		"socket for tzsplive");
	freeaddrinfo(listenai);
	return -1;

}

static int tzsplive_create_output_socket(libtrace_out_t *libtrace) {
	struct addrinfo hints;
        int reuse = 1;
	int sendbuf = TZSP_SENDBUF_SIZE;

        hints.ai_family = PF_UNSPEC;
        /* UDP socket */
        hints.ai_socktype = SOCK_DGRAM;
        /* listen for connections */
        hints.ai_flags = AI_PASSIVE;
        hints.ai_protocol = 0;

        FORMAT_DATA_OUT->listenai = NULL;

	if (getaddrinfo(FORMAT_DATA_OUT->outaddr, FORMAT_DATA_OUT->outport,
                &hints, &FORMAT_DATA_OUT->listenai) != 0) {

                fprintf(stderr, "Call to getaddrinfo failed for %s:%s -- %s\n",
                        FORMAT_DATA_OUT->outaddr, FORMAT_DATA_OUT->outport,
                        strerror(errno));
                goto listenerror;
        }

	FORMAT_DATA_OUT->outsocket = socket(FORMAT_DATA_OUT->listenai->ai_family,
						FORMAT_DATA_OUT->listenai->ai_socktype, 0);
        if (FORMAT_DATA_OUT->outsocket < 0) {
                fprintf(stderr, "Failed to create socket for %s:%s -- %s\n",
                        FORMAT_DATA_OUT->outaddr, FORMAT_DATA_OUT->outport,
                        strerror(errno));
                goto listenerror;
        }

	if (setsockopt(FORMAT_DATA_OUT->outsocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
                fprintf(stderr, "Failed to configure socket for %s:%s -- %s\n",
                        FORMAT_DATA_OUT->outaddr, FORMAT_DATA_OUT->outport,
                        strerror(errno));
                goto listenerror;
        }

	if (setsockopt(FORMAT_DATA_OUT->outsocket, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf)) < 0) {
		fprintf(stderr, "Failed to set send buffer for %s:%s -- %s\n",
			FORMAT_DATA_OUT->outaddr, FORMAT_DATA_OUT->outport,
                        strerror(errno));
		goto listenerror;
	}

        return 1;

listenerror:
        trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "Unable to create output "
                "socket for tzsplive");
        freeaddrinfo(FORMAT_DATA_OUT->listenai);
        return -1;
}

/* called with trace_create */
static int tzsplive_init_input(libtrace_t *libtrace) {
	char *scan = NULL;

	libtrace->format_data = (tzsp_format_data_t *)calloc(1,
		sizeof(tzsp_format_data_t));

	if (libtrace->format_data == NULL) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable "
			"to allocate memory for format data in tzsp_init_input();");
		return -1;
	}

	scan = strchr(libtrace->uridata, ':');
	if (scan == NULL) {
                FORMAT_DATA->listenaddr = strdup(libtrace->uridata);
                FORMAT_DATA->listenport = strdup("37008");
	} else {
        	FORMAT_DATA->listenaddr = strndup(libtrace->uridata,
	        	(size_t)(scan - libtrace->uridata));
        	FORMAT_DATA->listenport = strdup(scan + 1);
        }

	FORMAT_DATA->socket = -1;

	FORMAT_DATA->buf = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
	if (FORMAT_DATA->buf == NULL) {
                trace_set_err(libtrace, TRACE_ERR_OUT_OF_MEMORY, "Unable "
                        "to allocate memory for format data in tzsplive_init_input()");
                free(libtrace->format_data);
                libtrace->format_data = NULL;
                return -1;
        }

	return 0;
}

static int tzsplive_init_output(libtrace_out_t *libtrace) {
	char *scan = NULL;

	libtrace->format_data = malloc(sizeof(tzsp_format_data_out_t));

	if (libtrace->format_data == NULL) {
		trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "Unable "
			"to allocate memory for format data in tzsp_init_output()");
		return -1;
	}

	scan = strchr(libtrace->uridata, ':');
        if (scan == NULL) {
                trace_set_err_out(libtrace, TRACE_ERR_BAD_FORMAT, "Bad tzsp "
                        "URI. Should be tzsplive:<listenaddr>:<listenport>");
		free(libtrace->format_data);
                return -1;
        }
        FORMAT_DATA_OUT->outaddr = strndup(libtrace->uridata,
                (size_t)(scan - libtrace->uridata));
        FORMAT_DATA_OUT->outport = strdup(scan + 1);

        FORMAT_DATA_OUT->outsocket = -1;

	FORMAT_DATA_OUT->buf = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
	if (FORMAT_DATA_OUT->buf == NULL) {
		trace_set_err_out(libtrace, TRACE_ERR_OUT_OF_MEMORY, "Unable "
			"to allocate memory for format data in tzsplive_init_output()");
		free(libtrace->format_data);
                libtrace->format_data = NULL;
		return -1;
	}

	return 0;
}

/* Called with trace_start */
static int tzsplive_start_input(libtrace_t *libtrace) {

	/* create the listener socket */
	if (tzsplive_create_socket(libtrace) < 0) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable to create"
			" listening socket");
		return -1;
	}

	return 1;
}

static int tzsplive_start_output(libtrace_out_t *libtrace) {

	/* create output socket */
	if (tzsplive_create_output_socket(libtrace) < 0) {
		trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "Unable to "
			"create output socket");
		return -1;
	}

	return 1;
}

static int tzsplive_pause_input(libtrace_t *libtrace UNUSED) {
	if (FORMAT_DATA->socket >= 0) {
		close(FORMAT_DATA->socket);
	}
	return 0;
}

static int tzsplive_fin_input(libtrace_t *libtrace) {
        if (!libtrace->format_data) {
                return 0;
        }

	if (FORMAT_DATA->listenaddr) {
		free(FORMAT_DATA->listenaddr);
	}
	if (FORMAT_DATA->listenport) {
		free(FORMAT_DATA->listenport);
	}
	if (FORMAT_DATA->socket >= 0) {
		close(FORMAT_DATA->socket);
	}
	if (FORMAT_DATA->buf) {
		free(FORMAT_DATA->buf);
	}
        free(libtrace->format_data);
	return 0;
}

static uint8_t *tzsplive_get_option(const libtrace_packet_t *packet, uint8_t option) {
	uint8_t *ptr = packet->buffer;

	/* Get the TZSP header */
        tzsp_header_t *hdr = (tzsp_header_t *)ptr;
        /* Ensure this is TZSP version 1 */
        if (hdr->version != 1) {
                trace_set_err(packet->trace, TRACE_ERR_UNSUPPORTED, "TZSP version %" PRIu8 " is"
                        " not supported\n", hdr->version);
                return NULL;
        }

        /* jump over TZSP header */
        ptr += sizeof(tzsp_header_t);

        /* get the tagged fields */
        tzsp_tagfield_t *tag = (tzsp_tagfield_t *)ptr;
        /* Jump over any padding or tagfields till the correct one is found */
        while (tag->type != option) {
		/* Option not found */
		if (tag->type == TZSP_TAG_END) {
			return NULL;
		}
                if (tag->type == TZSP_TAG_PADDING) {
                        /* jump over the padding */
                        ptr += sizeof(uint8_t);
                } else {
                        /* jump over the tag header and the data */
                        ptr += sizeof(tzsp_tagfield_t)+tag->length;
                }
                tag = (tzsp_tagfield_t *)ptr;
        }

        return ptr;
}

static uint8_t *tzsplive_get_packet_payload(const libtrace_packet_t *packet) {
        /* Get pointer to TZSP_TAG_END */
        uint8_t *ptr = tzsplive_get_option(packet, TZSP_TAG_END);

	/* All valid TZSP packets must contain TZSP_TAG_END, so if missing packet is
	 * invalid/corrupt */
	if (ptr == NULL) {
		fprintf(stderr, "Invalid TZSP packet in tzsplive_get_packet_payload()\n");
		return NULL;
	}

        /* Jump over the end tag to the payload */
        return ptr + sizeof(uint8_t);
}

static int tzsplive_insert_timestamp(libtrace_t *libtrace,
                libtrace_packet_t *packet, int pktlen) {
	struct timeval tv;
	tzsp_tagfield_t timestamp;
	uint8_t *ptr;
	int ret = 0;
        uint64_t timesafe;

	// Construct the tagfield
	timestamp.type = TZSP_LIBTRACE_CUSTOM_TAG_TIMEVAL;
	timestamp.length = sizeof(tv);

	// Get the current timestamp
	if ((ret = gettimeofday(&tv, NULL)) != 0) {
		return 0;
	}

	// Copy over the current packet
	memcpy(FORMAT_DATA->buf, packet->buffer, (size_t)pktlen);

	// pointer to begining of tagged fields
	ptr = packet->buffer + sizeof(tzsp_header_t);

        memmove((ptr + sizeof(tzsp_tagfield_t) + sizeof(timesafe) +
                sizeof(timesafe)), ptr, pktlen - sizeof(tzsp_header_t));

	// insert the timestamp tagfield header and value
	memcpy(ptr, &timestamp, sizeof(tzsp_tagfield_t));
	ptr += sizeof(tzsp_tagfield_t);

        timesafe = bswap_host_to_be64((uint64_t)(tv.tv_sec));
	memcpy(ptr, &(timesafe), sizeof(timesafe));
	ptr += sizeof(timesafe);
        timesafe = bswap_host_to_be64((uint64_t)(tv.tv_usec));
	memcpy(ptr, &(timesafe), sizeof(timesafe));
	ptr += sizeof(timesafe);

	return 1;
}

static int tzsplive_prepare_packet(libtrace_t *libtrace UNUSED, libtrace_packet_t *packet,
        void *buffer, libtrace_rt_types_t rt_type, uint32_t flags) {

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
        packet->payload = tzsplive_get_packet_payload(packet);

        return 0;
}

static int tzsplive_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	int ret;
	uint32_t flags = 0;

	if (!libtrace->format_data) {
		trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, "Trace format data missing, "
			"call trace_create() before calling trace_read_packet()");
		return -1;
	}

	if (!packet->buffer || packet->buf_control == TRACE_CTRL_EXTERNAL) {
                packet->buffer = malloc((size_t)LIBTRACE_PACKET_BUFSIZE);
		if (!packet->buffer) {
			trace_set_err(libtrace, errno, "Unable to allocate memory for "
				"packet buffer");
			return -1;
		}
	}
	flags |= TRACE_PREP_OWN_BUFFER;

	/* Make sure we shouldnt be halting */
	if ((ret = is_halted(libtrace)) != -1) {
		return ret;
	}
	/* Try read a packet from the socket */
	ret = recv(FORMAT_DATA->socket, packet->buffer, (size_t)LIBTRACE_PACKET_BUFSIZE,
		MSG_DONTWAIT);
	/* Error reading */
	if (ret == -1) {
		/* Nothing available to read */
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* sleep for a short period */
			usleep(100);
                        /* return and let libtrace check for new message in the
                         * message queue.
                         */
                        return READ_MESSAGE;
		}
		/* Socket error */
		trace_set_err(libtrace, TRACE_ERR_BAD_IO, "Error receiving on socket "
			"%d: %s", FORMAT_DATA->socket, strerror(errno));
		if (FORMAT_DATA->socket >= 0) {
			close(FORMAT_DATA->socket);
			FORMAT_DATA->socket = -1;
			return ret;
		}
	}

	if (ret < (int)sizeof(tzsp_header_t)) {
		trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Incomplete TZSP header");
		return -1;
	}

	/* insert the timestamp */
	tzsplive_insert_timestamp(libtrace, packet, ret);

	/* Cache the captured length */
        packet->cached.framing_length = trace_get_framing_length(packet);
        packet->cached.capture_length = ret;

	if (tzsplive_prepare_packet(libtrace, packet, packet->buffer,
		TRACE_RT_DATA_TZSP, flags)) {

		return -1;
	}

	return ret;
}

static int tzsplive_write_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	int ret = -1;
	int to_send = 0;
	int offset = 0;
	uint8_t *ptr;

	/* Check TZSP can write this packet */
	if (!tzsplive_can_write(packet)) {
		return 0;
	}

	if (!libtrace) {
		fprintf(stderr, "NULL trace passed into tzsplive_write_packet()\n");
		return -1;
	}
	if (!packet) {
		trace_set_err_out(libtrace, TRACE_ERR_NULL, "NULL packet passed into "
			"tzsplive_write_packet()");
		return -1;
	}

	/* If the packet is already TZSP strip libtrace timestamp and output */
	if (packet->trace->format->type == TRACE_FORMAT_TZSPLIVE) {

		/* strip out the timestamp inserted by libtrace */
        	/* copy over the tzsp header to the buffer */
        	memcpy(FORMAT_DATA_OUT->buf, packet->buffer, sizeof(tzsp_header_t));
        	ptr = FORMAT_DATA_OUT->buf + sizeof(tzsp_header_t);
       		/* offset after the timestamp to copy from */
        	offset = sizeof(tzsp_header_t) +
                	sizeof(tzsp_tagfield_t) +
                	sizeof(struct timeval);
		/* number of bytes after the timestamp to copy */
        	to_send = trace_get_capture_length(packet) +
                        	(trace_get_framing_length(packet)-offset);
        	/* copy the rest of the packet to the buffer */
        	memcpy(ptr, packet->buffer+offset, to_send);

		/* send the packet */
		ret = sendto(FORMAT_DATA_OUT->outsocket,
			FORMAT_DATA_OUT->buf,
			to_send,
			0,
			FORMAT_DATA_OUT->listenai->ai_addr,
			FORMAT_DATA_OUT->listenai->ai_addrlen);

	/* append the tzsp header to the begining of the packets payload */
	} else {

		/* construct the TZSP header */
		tzsp_header_t hdr;
		hdr.version = 1;
		hdr.type = 1;
		hdr.encap = htons(libtrace_to_tzsp_type(trace_get_link_type(packet)));

		tzsp_tagfield_t rx_frame;
		rx_frame.type = TZSP_TAG_RX_FRAME_LENGTH;
		rx_frame.length = 2;
		uint16_t rx_val = htons(trace_get_wire_length(packet));

		uint8_t tag_end = 1;

		/* Account for TZSP header and capture length */
		to_send = sizeof(tzsp_header_t) +
			  sizeof(rx_frame) +
			  sizeof(rx_val) +
		  	  sizeof(tag_end) +
		  	  trace_get_capture_length(packet);

		/* Copy TZSP header to buffer */
		memcpy(FORMAT_DATA_OUT->buf, &hdr, sizeof(tzsp_header_t));
		offset += sizeof(tzsp_header_t);
		memcpy(FORMAT_DATA_OUT->buf + offset, &rx_frame, sizeof(rx_frame));
		offset += sizeof(rx_frame);
		memcpy(FORMAT_DATA_OUT->buf + offset, &rx_val, sizeof(rx_val));
		offset += sizeof(rx_val);
		memcpy(FORMAT_DATA_OUT->buf + offset, &tag_end, sizeof(tag_end));
		offset += sizeof(tag_end);
		/* Copy packet payload to buffer */
		memcpy(FORMAT_DATA_OUT->buf + offset, packet->payload, trace_get_capture_length(packet));

		/* send the packet */
		ret = sendto(FORMAT_DATA_OUT->outsocket,
			FORMAT_DATA_OUT->buf,
			to_send,
                        0,
                        FORMAT_DATA_OUT->listenai->ai_addr,
                        FORMAT_DATA_OUT->listenai->ai_addrlen);
	}

	/* Check if expected number of bytes was sent */
        if (ret != to_send) {
        	trace_set_err_out(libtrace, TRACE_ERR_BAD_IO,
                	"Error sending on socket %d: %s",
                        FORMAT_DATA_OUT->outsocket, strerror(errno));
        }

        return ret;
}

static int tzsplive_fin_output(libtrace_out_t *libtrace) {
	if (FORMAT_DATA_OUT->outaddr) {
                free(FORMAT_DATA_OUT->outaddr);
        }
        if (FORMAT_DATA_OUT->outport) {
                free(FORMAT_DATA_OUT->outport);
        }
        if (FORMAT_DATA_OUT->outsocket >= 0) {
                close(FORMAT_DATA_OUT->outsocket);
        }
	if (FORMAT_DATA_OUT->listenai) {
		freeaddrinfo(FORMAT_DATA_OUT->listenai);
	}
	if (FORMAT_DATA_OUT->buf) {
		free(FORMAT_DATA_OUT->buf);
	}
        free(libtrace->format_data);
	return 0;
}

static libtrace_linktype_t tzsplive_get_link_type(const libtrace_packet_t *packet) {
	if (packet->header == NULL) {
		return ~0;
	}

	tzsp_header_t *hdr = (tzsp_header_t *)packet->header;
	switch (ntohs(hdr->encap)) {
		case (TZSP_ENCAP_ETHERNET): return TRACE_TYPE_ETH;
		case (TZSP_ENCAP_TOKEN_RING): return TRACE_TYPE_UNKNOWN;
		case (TZSP_ENCAP_SLIP): return TRACE_TYPE_UNKNOWN;
		case (TZSP_ENCAP_PPP): return TRACE_TYPE_PPP;
		case (TZSP_ENCAP_FDDI): return TRACE_TYPE_UNKNOWN;
		case (TZSP_ENCAP_RAW): return TRACE_TYPE_NONE;
		case (TZSP_ENCAP_80211): return TRACE_TYPE_80211;
		case (TZSP_ENCAP_80211_PRISM): return TRACE_TYPE_80211_PRISM;
		case (TZSP_ENCAP_80211_AVS): return TRACE_TYPE_UNKNOWN;
		default: return TRACE_TYPE_UNKNOWN;
	}
}

static struct timeval tzsplive_get_timeval(const libtrace_packet_t *packet) {
	uint8_t *ptr;
	struct timeval tv;

	if ((ptr = tzsplive_get_option(packet,
                        TZSP_LIBTRACE_CUSTOM_TAG_TIMEVAL)) != NULL) {
                ptr += sizeof(tzsp_tagfield_t);

		tv.tv_sec = (uint32_t)bswap_be_to_host64(*(uint64_t *)ptr);
                ptr += sizeof(uint64_t);
                tv.tv_usec = (uint32_t)bswap_be_to_host64(*(uint64_t *)ptr);
	} else if ((ptr = tzsplive_get_option(packet,
                        TZSP_TAG_TIMESTAMP)) != NULL) {
                /* fall back to the crappy 32 bit timestamp if present */
                ptr += sizeof(tzsp_tagfield_t);
                tv.tv_sec = ntohl(*(uint32_t *)ptr);
                tv.tv_usec = 0;
        } else{
		tv.tv_sec = 0;
		tv.tv_usec = 0;
	}
	return tv;
}

static int tzsplive_get_capture_length(const libtrace_packet_t *packet) {
	return packet->cached.capture_length;
}
static int tzsplive_get_wire_length(const libtrace_packet_t *packet) {
	uint8_t *ptr;
	if ((ptr = tzsplive_get_option(packet, TZSP_TAG_RX_FRAME_LENGTH)) != NULL) {
		/* jump to the value */
		ptr += sizeof(tzsp_tagfield_t);
		return ntohs(*(uint16_t *)ptr);
	} else {
		/* Fallback to the captured length */
		return trace_get_capture_length(packet);
	}
}
static int tzsplive_get_framing_length(const libtrace_packet_t *packet) {

	uint8_t *payload = tzsplive_get_packet_payload(packet);

	if (payload != NULL) {
		return payload - (uint8_t *)packet->buffer;
	} else {
		return 0;
	}
}

static struct libtrace_format_t tzsplive = {
        "tzsplive",
        "$Id$",
        TRACE_FORMAT_TZSPLIVE,
        NULL,                           /* probe filename */
        NULL,                           /* probe magic */
        tzsplive_init_input,            /* init_input */
        NULL,			        /* config_input */
        tzsplive_start_input,           /* start_input */
        tzsplive_pause_input,           /* pause */
        tzsplive_init_output,           /* init_output */
        NULL,                           /* config_output */
        tzsplive_start_output,          /* start_output */
        tzsplive_fin_input,             /* fin_input */
        tzsplive_fin_output,            /* fin_output */
        tzsplive_read_packet,           /* read_packet */
        tzsplive_prepare_packet,        /* prepare_packet */
        NULL,                           /* fin_packet */
        tzsplive_write_packet,          /* write_packet */
        NULL,                           /* flush_output */
        tzsplive_get_link_type,         /* get_link_type */
        NULL,                           /* get_direction */
        NULL,                           /* set_direction */
        NULL,			        /* get_erf_timestamp */
        tzsplive_get_timeval,           /* get_timeval */
        NULL,                           /* get_timespec */
        NULL,                           /* get_seconds */
	NULL,				/* get_meta_section */
        NULL,                           /* seek_erf */
        NULL,                           /* seek_timeval */
        NULL,                           /* seek_seconds */
        tzsplive_get_capture_length,    /* get_capture_length */
        tzsplive_get_wire_length,       /* get_wire_length */
        tzsplive_get_framing_length,    /* get_framing_length */
        NULL,                           /* set_capture_length */
        NULL,                           /* get_received_packets */
	NULL,                           /* get_filtered_packets */
        NULL,                           /* get_dropped_packets */
        NULL,                           /* get_statistics */
        NULL,                           /* get_fd */
        NULL,				/* trace_event */
        NULL,                           /* help */
        NULL,                           /* next pointer */
        NON_PARALLEL(true)
};

void tzsplive_constructor(void) {
	register_format(&tzsplive);
}
