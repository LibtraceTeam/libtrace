#include "libtrace.h"
#include "libtrace_int.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FORMAT_DATA ((tzsp_format_data_t *)libtrace->format_data)
#define FORMAT_DATA_OUT ((tzsp_format_data_out_t *)libtrace->format_data)

/* Packet types */
#define TZSP_TYPE_RX 0
#define TZSP_TYPE_TX 1
#define TZSP_TYPE_RESV 2
#define TZSP_TYPE_CONF 3
#define TZSP_TYPE_KEPT_ALIVE 4
#define TZSP_TYPE_PORT 5

/* Encapsulation types */
#define TZSP_ENCAP_ETHERNET 1
#define TZSP_ENCAP_TOKEN_RING 2
#define TZSP_ENCAP_SLIP 3
#define TZSP_ENCAP_PPP 4
#define TZSP_ENCAP_FDDI 5
#define TZSP_ENCAP_RAW 7
#define TZSP_ENCAP_80211 18
#define TZSP_ENCAP_80211_PRISM 119
#define TZSP_ENCAP_80211_AVS 127

/* Tag fields */
#define TZSP_TAG_PADDING 0
#define TZSP_TAG_END 1
#define TZSP_TAG_RAW_RSSI 10
#define TZSP_TAG_SNR 11
#define TZSP_TAG_DATE_RATE 12
#define TZSP_TAG_TIMESTAMP 13
#define TZSP_TAG_CONTENTION_FREE 15
#define TZSP_TAG_DECRYPTED 16
#define TZSP_TAG_FCS_ERROR 17
#define TZSP_TAG_RX_CHANNEL 18
#define TZSP_TAG_PACKET_COUNT 40
#define TZSP_TAG_RX_FRAME_LENGTH 41
#define TZSP_TAG_WLAN_RADIO_HDR_SERIAL 60

typedef struct tzsp_format_data {
	char *listenaddr;
	char *listenport;

	int socket;
} tzsp_format_data_t;

typedef struct tzsp_format_data_out {
	char *outaddr;
	char *outport;

	int outsocket;
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

static int tzsplive_create_socket(libtrace_t *libtrace) {
	struct addrinfo hints, *listenai;
	int reuse = 1;

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
	struct addrinfo hints, *listenai;
        int reuse = 1;

        hints.ai_family = PF_UNSPEC;
        /* UDP socket */
        hints.ai_socktype = SOCK_DGRAM;
        /* listen for connections */
        hints.ai_flags = AI_PASSIVE;
        hints.ai_protocol = 0;

        listenai = NULL;

	if (getaddrinfo(FORMAT_DATA_OUT->outaddr, FORMAT_DATA_OUT->outport,
                &hints, &listenai) != 0) {

                fprintf(stderr, "Call to getaddrinfo failed for %s:%s -- %s\n",
                        FORMAT_DATA_OUT->outaddr, FORMAT_DATA_OUT->outport,
                        strerror(errno));
                goto listenerror;
        }

	FORMAT_DATA_OUT->outsocket = socket(listenai->ai_family, listenai->ai_socktype, 0);
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

	freeaddrinfo(listenai);
        return 1;

listenerror:
        trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "Unable to create output "
                "socket for tzsplive");
        freeaddrinfo(listenai);
        return -1;
}

/* called with trace_create */
static int tzsplive_init_input(libtrace_t *libtrace) {
	char *scan = NULL;

	libtrace->format_data = (tzsp_format_data_t *)malloc(
		sizeof(tzsp_format_data_t));

	if (libtrace->format_data == NULL) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable "
			"to allocate memory for format data inside tzsp_init_input();");
		return -1;
	}

	scan = strchr(libtrace->uridata, ':');
	if (scan == NULL) {
		trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, "Bad tzsp "
			"URI. Should be tzsplive:<listenaddr>:<listenport>");
		return -1;
	}
	FORMAT_DATA->listenaddr = strndup(libtrace->uridata,
		(size_t)(scan - libtrace->uridata));
	FORMAT_DATA->listenport = strdup(scan + 1);

	FORMAT_DATA->socket = -1;

	return 0;
}

static int tzsplive_init_output(libtrace_out_t *libtrace) {
	char *scan = NULL;

	libtrace->format_data = malloc(sizeof(tzsp_format_data_out_t));

	if (libtrace->format_data == NULL) {
		trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "Unable "
			"to allocate memory for format data inside tzsp_init_output()");
		return -1;
	}

	scan = strchr(libtrace->uridata, ':');
        if (scan == NULL) {
                trace_set_err_out(libtrace, TRACE_ERR_BAD_FORMAT, "Bad tzsp "
                        "URI. Should be tzsplive:<listenaddr>:<listenport>");
                return -1;
        }
        FORMAT_DATA_OUT->outaddr = strndup(libtrace->uridata,
                (size_t)(scan - libtrace->uridata));
        FORMAT_DATA_OUT->outport = strdup(scan + 1);

        FORMAT_DATA_OUT->outsocket = -1;

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
	if (FORMAT_DATA->listenaddr) {
		free(FORMAT_DATA->listenaddr);
	}
	if (FORMAT_DATA->listenport) {
		free(FORMAT_DATA->listenport);
	}
	if (FORMAT_DATA->socket >= 0) {
		close(FORMAT_DATA->socket);
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
                        ptr += sizeof(uint16_t)+tag->length;
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

readagain:
	/* Try read a packet from the socket */
	ret = recv(FORMAT_DATA->socket, packet->buffer, (size_t)LIBTRACE_PACKET_BUFSIZE,
		MSG_DONTWAIT);
	/* Error reading */
	if (ret == -1) {
		/* Nothing available to read */
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			goto readagain;
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

	if (tzsplive_prepare_packet(libtrace, packet, packet->buffer,
		TRACE_RT_DATA_TZSP, flags)) {

		return -1;
	}

	return ret;
}

static int tzsplive_write_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	//int ret = 0;

	if (!libtrace) {
		fprintf(stderr, "NULL trace passed into tzsplive_write_packet()\n");
		return -1;
	}
	if (!packet) {
		trace_set_err_out(libtrace, TRACE_ERR_NULL, "NULL packet passed into "
			"tzsplive_write_packet()");
		return -1;
	}

	/* We cannot write packets until we find a way to get the capture/wire length if
	 * the tag is not present in the tzsp header */

	return -1;
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

static uint64_t tzsplive_get_erf_timestamp(const libtrace_packet_t *packet UNUSED) {
	return 0;
}

static int tzsplive_get_capture_length(const libtrace_packet_t *packet) {
	return trace_get_wire_length(packet);
}
static int tzsplive_get_wire_length(const libtrace_packet_t *packet) {
	uint8_t *ptr;
	if ((ptr = tzsplive_get_option(packet, TZSP_TAG_RX_FRAME_LENGTH)) != NULL) {
		/* jump to the value */
		ptr += sizeof(uint16_t);
		return *(uint16_t *)ptr;
	} else {
		/* could do something else here to try find the wire length?? */
		return  0;
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
        tzsplive_get_erf_timestamp,     /* get_erf_timestamp */
        NULL,                           /* get_timeval */
        NULL,                           /* get_timespec */
        NULL,                           /* get_seconds */
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
