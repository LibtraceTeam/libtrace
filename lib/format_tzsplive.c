#include "libtrace.h"
#include "libtrace_int.h"
#include "data-struct/simple_circular_buffer.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FORMAT_DATA ((tzsp_format_data_t *)libtrace->format_data)

#define TZSP_RECVBUF_SIZE (64 * 1024 * 1024)

typedef struct tzsp_format_data {
	char *listenaddr;
	char *listenport;

	pthread_t listenthread;
	libtrace_scb_t *recvbuffer;

} tzsp_format_data_t;

typedef struct tzsp_header {
	uint8_t version;
	uint8_t type;
	
	
} PACKED tzsp_header_t;

static void *tzsplive_listener(void *data) {
	libtrace_t *libtrace = (libtrace_t *)data;

	struct addrinfo hints, *listenai;
	int sock;
	int reuse = 1;

	hints.ai_family = PF_UNSPEC;
	/* UDP socket */
	hints.ai_socktype = SOCK_DGRAM;
	/* listen for connections */
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;

	sock = -1;
	listenai = NULL;

	if (getaddrinfo(FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
		&hints, &listenai) != 0) {

		fprintf(stderr, "Call to getaddrinfo failed for %s:%s -- %s\n",
			FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
			strerror(errno));
		goto listenerror;
	}

	sock = socket(listenai->ai_family, listenai->ai_socktype, 0);
	if (sock < 0) {
		fprintf(stderr, "Failed to create socket for %s:%s -- %s\n",
			FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
			strerror(errno));
		goto listenerror;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		fprintf(stderr, "Failed to configure socket for %s:%s -- %s\n",
			FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
			strerror(errno));
		goto listenerror;
	}

	if (bind(sock, (struct sockaddr *)listenai->ai_addr, listenai->ai_addrlen) < 0) {
		fprintf(stderr, "Failed to bind socket for %s:%s -- %s\n",
			FORMAT_DATA->listenaddr, FORMAT_DATA->listenport,
			strerror(errno));
		goto listenerror;
	}

	freeaddrinfo(listenai);

	while (is_halted(libtrace) == -1) {
		char *buff[1500];
		//libtrace_scb_recv_sock(FORMAT_DATA->recvbuffer, sock, 0);
		size_t c = recv(sock, buff, sizeof(buff), 0);
		fprintf(stderr, "Got packet %d bytes\n", (int)c);
	}

	goto listenshutdown;

listenerror:
	trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable to create "
		"listening socket for tzsp");

listenshutdown:
	if (sock >= 0) {
		close(sock);
	}
	if (listenai) {
		freeaddrinfo(listenai);
	}
	pthread_exit(NULL);
}

/* called with trace_create */
static int tzsplive_init_input(libtrace_t *libtrace) {
	char *scan = NULL;

	libtrace->format_data = (tzsp_format_data_t *)malloc(
		sizeof(tzsp_format_data_t));

	if (libtrace->format_data) {
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

	return 0;
}

/* Called with trace_start */
static int tzsplive_start_input(libtrace_t *libtrace) {
	int ret;

	/* Setup the queue */
	libtrace_scb_init(FORMAT_DATA->recvbuffer, TZSP_RECVBUF_SIZE, 0);

	/* Start the listening thread */
	ret = pthread_create(&(FORMAT_DATA->listenthread), NULL,
		tzsplive_listener, libtrace);

	if (ret != 0) {
		return -1;
	}

	return 1;
}

static int tzsplive_pause_input(libtrace_t *libtrace UNUSED) {
	return 0;
}

static int tzsplive_fin_input(libtrace_t *libtrace) {
	if (FORMAT_DATA->listenaddr) {
		free(FORMAT_DATA->listenaddr);
	}
	if (FORMAT_DATA->listenport) {
		free(FORMAT_DATA->listenport);
	}
	free(libtrace->format_data);
	return 0;
}

static int tzsplive_read_packet(libtrace_t *libtrace UNUSED, libtrace_packet_t *packet UNUSED) {
	return 0;
}

static int tzsplive_prepare_packet(libtrace_t *libtrace UNUSED, libtrace_packet_t *packet UNUSED,
	void *buffer UNUSED, libtrace_rt_types_t rt_type UNUSED, uint32_t flags UNUSED) {

	return 0;
}

static libtrace_linktype_t tzsplive_get_link_type(const libtrace_packet_t *packet UNUSED) {
	return TRACE_TYPE_TZSP;
}

static uint64_t tzsplive_get_erf_timestamp(const libtrace_packet_t *packet UNUSED) {
	return 0;
}

static int tzsplive_get_pdu_length(const libtrace_packet_t *packet UNUSED) {
	return 0;
}
static int tzsplive_get_framing_length(const libtrace_packet_t *packet UNUSED) {
	return 0;
}


static struct libtrace_format_t tzsplive = {
        "tzsplive",
        "$Id$",
        TRACE_FORMAT_TZSPLIVE,
        NULL,                           /* probe filename */
        NULL,                           /* probe magic */
        tzsplive_init_input,            /* init_input */
        NULL,                           /* config_input */
        tzsplive_start_input,           /* start_input */
        tzsplive_pause_input,           /* pause */
        NULL,                           /* init_output */
        NULL,                           /* config_output */
        NULL,                           /* start_output */
        tzsplive_fin_input,             /* fin_input */
        NULL,                           /* fin_output */
        tzsplive_read_packet,           /* read_packet */
        tzsplive_prepare_packet,        /* prepare_packet */
        NULL,                           /* fin_packet */
        NULL,                           /* write_packet */
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
        tzsplive_get_pdu_length,       /* get_capture_length */
        tzsplive_get_pdu_length,       /* get_wire_length */
        tzsplive_get_framing_length,    /* get_framing_length */
        NULL,                           /* set_capture_length */
        NULL,                           /* get_received_packets */
	NULL,                           /* get_filtered_packets */
        NULL,                           /* get_dropped_packets */
        NULL,                           /* get_statistics */
        NULL,                           /* get_fd */
        NULL, //trace_event_etsilive,           /* trace_event */
        NULL,                           /* help */
        NULL,                           /* next pointer */
        NON_PARALLEL(true)              /* TODO this can be parallel */
};

void tzsplive_constructor(void) {
	register_format(&tzsplive);
}
