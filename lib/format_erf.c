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
#define _GNU_SOURCE

#include "config.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "parse_cmd.h"

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
#  error "Can't find inttypes.h - this needs to be fixed"
#endif 

#ifdef HAVE_STDDEF_H
#  include <stddef.h>
#else
# error "Can't find stddef.h - do you define ptrdiff_t elsewhere?"
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Catch undefined O_LARGEFILE on *BSD etc */
#ifndef O_LARGEFILE
#  define O_LARGEFILE 0
#endif 

static struct libtrace_format_t *erf_ptr = 0;
static struct libtrace_format_t *rtclient_ptr = 0;
#if HAVE_DAG
static struct libtrace_format_t *dag_ptr = 0;
#endif 
static struct libtrace_format_t *legacypos_ptr = 0;
static struct libtrace_format_t *legacyeth_ptr = 0;
static struct libtrace_format_t *legacyatm_ptr = 0;

#define CONNINFO libtrace->format_data->conn_info
#define INPUT libtrace->format_data->input
#define OUTPUT libtrace->format_data->output
#if HAVE_DAG
#define DAG libtrace->format_data->dag
#endif
#define OPTIONS libtrace->format_data->options
struct libtrace_format_data_t {
	union {
                struct {
                        char *hostname;
                        short port;
                } rt;
                char *path;		
        } conn_info;
        
	union {
                int fd;
#if HAVE_ZLIB
                gzFile *file;
#else	
		FILE *file;
#endif
        } input;

#if HAVE_DAG
	struct {
		void *buf; 
		unsigned bottom;
		unsigned top;
		unsigned diff;
		unsigned curr;
		unsigned offset;
	} dag;
#endif
};

struct libtrace_format_data_out_t {
        union {
                struct {
                        char *hostname;
                        short port;
                } rt;
                char *path;
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
        } output;
};

#ifdef HAVE_DAG
static int dag_init_input(struct libtrace_t *libtrace) {
	struct stat buf;
	libtrace->format_data = (struct libtrace_format_data_t *)
		malloc(sizeof(struct libtrace_format_data_t));

	CONNINFO.path = libtrace->uridata;
	if (stat(CONNINFO.path,&buf) == -1) {
		perror("stat");
		return 0;
	} 
	if (S_ISCHR(buf.st_mode)) {
		// DEVICE
		libtrace->sourcetype = DEVICE;
		if((INPUT.fd = dag_open(CONNINFO.path)) < 0) {
			fprintf(stderr,"Cannot open DAG %s: %m\n", 
					CONNINFO.path,errno);
			exit(0);
		}
		if((DAG.buf = (void *)dag_mmap(INPUT.fd)) == MAP_FAILED) {
			fprintf(stderr,"Cannot mmap DAG %s: %m\n", 
					CONNINFO.path,errno);
			exit(0);
		}
		if(dag_start(INPUT.fd) < 0) {
			fprintf(stderr,"Cannot start DAG %s: %m\n", 
					CONNINFO.path,errno);
			exit(0);
		}
	} else {
		fprintf(stderr,"%s isn't a valid char device, exiting\n",
				CONNINFO.path);
		return 0;
	}
	return 1;
}
#endif

static int erf_init_input(struct libtrace_t *libtrace) {
	struct stat buf;
	struct sockaddr_un unix_sock;
	libtrace->format_data = (struct libtrace_format_data_t *)
		malloc(sizeof(struct libtrace_format_data_t));

	CONNINFO.path = libtrace->uridata;
	if (!strncmp(CONNINFO.path,"-",1)) {
		// STDIN
		libtrace->sourcetype = STDIN;
#if HAVE_ZLIB
		INPUT.file = gzdopen(STDIN, "r");
#else	
		INPUT.file = stdin;
#endif

	} else {
		if (stat(CONNINFO.path,&buf) == -1 ) {
			perror("stat");
			return 0;
		}
		if (S_ISSOCK(buf.st_mode)) {
			libtrace->sourcetype = SOCKET;
			if ((INPUT.fd = socket(
					AF_UNIX, SOCK_STREAM, 0)) == -1) {
				perror("socket");
				return 0;
			}
			unix_sock.sun_family = AF_UNIX;
			bzero(unix_sock.sun_path,108);
			snprintf(unix_sock.sun_path,
					108,"%s"
					,CONNINFO.path);

			if (connect(INPUT.fd, 
					(struct sockaddr *)&unix_sock,
					sizeof(struct sockaddr)) == -1) {
				perror("connect (unix)");
				return 0;
			}
		} else { 
			libtrace->sourcetype = TRACE;
#if HAVE_ZLIB
			// using gzdopen means we can set O_LARGEFILE
			// ourselves. However, this way is messy and 
			// we lose any error checking on "open"
			INPUT.file = 
				gzdopen(open(
					CONNINFO.path,
					O_LARGEFILE), "r");
#else
			INPUT.file = 
				fdopen(open(
					CONNINFO.path,
					O_LARGEFILE), "r");
#endif

		}
	}
	return 1;
}

static int rtclient_init_input(struct libtrace_t *libtrace) {
	char *scan;
	char *uridata = libtrace->uridata;
	struct hostent *he;
	struct sockaddr_in remote;
	libtrace->format_data = (struct libtrace_format_data_t *)
		malloc(sizeof(struct libtrace_format_data_t));

	libtrace->sourcetype = RT;

	if (strlen(uridata) == 0) {
		CONNINFO.rt.hostname = 
			strdup("localhost");
		CONNINFO.rt.port = 
			COLLECTOR_PORT;
	} else {
		if ((scan = strchr(uridata,':')) == NULL) {
			CONNINFO.rt.hostname = 
				strdup(uridata);
			CONNINFO.rt.port =
				COLLECTOR_PORT;
		} else {
			CONNINFO.rt.hostname = 
				(char *)strndup(uridata,
						(scan - uridata));
			CONNINFO.rt.port = 
				atoi(++scan);
		}
	}
	
	if ((he=gethostbyname(CONNINFO.rt.hostname)) == NULL) {  
		perror("gethostbyname");
		return 0;
	} 
	if ((INPUT.fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		return 0;
	}

	remote.sin_family = AF_INET;   
	remote.sin_port = htons(CONNINFO.rt.port);
	remote.sin_addr = *((struct in_addr *)he->h_addr);
	bzero(&(remote.sin_zero), 8);

	if (connect(INPUT.fd, (struct sockaddr *)&remote,
				sizeof(struct sockaddr)) == -1) {
		perror("connect (inet)");
		return 0;
	}
	return 1;
}

static int erf_init_output(struct libtrace_out_t *libtrace) {
	char *filemode = 0;
	int fd;
	libtrace->format_data = (struct libtrace_format_data_out_t *)
		calloc(1,sizeof(struct libtrace_format_data_out_t));

	OPTIONS.erf.level = 0;
	asprintf(&filemode,"wb%d",OPTIONS.erf.level);

        if (!strncmp(libtrace->uridata,"-",1)) {
                // STDOUT
#if HAVE_ZLIB
                OUTPUT.file = gzdopen(dup(1), filemode);
#else
                OUTPUT.file = stdout;
#endif
	}
	else {
	        // TRACE
		fd = open(libtrace->uridata, O_CREAT | O_LARGEFILE | O_WRONLY, S_IRUSR | S_IWUSR);
		if (fd <= 0) {
			return 0;
		}
#if HAVE_ZLIB
                // using gzdopen means we can set O_LARGEFILE
                // ourselves. However, this way is messy and
                // we lose any error checking on "open"
                OUTPUT.file =  gzdopen(fd, filemode);
#else
		OUTPUT.file =  fdopen(fd, "w");
#endif
		 
	}
	free(filemode);	
	return 1;
}

static int erf_config_output(struct libtrace_out_t *libtrace, int argc, char *argv[]) {
#if HAVE_ZLIB
	int opt;
	int level = OPTIONS.erf.level;
	optind = 1;


	while ((opt = getopt(argc, argv, "z:")) != EOF) {
		switch (opt) {
			case 'z':
				level = atoi(optarg);
				break;
			default:
				printf("Bad argument to erf: %s\n", optarg);
				// maybe spit out some help here
				return -1;
		}
	}
	if (level != OPTIONS.erf.level) {
		if (level > 9 || level < 0) {
			// retarded level choice
			printf("Compression level must be between 0 and 9 inclusive - you selected %i \n", level);
			
		} else {
			OPTIONS.erf.level = level;
			return gzsetparams(OUTPUT.file, level, Z_DEFAULT_STRATEGY);
		}
	}
#endif
	return 0;

}


#ifdef HAVE_DAG
static int dag_fin_input(struct libtrace_t *libtrace) {
	dag_stop(INPUT.fd);
}
#endif

static int erf_fin_input(struct libtrace_t *libtrace) {
#if HAVE_ZLIB
	gzclose(INPUT.file);
#else	
	fclose(INPUT.file);	
#endif
	free(libtrace->format_data);
	return 0;
}

static int rtclient_fin_input(struct libtrace_t *libtrace) {
	close(INPUT.fd);
	return 0;
}

static int erf_fin_output(struct libtrace_out_t *libtrace) {
#if HAVE_ZLIB
        gzclose(OUTPUT.file);
#else
        fclose(OUTPUT.file);
#endif
	free(libtrace->format_data);

	return 0;
}
 


#if HAVE_DAG
static int dag_read(struct libtrace_t *libtrace, void *buffer, size_t len) {
	int numbytes;
	static short lctr = 0;
	struct dag_record_t *erfptr = 0;
	int rlen;

	if (buffer == 0)
		buffer = malloc(len);
	
	DAG.bottom = DAG.top;
	DAG.top = dag_offset(
			INPUT.fd,
			&(DAG.bottom),
			0);
	DAG.diff = DAG.top -
		DAG.bottom;

	numbytes=DAG.diff;
	DAG.offset = 0;
	return numbytes;
}
#endif

#if HAVE_DAG
static int dag_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes;
	int size;
	char buf[RP_BUFSIZE];
	dag_record_t *erfptr;
	void *buffer = packet->buffer;
	void *buffer2 = buffer;
	int rlen;
	
	if (DAG.diff == 0) {
		if ((numbytes = dag_read(libtrace,buf,RP_BUFSIZE)) <= 0) 
			return numbytes;
	}

	//DAG always gives us whole packets
	erfptr = (dag_record_t *) ((void *)DAG.buf + 
			(DAG.bottom + DAG.offset));
	size = ntohs(erfptr->rlen);

	if ( size  > LIBTRACE_PACKET_BUFSIZE) {
		assert( size < LIBTRACE_PACKET_BUFSIZE);
	}

	// have to copy it out of the memory hole at this stage:
	memcpy(packet->buffer, erfptr, size);
	
	packet->status = 0;
	packet->size = size;
	DAG.offset += size;
	DAG.diff -= size;

	assert(DAG.diff >= 0);

	return (size);
}
#endif

static int legacy_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes;
	int size;
	void *buffer = packet->buffer;
	void *buffer2 = buffer;
	dag_record_t *erfptr = (dag_record_t *)buffer;
	int rlen;

#if HAVE_ZLIB
	if ((numbytes=gzread(INPUT.file,
					buffer,
					dag_record_size)) == -1) {
		perror("gzread");
		return -1;
	}
#else
	if ((numbytes = read(INPUT.file, buffer, dag_record_size)) == -1) {
		perror("read");
		return -1;
	}
#endif
	if (numbytes == 0) {
		return 0;
	}

	// legacy - 64byte captures
	// type is TYPE_LEGACY
	rlen = 64;
	size = rlen - dag_record_size;
	buffer2 = buffer + dag_record_size;
	
#ifdef HAVE_ZLIB
	if ((numbytes=gzread(INPUT.file,
					buffer2,
					size)) == -1) {
		perror("gzread");
		return -1;
	}
#else
	if ((numbytes = read(INPUT.file,buffer2,size)) == -1) {
		perror("gzread");
		return -1;
	}
#endif
	packet->status = 0;
	packet->size = rlen;
	return rlen;
}
static int erf_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes;
	int size;
	void *buffer = packet->buffer;
	void *buffer2 = buffer;
	int rlen;
#if HAVE_ZLIB
	if ((numbytes=gzread(INPUT.file,
					buffer,
					dag_record_size)) == -1) {
		perror("gzread");
		return -1;
	}
#else
	if ((numbytes = read(INPUT.file, buffer, dag_record_size)) == -1) {
		perror("read");
		return -1;
	}
#endif
	if (numbytes == 0) {
		return 0;
	}
	rlen = ntohs(((dag_record_t *)buffer)->rlen);
	size = rlen - dag_record_size;
	assert(size < LIBTRACE_PACKET_BUFSIZE);
	buffer2 = buffer + dag_record_size;
	
	// read in the rest of the packet
#ifdef HAVE_ZLIB
	if ((numbytes=gzread(INPUT.file,
					buffer2,
					size)) == -1) {
		perror("gzread");
		return -1;
	}
#else
	if ((numbytes = read(INPUT.file,buffer2,size)) == -1) {
		perror("gzread");
		return -1;
	}
#endif
	packet->status = 0;
	packet->size = rlen;
	return rlen;
}

static int rtclient_read(struct libtrace_t *libtrace, void *buffer, size_t len) {
	int numbytes;

	if (buffer == 0)
		buffer = malloc(len);
	while(1) {
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif
		if ((numbytes = recv(INPUT.fd,
						buffer,
						len,
						MSG_NOSIGNAL)) == -1) {
			if (errno == EINTR) {
				//ignore EINTR in case
				// a caller is using signals
				continue;
			}
			perror("recv");
			return -1;
		}
		break;

	}
	return numbytes;
}

static int rtclient_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes = 0;
	int size = 0;
	char buf[RP_BUFSIZE];
	int read_required = 0;
	
	void *buffer = 0;

	packet->trace = libtrace;
	buffer = packet->buffer;

	do {
		if (tracefifo_out_available(libtrace->fifo) == 0 || read_required) {
			if ((numbytes = rtclient_read(
					libtrace,buf,RP_BUFSIZE))<=0) {
				return numbytes;
			}
			tracefifo_write(libtrace->fifo,buf,numbytes);
			read_required = 0;
		}
		// Read status byte
		if (tracefifo_out_read(libtrace->fifo,
				&packet->status, sizeof(int)) == 0) {
			read_required = 1;
			continue;
		}
		tracefifo_out_update(libtrace->fifo,sizeof(int));

		// read in the ERF header
		if ((numbytes = tracefifo_out_read(libtrace->fifo, buffer,
						sizeof(dag_record_t))) == 0) {
			tracefifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}
		size = ntohs(((dag_record_t *)buffer)->rlen);
		
		// read in the full packet
		if ((numbytes = tracefifo_out_read(libtrace->fifo, 
						buffer, size)) == 0) {
			tracefifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}

		// got in our whole packet, so...
		tracefifo_out_update(libtrace->fifo,size);

		tracefifo_ack_update(libtrace->fifo,size + sizeof(int));

		packet->size = numbytes;
		return numbytes;
	} while(1);
}

static int erf_dump_packet(struct libtrace_out_t *libtrace, dag_record_t *erfptr, void *buffer, size_t size) {
	int numbytes = 0;
#if HAVE_ZLIB
	if ((numbytes = gzwrite(OUTPUT.file, erfptr, dag_record_size + 2)) == 0) {
		perror("gzwrite");
		return -1;
	}
	if ((numbytes = gzwrite(OUTPUT.file, buffer, size)) == 0) {
		perror("gzwrite");
		return -1;
	}
#else
	if ((numbytes = write(OUTPUT.file, erfptr, dag_record_size + 2)) == 0) {
		perror("write");
		return -1;
	}
	if ((numbytes = write(OUTPUT.file, buffer, size)) == 0) {
		perror("write");
		return -1;
	}
#endif
	return numbytes + sizeof(dag_record_t);

}
		
static int erf_write_packet(struct libtrace_out_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes = 0;
	dag_record_t erfhdr;
	void *payload = (void *)trace_get_link(packet);

	if (packet->trace->format == erf_ptr || 
#if HAVE_DAG
			packet->trace->format == dag_ptr ||
#endif
			packet->trace->format == rtclient_ptr ) {
		numbytes = erf_dump_packet(libtrace,
				(dag_record_t *)packet->buffer,
				payload,
				packet->size - 
					(dag_record_size + 2)); 
	} else {
		// convert format - build up a new erf header
		// Timestamp
		erfhdr.ts = trace_get_erf_timestamp(packet);
		// Link type
		switch(trace_get_link_type(packet)) {
		case TRACE_TYPE_ETH:
			erfhdr.type=TYPE_ETH; break;
		case TRACE_TYPE_ATM:
			erfhdr.type=TYPE_ATM; break;
		default:
			erfhdr.type=0; 
		}
		// Flags. Can't do this
		memset(&erfhdr.flags,1,1);
		// Packet length
		erfhdr.rlen = trace_get_capture_length(packet);
		// loss counter. Can't do this
		erfhdr.lctr = 0;
		// Wire length
		erfhdr.wlen = trace_get_wire_length(packet);
		
		// Write it out
		numbytes = erf_dump_packet(libtrace,
				&erfhdr,
				payload,
				erfhdr.rlen);
	}
	return numbytes;
}


static void *legacy_get_link(const struct libtrace_packet_t *packet) {
	const void *posptr = 0;
	posptr = ((uint8_t *)packet->buffer);
	return (void *)posptr;
}

static libtrace_linktype_t legacy_get_link_type(const struct libtrace_packet_t *packet) {
	return TRACE_TYPE_LEGACY;
}

static libtrace_linktype_t legacyeth_get_link_type(const struct libtrace_packet_t *packet) {
	return TRACE_TYPE_LEGACY_ETH;
}

static libtrace_linktype_t legacyatm_get_link_type(const struct libtrace_packet_t *packet) {
	return TRACE_TYPE_LEGACY_ATM;
}

static libtrace_linktype_t legacypos_get_link_type(const struct libtrace_packet_t *packet) {
	return TRACE_TYPE_LEGACY_POS;
}

static void *erf_get_link(const struct libtrace_packet_t *packet) {
        const void *ethptr = 0;
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->buffer;
	
	if (erfptr->flags.rxerror == 1) {
		return NULL;
	}
	ethptr = ((uint8_t *)packet->buffer +
			dag_record_size + 2);
	return (void *)ethptr;
}

static libtrace_linktype_t erf_get_link_type(const struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->buffer;
	switch (erfptr->type) {
		case TYPE_ETH: return TRACE_TYPE_ETH;
		case TYPE_ATM: return TRACE_TYPE_ATM;
		default: assert(0);
	}
	return erfptr->type;
}

static int8_t erf_get_direction(const struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->buffer;
	return erfptr->flags.iface;
}

static int8_t erf_set_direction(const struct libtrace_packet_t *packet, int8_t direction) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->buffer;
	erfptr->flags.iface = direction;
	return erfptr->flags.iface;
}

static uint64_t erf_get_erf_timestamp(const struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->buffer;
	return erfptr->ts;
}

static int legacy_get_capture_length(const struct libtrace_packet_t *packet __attribute__((unused))) {
	return 64;
}

static int legacypos_get_wire_length(const struct libtrace_packet_t *packet) {
	
}
static int erf_get_capture_length(const struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->buffer;
	return ntohs(erfptr->rlen);
}

static int erf_get_wire_length(const struct libtrace_packet_t *packet) {
	dag_record_t *erfptr = 0;
	erfptr = (dag_record_t *)packet->buffer;
	return ntohs(erfptr->wlen);
}

static size_t erf_set_capture_length(struct libtrace_packet_t *packet, size_t size) {
	dag_record_t *erfptr = 0;
	assert(packet);
	if(size > packet->size) {
		// can't make a packet larger
		return packet->size;
	}
	erfptr = (dag_record_t *)packet->buffer;
	erfptr->rlen = ntohs(size + sizeof(dag_record_t));
	packet->size = size + sizeof(dag_record_t);
	return packet->size;
}

static int rtclient_get_fd(const struct libtrace_packet_t *packet) {
	return packet->trace->format_data->input.fd;
}

static int erf_get_fd(const struct libtrace_packet_t *packet) {
	return packet->trace->format_data->input.fd;
}

#if HAVE_DAG
static void dag_help() {
	printf("dag format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tdag:/dev/dagn\n");
	printf("\n");
	printf("\te.g.: dag:/dev/dag0\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tnone\n");
	printf("\n");
}
#endif

static void legacypos_help() {
	printf("legacypos format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tlegacypos:/path/to/file\t(uncompressed)\n");
	printf("\tlegacypos:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\tlegacypos:-\t(stdin, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: legacypos:/tmp/trace.gz\n");
	printf("\n");
}

static void legacyatm_help() {
	printf("legacyatm format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tlegacyatm:/path/to/file\t(uncompressed)\n");
	printf("\tlegacyatm:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\tlegacyatm:-\t(stdin, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: legacyatm:/tmp/trace.gz\n");
	printf("\n");
}

static void legacyeth_help() {
	printf("legacyeth format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\tlegacyeth:/path/to/file\t(uncompressed)\n");
	printf("\tlegacyeth:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\tlegacyeth:-\t(stdin, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: legacyeth:/tmp/trace.gz\n");
	printf("\n");
}

static void erf_help() {
	printf("erf format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\terf:/path/to/file\t(uncompressed)\n");
	printf("\terf:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\terf:-\t(stdin, either compressed or not)\n");
	printf("\terf:/path/to/socket\n");
	printf("\n");
	printf("\te.g.: erf:/tmp/trace\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\terf:path/to/file\t(uncompressed)\n");
	printf("\terf:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\terf:-\t(stdout, either compressed or not)\n");
	printf("\n");
	printf("\te.g.: erf:/tmp/trace\n");
	printf("\n");
	printf("Supported output options:\n");
	printf("\t-z\tSpecify the gzip compression, ranging from 0 (uncompressed) to 9 - defaults to 1\n");
	printf("\n");

	
}

static void rtclient_help() {
	printf("rtclient format module\n");
	printf("Supported input URIs:\n");
	printf("\trtclient:hostname:port\n");
	printf("\trtclient:hostname (connects on default port)\n");
	printf("\n");
	printf("\te.g.: rtclient:localhost\n");
	printf("\te.g.: rtclient:localhost:32500\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\trtclient: \t(will output on default port on all available IP addresses) \n");
	printf("\trtclient:hostname:port\n");
	printf("\trtclient:port\n");
	printf("\n");
	printf("\te.g.: rtclient:32500\n");
	printf("\te.g.: rtclient:\n");
	printf("\n");

}

static struct libtrace_format_t legacyatm = {
	"legacyatm",
	"$Id$",
	"legacyatm",
	erf_init_input,			/* init_input */	
	NULL,				/* init_output */
	NULL,				/* config_output */
	erf_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	legacy_read_packet,		/* read_packet */
	NULL,				/* write_packet */
	legacy_get_link,		/* get_link */
	legacyatm_get_link_type,	/* get_link_type */
	NULL,				/* get_direction */
	NULL,				/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	legacy_get_capture_length,	/* get_capture_length */
	NULL,				/* get_wire_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	legacyatm_help			/* help */
};

static struct libtrace_format_t legacyeth = {
	"legacyeth",
	"$Id$",
	"legacyeth",
	erf_init_input,			/* init_input */	
	NULL,				/* init_output */
	NULL,				/* config_output */
	erf_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	legacy_read_packet,		/* read_packet */
	NULL,				/* write_packet */
	legacy_get_link,		/* get_link */
	legacyeth_get_link_type,	/* get_link_type */
	NULL,				/* get_direction */
	NULL,				/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	legacy_get_capture_length,	/* get_capture_length */
	NULL,				/* get_wire_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	legacyatm_help			/* help */
};

static struct libtrace_format_t legacypos = {
	"legacypos",
	"$Id$",
	"legacypos",
	erf_init_input,			/* init_input */	
	NULL,				/* init_output */
	NULL,				/* config_output */
	erf_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	legacy_read_packet,		/* read_packet */
	NULL,				/* write_packet */
	legacy_get_link,		/* get_link */
	legacypos_get_link_type,	/* get_link_type */
	NULL,				/* get_direction */
	NULL,				/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	legacy_get_capture_length,	/* get_capture_length */
	NULL,				/* get_wire_length */
	NULL,				/* set_capture_length */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	legacypos_help			/* help */
};

	
static struct libtrace_format_t erf = {
	"erf",
	"$Id$",
	"erf",
	erf_init_input,			/* init_input */	
	erf_init_output,		/* init_output */
	erf_config_output,		/* config_output */
	erf_fin_input,			/* fin_input */
	erf_fin_output,			/* fin_output */
	erf_read_packet,		/* read_packet */
	erf_write_packet,		/* write_packet */
	erf_get_link,			/* get_link */
	erf_get_link_type,		/* get_link_type */
	erf_get_direction,		/* get_direction */
	erf_set_direction,		/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	erf_get_capture_length,		/* get_capture_length */
	erf_get_wire_length,		/* get_wire_length */
	erf_set_capture_length,		/* set_capture_length */
	erf_get_fd,			/* get_fd */
	trace_event_trace,		/* trace_event */
	erf_help			/* help */
};

#ifdef HAVE_DAG
static struct libtrace_format_t dag = {
	"dag",
	"$Id$",
	"erf",
	dag_init_input,			/* init_input */	
	NULL,				/* init_output */
	NULL,				/* config_output */
	dag_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	dag_read_packet,		/* read_packet */
	NULL,				/* write_packet */
	erf_get_link,			/* get_link */
	erf_get_link_type,		/* get_link_type */
	erf_get_direction,		/* get_direction */
	erf_set_direction,		/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	erf_get_capture_length,		/* get_capture_length */
	erf_get_wire_length,		/* get_wire_length */
	erf_set_capture_length,		/* set_capture_length */
	NULL,				/* get_fd */
	trace_event_trace,		/* trace_event */
	dag_help			/* help */
};
#endif

static struct libtrace_format_t rtclient = {
	"rtclient",
	"$Id$",
	"erf",
	rtclient_init_input,		/* init_input */	
	NULL,				/* init_output */
	NULL,				/* config_output */
	rtclient_fin_input,		/* fin_input */
	NULL,				/* fin_output */
	rtclient_read_packet,		/* read_packet */
	NULL,				/* write_packet */
	erf_get_link,			/* get_link */
	erf_get_link_type,		/* get_link_type */
	erf_get_direction,		/* get_direction */
	erf_set_direction,		/* set_direction */
	erf_get_erf_timestamp,		/* get_erf_timestamp */
	NULL,				/* get_timeval */
	NULL,				/* get_seconds */
	erf_get_capture_length,		/* get_capture_length */
	erf_get_wire_length,		/* get_wire_length */
	erf_set_capture_length,		/* set_capture_length */
	rtclient_get_fd,		/* get_fd */
	trace_event_device,		/* trace_event */
	rtclient_help			/* help */
};

void __attribute__((constructor)) erf_constructor() {
	erf_ptr = &erf;
	register_format(erf_ptr);
#ifdef HAVE_DAG
	dag_ptr = &dag;
	register_format(dag_ptr);
#endif
	rtclient_ptr = &rtclient;
	register_format(rtclient_ptr);

	legacypos_ptr = &legacypos;
	register_format(legacypos_ptr);

	legacyeth_ptr = &legacyeth;
	register_format(legacyeth_ptr);

	legacyatm_ptr = &legacyatm;
	register_format(legacyatm_ptr);

}
