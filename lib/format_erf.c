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

#include "libtrace.h"
#include "format.h"
#include "rtserver.h"
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

/* Catch undefined O_LARGEFILE on *BSD etc */
#ifndef O_LARGEFILE
#  define O_LARGEFILE 0
#endif 

#ifdef HAVE_DAG
static int dag_init_input(struct libtrace_t *libtrace) {
	struct stat buf;
	if (stat(libtrace->conn_info.path,&buf) == -1) {
		perror("stat");
		return 0;
	} 
	if (S_ISCHR(buf.st_mode)) {
		// DEVICE
		if((libtrace->input.fd = 
				dag_open(libtrace->conn_info.path)) < 0) {
			fprintf(stderr,"Cannot open DAG %s: %m\n", 
					libtrace->conn_info.path,errno);
			exit(0);
		}
		if((libtrace->dag.buf = (void *)
				dag_mmap(libtrace->input.fd)) == MAP_FAILED) {
			fprintf(stderr,"Cannot mmap DAG %s: %m\n", 
					libtrace->conn_info.path,errno);
			exit(0);
		}
		if(dag_start(libtrace->input.fd) < 0) {
			fprintf(stderr,"Cannot start DAG %s: %m\n", 
					libtrace->conn_info.path,errno);
			exit(0);
		}
	} else {
		fprintf(stderr,"%s isn't a valid char device, exiting\n",
				libtrace->conn_info.path);
		return 0;
	}
}
#endif

static int erf_init_input(struct libtrace_t *libtrace) {
	struct stat buf;
	struct hostent *he;
	struct sockaddr_in remote;
	struct sockaddr_un unix_sock;
	if (!strncmp(libtrace->conn_info.path,"-",1)) {
		// STDIN
#if HAVE_ZLIB
		libtrace->input.file = gzdopen(STDIN, "r");
#else	
		libtrace->input.file = stdin;
#endif

	} else {
		if (stat(libtrace->conn_info.path,&buf) == -1 ) {
			perror("stat");
			return 0;
		}
		if (S_ISSOCK(buf.st_mode)) {
			// SOCKET
			if ((libtrace->input.fd = socket(
					AF_UNIX, SOCK_STREAM, 0)) == -1) {
				perror("socket");
				return 0;
			}
			unix_sock.sun_family = AF_UNIX;
			bzero(unix_sock.sun_path,108);
			snprintf(unix_sock.sun_path,
					108,"%s"
					,libtrace->conn_info.path);

			if (connect(libtrace->input.fd, 
					(struct sockaddr *)&unix_sock,
					sizeof(struct sockaddr)) == -1) {
				perror("connect (unix)");
				return 0;
			}
		} else { 
			// TRACE
#if HAVE_ZLIB
			// using gzdopen means we can set O_LARGEFILE
			// ourselves. However, this way is messy and 
			// we lose any error checking on "open"
			libtrace->input.file = 
				gzdopen(open(
					libtrace->conn_info.path,
					O_LARGEFILE), "r");
#else
			libtrace->input.file = 
				fdopen(open(
					libtrace->conn_info.path,
					O_LARGEFILE), "r");
#endif

		}
	}
}

static int rtclient_init_input(struct libtrace_t *libtrace) {
	char *scan;
	char *uridata = libtrace->conn_info.path;
	struct hostent *he;
	struct sockaddr_in remote;

	if (strlen(uridata) == 0) {
		libtrace->conn_info.rt.hostname = 
			strdup("localhost");
		libtrace->conn_info.rt.port = 
			COLLECTOR_PORT;
	} else {
		if ((scan = strchr(uridata,':')) == NULL) {
			libtrace->conn_info.rt.hostname = 
				strdup(uridata);
			libtrace->conn_info.rt.port =
				COLLECTOR_PORT;
		} else {
			libtrace->conn_info.rt.hostname = 
				(char *)strndup(uridata,
						(scan - uridata));
			libtrace->conn_info.rt.port = 
				atoi(++scan);
		}
	}
	
	if ((he=gethostbyname(libtrace->conn_info.rt.hostname)) == NULL) {  
		perror("gethostbyname");
		return 0;
	} 
	if ((libtrace->input.fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		return 0;
	}

	remote.sin_family = AF_INET;   
	remote.sin_port = htons(libtrace->conn_info.rt.port);
	remote.sin_addr = *((struct in_addr *)he->h_addr);
	bzero(&(remote.sin_zero), 8);

	if (connect(libtrace->input.fd, (struct sockaddr *)&remote,
				sizeof(struct sockaddr)) == -1) {
		perror("connect (inet)");
		return 0;
	}
}

static int erf_init_output(struct libtrace_out_t *libtrace) {
	char *filemode = 0;

	libtrace->options.erf.level = 1;
	asprintf(&filemode,"wb%d",libtrace->options.erf.level);

        if (!strncmp(libtrace->uridata,"-",1)) {
                // STDOUT
#if HAVE_ZLIB
                libtrace->output.file = gzdopen(dup(1), filemode);
#else
                libtrace->output.file = stdout;
#endif
	}
	else {
	        // TRACE
#if HAVE_ZLIB
                // using gzdopen means we can set O_LARGEFILE
                // ourselves. However, this way is messy and
                // we lose any error checking on "open"
                libtrace->output.file =  gzdopen(open(
                                        libtrace->uridata,
                                        O_CREAT | O_LARGEFILE | O_WRONLY, 
					S_IRUSR | S_IWUSR), filemode);
#else
                libtrace->output.file =  fdopen(open(
                                        libtrace->uridata,
                                        O_CREAT | O_LARGEFILE | O_WRONLY, 
					S_IRUSR | S_IWUSR), "w");
#endif
	}
	

}

static int rtclient_init_output(struct libtrace_out_t *libtrace) {
	char * uridata = libtrace->uridata;
	char * scan;
	// extract conn_info from uridata
	if (strlen(uridata) == 0) {
		libtrace->conn_info.rt.hostname = strdup("localhost");
		libtrace->conn_info.rt.port = COLLECTOR_PORT;
	}
	else {
		if ((scan = strchr(uridata,':')) == NULL) {
                        libtrace->conn_info.rt.hostname =
                                strdup(uridata);
                        libtrace->conn_info.rt.port =
                                COLLECTOR_PORT;
                } else {
                        libtrace->conn_info.rt.hostname =
                                (char *)strndup(uridata,
                                                (scan - uridata));
                        libtrace->conn_info.rt.port =
                                atoi(++scan);
                }
        }
	
	
	libtrace->output.rtserver = rtserver_create(libtrace->conn_info.rt.hostname,
				libtrace->conn_info.rt.port);
	if (!libtrace->output.rtserver)
		return 0;
	
}

static int erf_config_output(struct libtrace_out_t *libtrace, int argc, char *argv[]) {
	int opt;
	int level = libtrace->options.erf.level;
	optind = 1;

	while ((opt = getopt(argc, argv, "z:")) != EOF) {
		switch (opt) {
			case 'z':
				level = atoi(optarg);
				break;
			default:
				printf("Bad argument to erf: %s\n", opt);
				// maybe spit out some help here
				return -1;
		}
	}
	if (level != libtrace->options.erf.level) {
		if (level > 9 || level < 0) {
			// retarded level choice
			printf("Compression level must be between 0 and 9 inclusive - you selected %i \n", level);
			
		} else {
			libtrace->options.erf.level = level;
			return gzsetparams(libtrace->output.file, level, Z_DEFAULT_STRATEGY);
		}
	}
	return 0;

}

static int rtclient_config_output(struct libtrace_out_t *libtrace, int argc, char *argv[]) {
	return 0;
}

#ifdef HAVE_DAG
static int dag_fin_input(struct libtrace_t *libtrace) {
	dag_stop(libtrace->input.fd);
}
#endif

static int erf_fin_input(struct libtrace_t *libtrace) {
#if HAVE_ZLIB
	gzclose(libtrace->input.file);
#else	
	fclose(libtrace->input.file);	
#endif
}

static int rtclient_fin_input(struct libtrace_t *libtrace) {
	close(libtrace->input.fd);
}

static int erf_fin_output(struct libtrace_out_t *libtrace) {
#if HAVE_ZLIB
        gzclose(libtrace->output.file);
#else
        fclose(libtrace->output.file);
#endif
}
 

static int rtclient_fin_output(struct libtrace_out_t *libtrace) {
	rtserver_destroy(libtrace->output.rtserver);
}

#if HAVE_DAG
static int dag_read(struct libtrace_t *libtrace, void *buffer, size_t len) {
	int numbytes;
	static short lctr = 0;
	struct dag_record_t *erfptr = 0;
	int rlen;

	if (buffer == 0)
		buffer = malloc(len);
	
	libtrace->dag.bottom = libtrace->dag.top;
	libtrace->dag.top = dag_offset(
			libtrace->input.fd,
			&(libtrace->dag.bottom),
			0);
	libtrace->dag.diff = libtrace->dag.top -
		libtrace->dag.bottom;

	numbytes=libtrace->dag.diff;
	libtrace->dag.offset = 0;
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
	
	if (libtrace->dag.diff == 0) {
		if ((numbytes = dag_read(libtrace,buf,RP_BUFSIZE)) <= 0) 
			return numbytes;
	}

	//DAG always gives us whole packets
	erfptr = (dag_record_t *) ((void *)libtrace->dag.buf + 
			(libtrace->dag.bottom + libtrace->dag.offset));
	size = ntohs(erfptr->rlen);

	if ( size  > LIBTRACE_PACKET_BUFSIZE) {
		printf("%d\n",size);
		assert( size < LIBTRACE_PACKET_BUFSIZE);
	}

	// have to copy it out of the memory hole at this stage:
	memcpy(packet->buffer, erfptr, size);

	packet->size = size;
	libtrace->dag.offset += size;
	libtrace->dag.diff -= size;

	assert(libtrace->dag.diff >= 0);

	return (size);
}
#endif

static int erf_read_packet(struct libtrace_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes;
	int size;
	char buf[RP_BUFSIZE];
	dag_record_t *erfptr;
	void *buffer = packet->buffer;
	void *buffer2 = buffer;
	int rlen;
	
	if ((numbytes=gzread(libtrace->input.file,
					buffer,
					dag_record_size)) == -1) {
		perror("gzread");
		return -1;
	}
	if (numbytes == 0) {
		return 0;
	}
	rlen = ntohs(((dag_record_t *)buffer)->rlen);
	size = rlen - dag_record_size;
	assert(size < LIBTRACE_PACKET_BUFSIZE);
	buffer2 = buffer + dag_record_size;
	
	// read in the rest of the packet
	if ((numbytes=gzread(libtrace->input.file,
					buffer2,
					size)) == -1) {
		perror("gzread");
		return -1;
	}
	packet->size = rlen;
	return rlen;
}

static int rtclient_read(struct libtrace_t *libtrace, void *buffer, size_t len) {
	int numbytes;
	static short lctr = 0;
	struct dag_record_t *erfptr = 0;
	int rlen;

	if (buffer == 0)
		buffer = malloc(len);
	while(1) {
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif
		if ((numbytes = recv(libtrace->input.fd,
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
	int numbytes;
	int size;
	char buf[RP_BUFSIZE];
	dag_record_t *erfptr;
	int read_required = 0;
	
	void *buffer = 0;
	buffer = packet->buffer;

	do {
		if (fifo_out_available(libtrace->fifo) == 0 || read_required) {
			if ((numbytes = rtclient_read(
						libtrace,buf,RP_BUFSIZE))<=0) {
				return numbytes;
			}
			assert(libtrace->fifo);
			fifo_write(libtrace->fifo,buf,numbytes);
			read_required = 0;
		}
		// Read status byte
		if (fifo_out_read(libtrace->fifo,
				&packet->status, sizeof(int)) == 0) {
			read_required = 1;
			continue;
		}
		fifo_out_update(libtrace->fifo,sizeof(int));

		// read in the ERF header
		if ((numbytes = fifo_out_read(libtrace->fifo, buffer,
						sizeof(dag_record_t))) == 0) {
			fifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}
		size = ntohs(((dag_record_t *)buffer)->rlen);

		// read in the full packet
		if ((numbytes = fifo_out_read(libtrace->fifo, 
						buffer, size)) == 0) {
			fifo_out_reset(libtrace->fifo);
			read_required = 1;
			continue;
		}

		// got in our whole packet, so...
		fifo_out_update(libtrace->fifo,size);

		fifo_ack_update(libtrace->fifo,size + sizeof(int));

		packet->size = numbytes;
		return numbytes;
	} while(1);
}

static int erf_write_packet(struct libtrace_out_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes = 0;

	if ((numbytes = gzwrite(libtrace->output.file, packet->buffer, packet->size)) == 0) {
		perror("gzwrite");
		return -1;
	}
	return numbytes;
}

static int rtclient_write_packet(struct libtrace_out_t *libtrace, struct libtrace_packet_t *packet) {
	int numbytes = 0;
	int size;
	int intsize = sizeof(int);
	char buf[RP_BUFSIZE];
	void *buffer = &buf[intsize];
	int write_required = 0;
	
	do {
		if (rtserver_checklisten(libtrace->output.rtserver) < 0)
			return -1;

		assert(libtrace->fifo);
		if (fifo_out_available(libtrace->fifo) == 0 || write_required) {
	                // Packet added to fifo
                        if ((numbytes = fifo_write(libtrace->fifo, packet->buffer, packet->size)) == 0) {
	                        // some error with the fifo
                                perror("fifo_write");
                                return -1;
                        }
                        write_required = 0;
                }

                // Read from fifo and add protocol header
                if ((numbytes = fifo_out_read(libtrace->fifo, buffer, sizeof(dag_record_t))) == 0) {
	                // failure reading in from fifo
                        fifo_out_reset(libtrace->fifo);
                        write_required = 1;
                        continue;
                }
                size = ntohs(((dag_record_t *)buffer)->rlen);
                assert(size < LIBTRACE_PACKET_BUFSIZE);
                if ((numbytes = fifo_out_read(libtrace->fifo, buffer, size)) == 0) {
 	               // failure reading in from fifo
                       fifo_out_reset(libtrace->fifo);
                       write_required = 1;
                       continue;
                }
                // Sort out the protocol header
                memcpy(buf, &packet->status, intsize);

		if ((numbytes = rtserver_sendclients(libtrace->output.rtserver, buf, size + sizeof(int))) < 0) {
                	write_required = 0;
                        continue;
                }


                fifo_out_update(libtrace->fifo, size);
	        fifo_ack_update(libtrace->fifo, size);
	} while(1);
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

static size_t erf_set_capture_length(struct libtrace_packet_t *packet, const size_t size) {
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

static void erf_help() {
	printf("erf format module: $Revision$\n");
	printf("Supported input URIs:\n");
	printf("\terf:/path/to/file\t(uncompressed)\n");
	printf("\terf:/path/to/file.gz\t(gzip-compressed)\n");
	printf("\terf:-\t(stdin, either compressed or not)\n")/
	printf("\terf:/path/to/socket\n");
	printf("\n");
	printf("\te.g.: erf:/tmp/trace\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tnone\n");
	printf("\n");

}

static void rtclient_help() {
	printf("rtclient format module\n");
	printf("Supported input URIs:\n");
	printf("\trtclient:hostname:port\n");
	printf("\trtclient:port\n");
	printf("\n");
	printf("\te.g.: rtclient:localhost\n");
	printf("\te.g.: rtclient:localhost:32500\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\trtclient:port\n");
	printf("\n");
	printf("\te.g.: rtclient:32500\n");
	printf("\n");

}

	
static struct format_t erf = {
	"erf",
	"$Id$",
	erf_init_input,			/* init_input */	
	erf_init_output,		/* init_output */
	erf_config_output,		/* config_output */
	erf_fin_input,			/* fin_input */
	erf_fin_output,			/* fin_output */
	NULL,				/* read */
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
	erf_help			/* help */
};

#ifdef HAVE_DAG
static struct format_t dag = {
	"dag",
	"$Id$",
	dag_init_input,			/* init_input */	
	NULL,				/* init_output */
	NULL,				/* config_output */
	dag_fin_input,			/* fin_input */
	NULL,				/* fin_output */
	dag_read,			/* read */
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
	dag_help			/* help */
};
#endif

static struct format_t rtclient = {
	"rtclient",
	"$Id$",
	rtclient_init_input,		/* init_input */	
	rtclient_init_output,		/* init_output */
	rtclient_config_output,		/* config_output */
	rtclient_fin_input,		/* fin_input */
	rtclient_fin_output,		/* fin_output */
	rtclient_read,			/* read */
	rtclient_read_packet,		/* read_packet */
	rtclient_write_packet,		/* write_packet */
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
	rtclient_help			/* help */
};

void __attribute__((constructor)) erf_constructor() {
	register_format(&erf);
#ifdef HAVE_DAG
	register_format(&dag);
#endif
	register_format(&rtclient);
}
