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


/* @file 
 *
 * @brief Trace file processing library
 *
 * @author Daniel Lawson
 * @author Perry Lorier
 *
 * @internal
 */
#define _GNU_SOURCE
#include "common.h"
#include "config.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#ifdef HAVE_SYS_LIMITS_H
#  include <sys/limits.h>
#endif

#ifdef HAVE_NET_IF_ARP_H
#  include <net/if_arp.h>
#endif

#ifdef HAVE_NET_IF_H
#  include <net/if.h>
#endif

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#  include <net/ethernet.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
#  include <netinet/if_ether.h>
#endif

#include <time.h>

#include "libtrace.h"
#include "fifo.h"
#include "libtrace_int.h"
#include "parse_cmd.h"

#ifdef HAVE_PCAP_BPF_H
#  include <pcap-bpf.h>
#else
#  ifdef HAVE_NET_BPF_H
#    include <net/bpf.h>
#  endif
#endif


#include "libtrace_int.h"
#include "format_helper.h"
#include "rt_protocol.h"

#define MAXOPTS 1024


static struct libtrace_format_t *formats_list = NULL;

/* strncpy is not assured to copy the final \0, so we
 * will use our own one that does
 */
static void xstrncpy(char *dest, const char *src, size_t n)
{
        strncpy(dest,src,n);
        dest[n]='\0';
}
 
static char *xstrndup(const char *src,size_t n)
{       
        char *ret=(char*)malloc(n+1);
	if (ret==NULL) {
		fprintf(stderr,"Out of memory");
		exit(EXIT_FAILURE);
	}
        xstrncpy(ret,src,n);
        return ret;
}

void register_format(struct libtrace_format_t *f) {
	assert(f->next==NULL);
	f->next=formats_list;
	formats_list=f;
	/* Now, verify things 
	 * This #if can be changed to a 1 to output warnings about inconsistant
	 * functions being provided by format modules.  This generally is very
	 * noisy, as almost all modules don't implement one or more functions
	 * for various reasons.  This is very useful when checking a new 
	 * format module is sane.
	 */ 
#if 0
	if (f->init_input) {
#define REQUIRE(x) \
		if (!f->x) \
			fprintf(stderr,"%s: Input format should provide " #x "\n",f->name)
		REQUIRE(read_packet);
		REQUIRE(start_input);
		REQUIRE(fin_input);
		REQUIRE(get_link_type);
		REQUIRE(get_capture_length);
		REQUIRE(get_wire_length);
		REQUIRE(get_framing_length);
		REQUIRE(trace_event);
		if (!f->get_erf_timestamp 
			&& !f->get_seconds
			&& !f->get_timeval) {
			fprintf(stderr,"%s: A trace format capable of input, should provide at least one of\n"
"get_erf_timestamp, get_seconds or trace_timeval\n",f->name);
		}
		if (f->trace_event!=trace_event_trace) {
			/* Theres nothing that a trace file could optimise with
			 * config_input
			 */
			REQUIRE(pause_input);
			REQUIRE(config_input);
			REQUIRE(get_fd);
		}
		else {
			if (f->get_fd) {
				fprintf(stderr,"%s: Unnecessary get_fd\n",
						f->name);
			}
		}
#undef REQUIRE
	}
	else {
#define REQUIRE(x) \
		if (f->x) \
			fprintf(stderr,"%s: Non Input format shouldn't need " #x "\n",f->name)
		REQUIRE(read_packet);
		REQUIRE(start_input);
		REQUIRE(pause_input);
		REQUIRE(fin_input);
		REQUIRE(get_link_type);
		REQUIRE(get_capture_length);
		REQUIRE(get_wire_length);
		REQUIRE(get_framing_length);
		REQUIRE(trace_event);
		REQUIRE(get_seconds);
		REQUIRE(get_timeval);
		REQUIRE(get_erf_timestamp);
#undef REQUIRE
	}
	if (f->init_output) {
#define REQUIRE(x) \
		if (!f->x) \
			fprintf(stderr,"%s: Output format should provide " #x "\n",f->name)
		REQUIRE(write_packet);
		REQUIRE(start_output);
		REQUIRE(config_output);
		REQUIRE(fin_output);
#undef REQUIRE
	}
	else {
#define REQUIRE(x) \
		if (f->x) \
			fprintf(stderr,"%s: Non Output format shouldn't need " #x "\n",f->name)
		REQUIRE(write_packet);
		REQUIRE(start_output);
		REQUIRE(config_output);
		REQUIRE(fin_output);
#undef REQUIRE
	}
#endif
}

void erf_constructor();
void legacy_constructor();
void linuxnative_constructor();
void pcap_constructor();
void pcapfile_constructor();
void rt_constructor();
void wag_constructor();
void duck_constructor();

/* call all the constructors if they haven't yet all been called */
void trace_init(void)
{
	if (!formats_list) {
		duck_constructor();
		erf_constructor();
		legacy_constructor();
#ifdef HAVE_NETPACKET_PACKET_H
		linuxnative_constructor();
#endif
#ifdef HAVE_LIBPCAP
		pcap_constructor();
#endif
#if HAVE_BIOCSETIF
		bpf_constructor();
#endif
		pcapfile_constructor();
		rt_constructor();
		wag_constructor();
	}
}

/* Prints help information for libtrace 
 *
 * Function prints out some basic help information regarding libtrace,
 * and then prints out the help() function registered with each input module
 */
DLLEXPORT void trace_help() {
	struct libtrace_format_t *tmp;
	trace_init();
	printf("libtrace %s\n\n",PACKAGE_VERSION);
	printf("Following this are a list of the format modules supported in this build of libtrace\n\n");
	for(tmp=formats_list;tmp;tmp=tmp->next) {
		if (tmp->help)
			tmp->help();
	}
}

#define RP_BUFSIZE 65536
#define URI_PROTO_LINE 16


/* Create a trace file from a URI
 *
 * @params char * containing a valid libtrace URI
 * @returns opaque pointer to a libtrace_t
 *
 * Valid URI's are:
 *  erf:/path/to/erf/file
 *  erf:/path/to/erf/file.gz
 *  erf:/path/to/rtclient/socket
 *  erf:-  			(stdin)
 *  dag:/dev/dagcard
 *  pcapint:pcapinterface 		(eg: pcapint:eth0)
 *  pcap:/path/to/pcap/file
 *  pcap:-
 *  rtclient:hostname
 *  rtclient:hostname:port
 *  wag:-
 *  wag:/path/to/wag/file
 *  wag:/path/to/wag/file.gz
 *  wag:/path/to/wag/socket
 *
 * If an error occured when attempting to open a trace, NULL is returned
 * and an error is output to stdout.
 */
DLLEXPORT libtrace_t *trace_create(const char *uri) {
        libtrace_t *libtrace = 
			(libtrace_t *)malloc(sizeof(libtrace_t));
        char *scan = 0;
        const char *uridata = 0;                  
	struct libtrace_format_t *tmp;

	trace_init();

	assert(uri && "Passing NULL to trace_create makes me a very sad program");

	if (!libtrace) {
		/* Out of memory */
		return NULL;
	}
	
	libtrace->err.err_num = TRACE_ERR_NOERROR;
	libtrace->format=NULL;
        
        /* parse the URI to determine what sort of event we are dealing with */
	if ((uridata = trace_parse_uri(uri, &scan)) == 0) {
		trace_set_err(libtrace,TRACE_ERR_BAD_FORMAT,"Bad uri format (%s)",uri);
		return libtrace;
	}
	
	libtrace->event.tdelta = 0.0;
	libtrace->filter = NULL;
	libtrace->snaplen = 0;
	libtrace->started=false;

	for (tmp=formats_list;tmp;tmp=tmp->next) {
		if (strlen(scan) == strlen(tmp->name) &&
				strncasecmp(scan, tmp->name, strlen(scan)) == 0
				) {
			libtrace->format=tmp;
			break;
		}
	}
	if (libtrace->format == 0) {
		trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT,
				"Unknown format (%s)",scan);
		return libtrace;
	}

        libtrace->uridata = strdup(uridata);
        /* libtrace->format now contains the type of uri
         * libtrace->uridata contains the appropriate data for this
	 */
        
	if (libtrace->format->init_input) {
		int err=libtrace->format->init_input(libtrace);
		assert (err==-1 || err==0);
		if (err==-1) {
			/* init_input should call trace_set_err to set 
			 * the error message
			 */
			return libtrace;
		}
	} else {
		trace_set_err(libtrace,TRACE_ERR_UNSUPPORTED,
				"Format does not support input (%s)",scan);
		return libtrace;
	}
	

        libtrace->fifo = create_tracefifo(1048576);
	if (!libtrace->fifo) {
		trace_set_err(libtrace,ENOMEM,"Could not allocate memory for fifo");
		free(scan);
		return libtrace;
	}
	assert(libtrace->fifo);
	free(scan);
	libtrace->err.err_num=TRACE_ERR_NOERROR;
	libtrace->err.problem[0]='\0';
        return libtrace;
}

/* Creates a "dummy" trace file that has only the format type set.
 *
 * @returns opaque pointer to a (sparsely initialised) libtrace_t
 *
 * IMPORTANT: Do not attempt to call trace_read_packet or other such functions
 * with the dummy trace. Its intended purpose is to act as a packet->trace for
 * libtrace_packet_t's that are not associated with a libtrace_t structure.
 */
DLLEXPORT libtrace_t * trace_create_dead (const char *uri) {
	libtrace_t *libtrace = (libtrace_t *) malloc(sizeof(libtrace_t));
	char *scan = (char *)calloc(sizeof(char),URI_PROTO_LINE);
	char *uridata;
	struct libtrace_format_t *tmp;

	trace_init();
	
	libtrace->err.err_num = TRACE_ERR_NOERROR;

	if((uridata = strchr(uri,':')) == NULL) {
		xstrncpy(scan, uri, strlen(uri));
	} else {
		xstrncpy(scan,uri, (uridata - uri));
	}
	
	libtrace->format = 0;	
	
	for(tmp=formats_list;tmp;tmp=tmp->next) {
                if (strlen(scan) == strlen(tmp->name) &&
                                !strncasecmp(scan,
                                        tmp->name,
                                        strlen(scan))) {
                                libtrace->format=tmp;
                                break;
                                }
        }
        if (libtrace->format == 0) {
		trace_set_err(libtrace,TRACE_ERR_BAD_FORMAT,
				"Unknown format (%s)",scan);
        }

	libtrace->format_data = NULL;
	free(scan);
	return libtrace;

}

/* Creates a trace output file from a URI. 
 *
 * @param uri	the uri string describing the output format and destination
 * @returns opaque pointer to a libtrace_output_t 
 *
 *  If an error occured when attempting to open the output trace, NULL is
 *  returned and trace_errno is set. 
 */
	
DLLEXPORT libtrace_out_t *trace_create_output(const char *uri) {
	libtrace_out_t *libtrace = 
			(libtrace_out_t*)malloc(sizeof(libtrace_out_t));
	
	char *scan = 0;
        const char *uridata = 0;
	struct libtrace_format_t *tmp;

	trace_init();

	libtrace->err.err_num = TRACE_ERR_NOERROR;
	strcpy(libtrace->err.problem,"Error message set\n");
	
        /* parse the URI to determine what sort of event we are dealing with */

	if ((uridata = trace_parse_uri(uri, &scan)) == 0) {
		trace_set_err_out(libtrace,TRACE_ERR_BAD_FORMAT,
				"Bad uri format (%s)",uri);
		return libtrace;
	}
	
        libtrace->format = NULL;
	for(tmp=formats_list;tmp;tmp=tmp->next) {
                if (strlen(scan) == strlen(tmp->name) &&
                                !strncasecmp(scan,
                                        tmp->name,
                                        strlen(scan))) {
                                libtrace->format=tmp;
                                break;
                                }
        }
        if (libtrace->format == NULL) {
		trace_set_err_out(libtrace,TRACE_ERR_BAD_FORMAT,
				"Unknown output format (%s)",scan);
                return libtrace;
        }
        libtrace->uridata = strdup(uridata);


        /* libtrace->format now contains the type of uri
         * libtrace->uridata contains the appropriate data for this
	 */

        if (libtrace->format->init_output) {
		/* 0 on success, -1 on failure */
                switch(libtrace->format->init_output(libtrace)) {
			case -1: /* failure */
				return libtrace;
			case 0: /* success */
				break;
			default:
				assert(!"init_output() should return -1 for failure, or 0 for success");
		}
	} else {
		trace_set_err_out(libtrace,TRACE_ERR_UNSUPPORTED,
				"Format does not support writing (%s)",scan);
                return libtrace;
        }


	free(scan);
	libtrace->started=false;
	return libtrace;
}

/* Start a trace
 * @param libtrace	the input trace to start
 * @returns 0 on success
 *
 * This does the work associated with actually starting up
 * the trace.  it may fail.
 */
DLLEXPORT int trace_start(libtrace_t *libtrace)
{
	assert(libtrace);
	if (libtrace->format->start_input) {
		int ret=libtrace->format->start_input(libtrace);
		if (ret < 0) {
			return ret;
		}
	}

	libtrace->started=true;
	return 0;
}

DLLEXPORT int trace_start_output(libtrace_out_t *libtrace) 
{
	assert(libtrace);
	if (libtrace->format->start_output) {
		int ret=libtrace->format->start_output(libtrace);
		if (ret < 0) {
			return ret;
		}
	}

	libtrace->started=true;
	return 0;
}

DLLEXPORT int trace_pause(libtrace_t *libtrace)
{
	assert(libtrace);
	assert(libtrace->started && "BUG: Called trace_pause without calling trace_start first");
	if (libtrace->format->pause_input)
		libtrace->format->pause_input(libtrace);
	libtrace->started=false;
	return 0;
}

DLLEXPORT int trace_config(libtrace_t *libtrace,
		trace_option_t option,
		void *value)
{
	int ret;
	if (libtrace->format->config_input) {
		ret=libtrace->format->config_input(libtrace,option,value);
		if (ret==0)
			return 0;
	}
	switch(option) {
		case TRACE_OPTION_SNAPLEN:
			libtrace->snaplen=*(int*)value;
			return 0;
		case TRACE_OPTION_FILTER:
			libtrace->filter=(libtrace_filter_t *)value;
			return 0;
		case TRACE_OPTION_PROMISC:
			trace_set_err(libtrace,TRACE_ERR_OPTION_UNAVAIL,
				"Promisc mode is not supported by this format module");
			return -1;
		case TRACE_META_FREQ:
			trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
				"This format does not support meta-data gathering");
			return -1;
	}
	trace_set_err(libtrace,TRACE_ERR_UNKNOWN_OPTION,
		"Unknown option %i", option);
	return -1;
}

/* Parses an output options string and calls the appropriate function to deal with output options.
 *
 * @param libtrace	the output trace object to apply the options to
 * @param options	the options string
 * @returns -1 if option configuration failed, 0 otherwise
 *
 * @author Shane Alcock
 */
DLLEXPORT int trace_config_output(libtrace_out_t *libtrace, 
		trace_option_output_t option,
		void *value) {
	if (libtrace->format->config_output) {
		return libtrace->format->config_output(libtrace, option, value);
	}
	return -1;
}

/* Close a trace file, freeing up any resources it may have been using
 *
 */
DLLEXPORT void trace_destroy(libtrace_t *libtrace) {
        assert(libtrace);
	if (libtrace->format) {
		if (libtrace->started && libtrace->format->pause_input)
			libtrace->format->pause_input(libtrace);
		libtrace->format->fin_input(libtrace);
	}
        /* need to free things! */
        if (libtrace->uridata)
		free(libtrace->uridata);
	if (libtrace->fifo)
		destroy_tracefifo(libtrace->fifo);
        free(libtrace);
}


DLLEXPORT void trace_destroy_dead(libtrace_t *libtrace) {
	assert(libtrace);
	free(libtrace);
}
/* Close an output trace file, freeing up any resources it may have been using
 *
 * @param libtrace	the output trace file to be destroyed
 *
 * @author Shane Alcock
 * */
DLLEXPORT void trace_destroy_output(libtrace_out_t *libtrace) {
	assert(libtrace);
	libtrace->format->fin_output(libtrace);
	free(libtrace->uridata);
	free(libtrace);
}

DLLEXPORT libtrace_packet_t *trace_create_packet() {
	libtrace_packet_t *packet = 
		(libtrace_packet_t*)calloc(1,sizeof(libtrace_packet_t));
	packet->buf_control=TRACE_CTRL_PACKET;
	return packet;
}

DLLEXPORT libtrace_packet_t *trace_copy_packet(const libtrace_packet_t *packet) {
	libtrace_packet_t *dest = 
		(libtrace_packet_t *)malloc(sizeof(libtrace_packet_t));
	dest->trace=packet->trace;
	dest->buffer=malloc(
			trace_get_framing_length(packet)
			+trace_get_capture_length(packet));
	dest->header=dest->buffer;
	dest->payload=(void*)
		((char*)dest->buffer+trace_get_framing_length(packet));
	dest->size=packet->size;
	dest->type=packet->type;
	dest->buf_control=TRACE_CTRL_PACKET;
	memcpy(dest->header,packet->header,trace_get_framing_length(packet));
	memcpy(dest->payload,packet->payload,trace_get_capture_length(packet));

	return dest;
}

/** Destroy a packet object
 *
 * sideeffect: sets packet to NULL
 */
DLLEXPORT void trace_destroy_packet(libtrace_packet_t *packet) {
	if (packet->buf_control == TRACE_CTRL_PACKET) {
		free(packet->buffer);
	}
	packet->buf_control=(buf_control_t)'\0'; 
				/* an "bad" value to force an assert
				 * if this packet is ever reused
				 */
	free(packet);
}	

/* Read one packet from the trace into buffer
 *
 * @param libtrace 	the libtrace opaque pointer
 * @param packet  	the packet opaque pointer
 * @returns 0 on EOF, negative value on error
 *
 */
DLLEXPORT int trace_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {

	assert(libtrace && "You called trace_read_packet() with a NULL libtrace parameter!\n");
	assert(libtrace->started && "BUG: You must call libtrace_start() before trace_read_packet()\n");
	assert(packet);
	assert((packet->buf_control==TRACE_CTRL_PACKET || packet->buf_control==TRACE_CTRL_EXTERNAL)&&
		"BUG: You must allocate a packet using packet_create()");
      
	/* Store the trace we are reading from into the packet opaque 
	 * structure */
	packet->trace = libtrace;

	if (libtrace->format->read_packet) {
		do {
			packet->size=libtrace->format->read_packet(libtrace,packet);
			if (packet->size==(size_t)-1 || packet->size==0) {
				return packet->size;
			}
			if (libtrace->filter) {
				/* If the filter doesn't match, read another
				 * packet
				 */
				if (!trace_apply_filter(libtrace->filter,packet)){
					continue;
				}
			}
			if (libtrace->snaplen>0) {
				/* Snap the packet */
				trace_set_capture_length(packet,
						libtrace->snaplen);
			}
			return packet->size;
		} while(1);
	}
	trace_set_err(libtrace,TRACE_ERR_UNSUPPORTED,"This format does not support reading packets\n");
	packet->size=~0U;
	return ~0U;
}

/* Writes a packet to the specified output
 *
 * @param libtrace	describes the output format, destination, etc.
 * @param packet	the packet to be written out
 * @returns the number of bytes written, -1 if write failed
 *
 * @author Shane Alcock
 * */
DLLEXPORT int trace_write_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	assert(libtrace);
	assert(packet);	
	/* Verify the packet is valid */
	assert(packet->size<65536);
	assert(packet->size>0);
	assert(libtrace->started);

	if (libtrace->format->write_packet) {
		return libtrace->format->write_packet(libtrace, packet);
	}
	trace_set_err_out(libtrace,TRACE_ERR_UNSUPPORTED,
		"This format does not support writing packets");
	return -1;
}

DLLEXPORT void *trace_get_link(const libtrace_packet_t *packet) {
	return (void *)packet->payload;
}

/*
typedef struct legacy_framing {
	uint64_t 	ts;
	uint32_t	crc;
	uint32_t	header;
	uint32_t	data[12]; // pad to 64 bytes 
} legacy_framing_t;
*/


/* Get the current time in DAG time format 
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns a 64 bit timestamp in DAG ERF format (upper 32 bits are the seconds
 * past 1970-01-01, the lower 32bits are partial seconds)
 * @author Daniel Lawson
 */ 
DLLEXPORT uint64_t trace_get_erf_timestamp(const libtrace_packet_t *packet) {
	uint64_t timestamp = 0;
	double seconds = 0.0;
	struct timeval ts;

	assert(packet->size>0 && packet->size<65536);

	if (packet->trace->format->get_erf_timestamp) {
		/* timestamp -> timestamp */
		timestamp = packet->trace->format->get_erf_timestamp(packet);
	} else if (packet->trace->format->get_timeval) {
		/* timeval -> timestamp */
		ts = packet->trace->format->get_timeval(packet);
		timestamp = ((((uint64_t)ts.tv_sec) << 32) + \
				(((uint64_t)ts.tv_usec * UINT_MAX)/1000000));
	} else if (packet->trace->format->get_seconds) {
		/* seconds -> timestamp */
		seconds = packet->trace->format->get_seconds(packet);
		timestamp = ((uint64_t)((uint32_t)seconds) << 32) + \
		      (uint64_t)(( seconds - (uint32_t)seconds   ) * UINT_MAX);
	}
	return timestamp;
}

/* Get the current time in struct timeval
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns time that this packet was seen in a struct timeval
 * @author Daniel Lawson
 * @author Perry Lorier
 */ 
DLLEXPORT struct timeval trace_get_timeval(const libtrace_packet_t *packet) {
        struct timeval tv;
	uint64_t ts = 0;
	double seconds = 0.0;
	assert(packet->size>0 && packet->size<65536);
	if (packet->trace->format->get_timeval) {
		/* timeval -> timeval */
		tv = packet->trace->format->get_timeval(packet);
	} else if (packet->trace->format->get_erf_timestamp) {
		/* timestamp -> timeval */
		ts = packet->trace->format->get_erf_timestamp(packet);
#if __BYTE_ORDER == __BIG_ENDIAN
		tv.tv_sec = ts & 0xFFFFFFFF;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
		tv.tv_sec = ts >> 32;
#else
#error "What on earth are you running this on?"
#endif
		tv.tv_usec = ((ts&0xFFFFFFFF)*1000000)>>32;
       		if (tv.tv_usec >= 1000000) {
               		tv.tv_usec -= 1000000;
               		tv.tv_sec += 1;
       		}
	} else if (packet->trace->format->get_seconds) {
		/* seconds -> timeval */
		seconds = packet->trace->format->get_seconds(packet);
		tv.tv_sec = (uint32_t)seconds;
		tv.tv_usec = (uint32_t)(((seconds - tv.tv_sec) * 1000000)/UINT_MAX);
	}

        return tv;
}

/* Get the current time in floating point seconds
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns time that this packet was seen in 64bit floating point seconds
 * @author Perry Lorier
 */ 
DLLEXPORT double trace_get_seconds(const libtrace_packet_t *packet) {
	double seconds = 0.0;
	uint64_t ts = 0;
	struct timeval tv;

	assert(packet->size>0 && packet->size<65536);
	
	if (packet->trace->format->get_seconds) {
		/* seconds->seconds */
		seconds = packet->trace->format->get_seconds(packet);
	} else if (packet->trace->format->get_erf_timestamp) {
		/* timestamp -> seconds */
		ts = packet->trace->format->get_erf_timestamp(packet);
		seconds =  (ts>>32) + ((ts & UINT_MAX)*1.0 / UINT_MAX);
	} else if (packet->trace->format->get_timeval) {
		/* timeval -> seconds */
		tv = packet->trace->format->get_timeval(packet);
		seconds = tv.tv_sec + ((tv.tv_usec * 1.0) / 1000000);
	}

	return seconds;
}

DLLEXPORT size_t trace_get_capture_length(const libtrace_packet_t *packet) {

	assert(packet->size<65536);

	if (packet->trace->format->get_capture_length) {
		return packet->trace->format->get_capture_length(packet);
	}
	return ~0U;
}
	
/* Get the size of the packet as it was seen on the wire.
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns the size of the packet as it was on the wire.
 * @author Perry Lorier
 * @author Daniel Lawson
 * @note Due to the trace being a header capture, or anonymisation this may
 * not be the same as the Capture Len.
 */ 
DLLEXPORT size_t trace_get_wire_length(const libtrace_packet_t *packet){
	assert(packet->size>0 && packet->size<65536);

	if (packet->trace->format->get_wire_length) {
		return packet->trace->format->get_wire_length(packet);
	}
	return ~0U;

}

/* Get the length of the capture framing headers.
 * @param packet  	the packet opaque pointer
 * @returns the size of the packet as it was on the wire.
 * @author Perry Lorier
 * @author Daniel Lawson
 * @note this length corresponds to the difference between the size of a 
 * captured packet in memory, and the captured length of the packet
 */ 
DLLEXPORT SIMPLE_FUNCTION
size_t trace_get_framing_length(const libtrace_packet_t *packet) {
	if (packet->trace->format->get_framing_length) {
		return packet->trace->format->get_framing_length(packet);
	}
	return ~0U;
}


/* Get the type of the link layer
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns libtrace_linktype_t
 * @author Perry Lorier
 * @author Daniel Lawson
 */
DLLEXPORT libtrace_linktype_t trace_get_link_type(const libtrace_packet_t *packet ) {
	if (packet->trace->format->get_link_type) {
		return packet->trace->format->get_link_type(packet);
	}
	return (libtrace_linktype_t)-1;
}

/* process a libtrace event
 * @param trace the libtrace opaque pointer
 * @param packet the libtrace_packet opaque pointer
 * @returns
 *  TRACE_EVENT_IOWAIT	Waiting on I/O on fd
 *  TRACE_EVENT_SLEEP	Next event in seconds
 *  TRACE_EVENT_PACKET	Packet arrived in buffer with size size
 *  TRACE_EVENT_TERMINATE Trace terminated (perhaps with an error condition)
 * FIXME currently keeps a copy of the packet inside the trace pointer,
 * which in turn is stored inside the new packet object...
 * @author Perry Lorier
 */
DLLEXPORT libtrace_eventobj_t trace_event(libtrace_t *trace, 
		libtrace_packet_t *packet) {
	libtrace_eventobj_t event = {TRACE_EVENT_IOWAIT,0,0.0,0};

	if (!trace) {
		fprintf(stderr,"You called trace_event() with a NULL trace object!\n");
	}
	assert(trace);
	assert(packet);

	/* Store the trace we are reading from into the packet opaque
	 * structure */
	packet->trace = trace;

	if (packet->trace->format->trace_event) {
		return packet->trace->format->trace_event(trace,packet);
	} else {
		return event;
	}

}

/* setup a BPF filter
 * @param filterstring a char * containing the bpf filter string
 * @returns opaque pointer pointer to a libtrace_filter_t object
 * @author Daniel Lawson
 */
DLLEXPORT libtrace_filter_t *trace_create_filter(const char *filterstring) {
#ifdef HAVE_BPF
	libtrace_filter_t *filter = (libtrace_filter_t*)
				malloc(sizeof(libtrace_filter_t));
	filter->filterstring = strdup(filterstring);
	filter->flag = 0;
	return filter;
#else
	fprintf(stderr,"This version of libtrace does not have bpf filter support\n");
	return NULL;
#endif
}

DLLEXPORT void trace_destroy_filter(libtrace_filter_t *filter)
{
#ifdef HAVE_BPF
	free(filter->filterstring);
	if (filter->flag)
		pcap_freecode(&filter->filter);
	free(filter);
#else

#endif
}

/* compile a bpf filter, now we know what trace it's on
 * @internal
 *
 * @returns -1 on error, 0 on success
 */
int trace_bpf_compile(libtrace_filter_t *filter,
		const libtrace_packet_t *packet	) {
#ifdef HAVE_BPF
	void *linkptr = 0;
	assert(filter);

	/* If this isn't a real packet, then fail */
	linkptr = trace_get_link(packet);
	if (!linkptr) {
		trace_set_err(packet->trace,
				TRACE_ERR_BAD_PACKET,"Packet has no payload");
		return -1;
	}
	
	if (filter->filterstring && ! filter->flag) {
		pcap_t *pcap;
		libtrace_linktype_t linktype=trace_get_link_type(packet);
		if (linktype==(libtrace_linktype_t)-1) {
			trace_set_err(packet->trace,TRACE_ERR_BAD_PACKET,
					"Packet has an unknown linktype");
			return -1;
		}
		if (libtrace_to_pcap_dlt(linktype) == -1) {
			trace_set_err(packet->trace,TRACE_ERR_BAD_PACKET,
					"Unknown pcap equivilent linktype");
			return -1;
		}
		pcap=(pcap_t *)pcap_open_dead(
				libtrace_to_pcap_dlt(linktype),
				1500);
		/* build filter */
		if (pcap_compile( pcap, &filter->filter, filter->filterstring, 
					1, 0)) {
			pcap_close(pcap);
			trace_set_err(packet->trace,TRACE_ERR_BAD_PACKET,
					"Packet has no payload");
			return -1;
		}
		pcap_close(pcap);
		filter->flag=1;
	}
	return 0;
#else
	assert(!"This should never be called when BPF not enabled");
	trace_set_err(packet->trace,TRACE_ERR_OPTION_UNAVAIL,
				"Feature unavailable");
	return -1;
#endif
}

DLLEXPORT int trace_apply_filter(libtrace_filter_t *filter,
			const libtrace_packet_t *packet) {
#ifdef HAVE_BPF
	void *linkptr = 0;
	int clen = 0;
	assert(filter);
	assert(packet);
	linkptr = trace_get_link(packet);
	if (!linkptr) {
		return 0;
	}

	/* We need to compile it now, because before we didn't know what the 
	 * link type was
	 */
	if (trace_bpf_compile(filter,packet)==-1)
		return -1;
	
	clen = trace_get_capture_length(packet);

	assert(filter->flag);
	return bpf_filter(filter->filter.bf_insns,(u_char*)linkptr,clen,clen);
#else
	fprintf(stderr,"This version of libtrace does not have bpf filter support\n");
	return 0;
#endif
}

/* Set the direction flag, if it has one
 * @param packet the packet opaque pointer
 * @param direction the new direction (0,1,2,3)
 * @returns a signed value containing the direction flag, or -1 if this is not supported
 */
DLLEXPORT libtrace_direction_t trace_set_direction(libtrace_packet_t *packet, 
		libtrace_direction_t direction) 
{
	assert(packet);
	assert(packet->size>0 && packet->size<65536);
	if (packet->trace->format->set_direction) {
		return packet->trace->format->set_direction(packet,direction);
	}
	return (libtrace_direction_t)~0U;
}

/* Get the direction flag, if it has one
 * @param packet a pointer to a libtrace_packet structure
 * @returns a signed value containing the direction flag, or -1 if this is not supported
 * The direction is defined as 0 for packets originating locally (ie, outbound)
 * and 1 for packets originating remotely (ie, inbound).
 * Other values are possible, which might be overloaded to mean special things
 * for a special trace.
 * @author Daniel Lawson
 */
DLLEXPORT libtrace_direction_t trace_get_direction(const libtrace_packet_t *packet) 
{
	assert(packet);
	assert(packet->size>0 && packet->size<65536);
	if (packet->trace->format->get_direction) {
		return packet->trace->format->get_direction(packet);
	}
	return (libtrace_direction_t)~0U;
}

#define ROOT_SERVER(x) ((x) < 512)
#define ROOT_CLIENT(x) ((512 <= (x)) && ((x) < 1024))
#define NONROOT_SERVER(x) ((x) >= 5000)
#define NONROOT_CLIENT(x) ((1024 <= (x)) && ((x) < 5000))
#define DYNAMIC(x) ((49152 < (x)) && ((x) < 65535))
#define SERVER(x) ROOT_SERVER(x) || NONROOT_SERVER(x)
#define CLIENT(x) ROOT_CLIENT(x) || NONROOT_CLIENT(x) 

/* Attempt to deduce the 'server' port
 * @param protocol the IP protocol (eg, 6 or 17 for TCP or UDP)
 * @param source the TCP or UDP source port
 * @param dest the TCP or UDP destination port
 * @returns a hint as to which port is the server port
 */
DLLEXPORT int8_t trace_get_server_port(UNUSED uint8_t protocol, 
		uint16_t source, uint16_t dest) 
{
	/*
	 * * If the ports are equal, return DEST
	 * * Check for well-known ports in the given protocol
	 * * Root server ports: 0 - 511
	 * * Root client ports: 512 - 1023
	 * * non-root client ports: 1024 - 4999
	 * * non-root server ports: 5000+
	 * * Check for static ranges: 1024 - 49151
	 * * Check for dynamic ranges: 49152 - 65535
	 * * flip a coin.
	 */
	
	/* equal */
	if (source == dest)
		return USE_DEST;

	/* root server port, 0 - 511 */
	if (ROOT_SERVER(source) && ROOT_SERVER(dest)) {
		if (source < dest)
			return USE_SOURCE;
		return USE_DEST;
	}

	if (ROOT_SERVER(source) && !ROOT_SERVER(dest))
		return USE_SOURCE;
	if (!ROOT_SERVER(source) && ROOT_SERVER(dest))
		return USE_DEST;

	/* non-root server */
	if (NONROOT_SERVER(source) && NONROOT_SERVER(dest)) {
		if (source < dest)
			return USE_SOURCE;
		return USE_DEST;
	}
	if (NONROOT_SERVER(source) && !NONROOT_SERVER(dest))
		return USE_SOURCE;
	if (!NONROOT_SERVER(source) && NONROOT_SERVER(dest))
		return USE_DEST;

	/* root client */
	if (ROOT_CLIENT(source) && ROOT_CLIENT(dest)) {
		if (source < dest)
			return USE_SOURCE;
		return USE_DEST;
	}
	if (ROOT_CLIENT(source) && !ROOT_CLIENT(dest)) {
		/* prefer root-client over nonroot-client */
		if (NONROOT_CLIENT(dest))
			return USE_SOURCE;
		return USE_DEST;
	}
	if (!ROOT_CLIENT(source) && ROOT_CLIENT(dest)) {
		/* prefer root-client over nonroot-client */
		if (NONROOT_CLIENT(source))
			return USE_DEST;
		return USE_SOURCE;
	}
	
	/* nonroot client */
	if (NONROOT_CLIENT(source) && NONROOT_CLIENT(dest)) {
		if (source < dest) 
			return USE_SOURCE;
		return USE_DEST;
	}
	if (NONROOT_CLIENT(source) && !NONROOT_CLIENT(dest))
		return USE_DEST;
	if (!NONROOT_CLIENT(source) && NONROOT_CLIENT(dest))
		return USE_SOURCE;

	/* dynamic range */
	if (DYNAMIC(source) && DYNAMIC(dest))
		if (source < dest)
			return USE_SOURCE;
		return USE_DEST;
	if (DYNAMIC(source) && !DYNAMIC(dest))
		return USE_DEST;
	if (!DYNAMIC(source) && DYNAMIC(dest))
		return USE_SOURCE;
	/*
	if (SERVER(source) && CLIENT(dest)) 
		return USE_SOURCE;
	
	if (SERVER(dest) && CLIENT(source)) 
		return USE_DEST;
	if (ROOT_SERVER(source) && !ROOT_SERVER(dest)) 
		return USE_SOURCE;
	if (ROOT_SERVER(dest) && !ROOT_SERVER(source)) 
		return USE_DEST;
	*/
	/* failing that test... */
	if (source < dest) {
		return USE_SOURCE;
	} 
	return USE_DEST;
	
}

/* Truncate the packet at the suggested length
 * @param packet	the packet opaque pointer
 * @param size		the new length of the packet
 * @returns the new size of the packet
 * @note size and the return size refer to the network-level payload of the
 * packet, and do not include any capture headers. For example, to truncate a
 * packet after the IP header, set size to sizeof(ethernet_header) +
 * sizeof(ip_header)
 * @note If the original network-level payload is smaller than size, then the
 * original size is returned and the packet is left unchanged.
 * @author Daniel Lawson
 */
DLLEXPORT size_t trace_set_capture_length(libtrace_packet_t *packet, size_t size) {
	assert(packet);
	assert(packet->size>0 && packet->size<65536);

	if (packet->trace->format->set_capture_length) {
		int caplen=packet->trace->format->set_capture_length(packet,size);
		if (caplen!=-1) {
			packet->size=trace_get_framing_length(packet)+caplen;
		}
		return caplen;
	}

	return ~0U;
}

DLLEXPORT const char * trace_parse_uri(const char *uri, char **format) {
	const char *uridata = 0;
	
	if((uridata = strchr(uri,':')) == NULL) {
                /* badly formed URI - needs a : */
                return 0;
        }

        if ((uridata - uri) > URI_PROTO_LINE) {
                /* badly formed URI - uri type is too long */
                return 0;
        }

        *format=xstrndup(uri, (uridata - uri));

	/* push uridata past the delimiter */
        uridata++;
	
	return uridata;
}

enum base_format_t trace_get_format(libtrace_packet_t *packet) 
{
	assert(packet);

	return packet->trace->format->type;
}
	
DLLEXPORT libtrace_err_t trace_get_err(libtrace_t *trace)
{
	libtrace_err_t err = trace->err;
	trace->err.err_num = 0; /* "OK" */
	trace->err.problem[0]='\0';
	return err;
}

DLLEXPORT bool trace_is_err(libtrace_t *trace)
{
	return trace->err.err_num != 0;
}

DLLEXPORT void trace_perror(libtrace_t *trace,const char *msg,...)
{
	char buf[256];
	va_list va;
	va_start(va,msg);
	vsnprintf(buf,sizeof(buf),msg,va);
	va_end(va);
	if(trace->err.err_num) {
		fprintf(stderr,"%s(%s): %s\n",
				buf,trace->uridata,trace->err.problem);
	} else {
		fprintf(stderr,"%s(%s): No error\n",
				buf,trace->uridata);
	}
	trace->err.err_num = 0; /* "OK" */
	trace->err.problem[0]='\0';
}

DLLEXPORT libtrace_err_t trace_get_err_output(libtrace_out_t *trace)
{
	libtrace_err_t err = trace->err;
	trace->err.err_num = TRACE_ERR_NOERROR; /* "OK" */
	trace->err.problem[0]='\0';
	return err;
}

DLLEXPORT bool trace_is_err_output(libtrace_out_t *trace)
{
	return trace->err.err_num != 0;
}

DLLEXPORT void trace_perror_output(libtrace_out_t *trace,const char *msg,...)
{
	char buf[256];
	va_list va;
	va_start(va,msg);
	vsnprintf(buf,sizeof(buf),msg,va);
	va_end(va);
	if(trace->err.err_num) {
		fprintf(stderr,"%s(%s): %s\n",
				buf,trace->uridata,trace->err.problem);
	} else {
		fprintf(stderr,"%s(%s): No error\n",buf,trace->uridata);
	}
	trace->err.err_num = TRACE_ERR_NOERROR; /* "OK" */
	trace->err.problem[0]='\0';
}

DLLEXPORT int trace_seek_erf_timestamp(libtrace_t *trace, uint64_t ts)
{
	if (trace->format->seek_erf) {
		return trace->format->seek_erf(trace,ts);
	}
	else {
		if (trace->format->seek_timeval) {
			struct timeval tv;
#if __BYTE_ORDER == __BIG_ENDIAN
			tv.tv_sec = ts & 0xFFFFFFFF;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			tv.tv_sec = ts >> 32;
#else
#error "What on earth are you running this on?"
#endif
			tv.tv_usec = ((ts&0xFFFFFFFF)*1000000)>>32;
			if (tv.tv_usec >= 1000000) {
				tv.tv_usec -= 1000000;
				tv.tv_sec += 1;
			}
			return trace->format->seek_timeval(trace,tv);
		}
		if (trace->format->seek_seconds) {
			double seconds =  
				(ts>>32) + ((ts & UINT_MAX)*1.0 / UINT_MAX);
			return trace->format->seek_seconds(trace,seconds);
		}
		trace_set_err(trace,
				TRACE_ERR_OPTION_UNAVAIL,
				"Feature unimplemented");
		return -1;
	}
}

DLLEXPORT int trace_seek_seconds(libtrace_t *trace, double seconds)
{
	if (trace->format->seek_seconds) {
		return trace->format->seek_seconds(trace,seconds);
	}
	else {
		if (trace->format->seek_timeval) {
			struct timeval tv;
			tv.tv_sec = (uint32_t)seconds;
			tv.tv_usec = (uint32_t)(((seconds - tv.tv_sec) * 1000000)/UINT_MAX);
			return trace->format->seek_timeval(trace,tv);
		}
		if (trace->format->seek_erf) {
			uint64_t timestamp = 
				((uint64_t)((uint32_t)seconds) << 32) + \
			    (uint64_t)(( seconds - (uint32_t)seconds   ) * UINT_MAX);
			return trace->format->seek_erf(trace,timestamp);
		}
		trace_set_err(trace,
				TRACE_ERR_OPTION_UNAVAIL,
				"Feature unimplemented");
		return -1;
	}
}

DLLEXPORT int trace_seek_timeval(libtrace_t *trace, struct timeval tv)
{
	if (trace->format->seek_timeval) {
		return trace->format->seek_timeval(trace,tv);
	}
	else {
		if (trace->format->seek_erf) {
			uint64_t timestamp = ((((uint64_t)tv.tv_sec) << 32) + \
				(((uint64_t)tv.tv_usec * UINT_MAX)/1000000));
			return trace->format->seek_erf(trace,timestamp);
		}
		if (trace->format->seek_seconds) {
			double seconds = tv.tv_sec + ((tv.tv_usec * 1.0)/1000000);
			return trace->format->seek_seconds(trace,seconds);
		}
		trace_set_err(trace,
				TRACE_ERR_OPTION_UNAVAIL,
				"Feature unimplemented");
		return -1;
	}
}

DLLEXPORT char *trace_ether_ntoa(const uint8_t *addr, char *buf)
{
	char *buf2 = buf;
	char staticbuf[18]={0,};
	if (!buf2)
		buf2=staticbuf;
	snprintf(buf2,18,"%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0],addr[1],addr[2],
			addr[3],addr[4],addr[5]);
	return buf2;
}

DLLEXPORT uint8_t *trace_ether_aton(const char *buf, uint8_t *addr)
{
	uint8_t *buf2 = addr;
	unsigned int tmp[6];
	static uint8_t staticaddr[6];
	if (!buf2)
		buf2=staticaddr;
	sscanf(buf,"%x:%x:%x:%x:%x:%x",
			&tmp[0],&tmp[1],&tmp[2],
			&tmp[3],&tmp[4],&tmp[5]);
	buf2[0]=tmp[0]; buf2[1]=tmp[1]; buf2[2]=tmp[2];
	buf2[3]=tmp[3]; buf2[4]=tmp[4]; buf2[5]=tmp[5];
	return buf2;
}

DLLEXPORT
void trace_construct_packet(libtrace_packet_t *packet,
		libtrace_linktype_t linktype,
		const void *data,
		uint16_t len)
{
	libtrace_t *deadtrace=NULL;
	libtrace_pcapfile_pkt_hdr_t hdr;
	struct timeval tv;
	if (NULL == deadtrace) deadtrace=trace_create_dead("pcapfile");
	gettimeofday(&tv,NULL);
	hdr.ts_sec=tv.tv_sec;
	hdr.ts_usec=tv.tv_usec;
	hdr.caplen=len;
	hdr.wirelen=len;

	packet->trace=deadtrace;
	packet->size=len+sizeof(hdr);
	if (packet->buf_control==TRACE_CTRL_PACKET) {
		packet->buffer=realloc(packet->buffer,packet->size);
	}
	else {
		packet->buffer=malloc(packet->size);
	}
	packet->buf_control=TRACE_CTRL_PACKET;
	packet->header=packet->buffer;
	packet->payload=(void*)((char*)packet->buffer+sizeof(hdr));
	memcpy(packet->header,&hdr,sizeof(hdr));
	memcpy(packet->payload,data,len);
	packet->type=pcap_dlt_to_rt(libtrace_to_pcap_dlt(linktype));
}
