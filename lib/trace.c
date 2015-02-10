/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock 
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
#ifndef WIN32
#include <sys/socket.h>
#endif
#include <stdarg.h>
#include <sys/param.h>

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
#ifdef WIN32
#include <sys/timeb.h>
#endif

#include "libtrace.h"
#include "libtrace_int.h"

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

/* This file contains much of the implementation of the libtrace API itself. */

static struct libtrace_format_t *formats_list = NULL;

volatile int libtrace_halt = 0;

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


/* call all the constructors if they haven't yet all been called */
static void trace_init(void)
{
	if (!formats_list) {
		duck_constructor();
		erf_constructor();
		tsh_constructor();
		legacy_constructor();
		atmhdr_constructor();
		linuxnative_constructor();
#ifdef HAVE_LIBPCAP
		pcap_constructor();
#endif
		bpf_constructor();
		pcapfile_constructor();
		rt_constructor();
#ifdef HAVE_DAG
		dag_constructor();
#endif
#ifdef HAVE_DPDK
        dpdk_constructor();
#endif
	}
}

/* Prints help information for libtrace 
 *
 * Function prints out some basic help information regarding libtrace,
 * and then prints out the help() function registered with each input module
 */
DLLEXPORT void trace_help(void) {
	struct libtrace_format_t *tmp;
	trace_init();
	printf("libtrace %s\n\n",PACKAGE_VERSION);
	printf("Following this are a list of the format modules supported in this build of libtrace\n\n");
	for(tmp=formats_list;tmp;tmp=tmp->next) {
		if (tmp->help)
			tmp->help();
	}
}

#define URI_PROTO_LINE 16U

/* Try to guess which format module is appropriate for a given trace file or
 * device */
static void guess_format(libtrace_t *libtrace, const char *filename)
{
	struct libtrace_format_t *tmp;
	
	/* Try and guess based on filename */
	for(tmp = formats_list; tmp; tmp=tmp->next) {
		if (tmp->probe_filename && tmp->probe_filename(filename)) {
			libtrace->format = tmp;
			libtrace->uridata = strdup(filename);
			return;
		}
	}

	libtrace->io = wandio_create(filename);
	if (!libtrace->io)
		return;

	/* Try and guess based on file magic */
	for(tmp = formats_list; tmp; tmp=tmp->next) {
		if (tmp->probe_magic && tmp->probe_magic(libtrace->io)) {
			libtrace->format = tmp;
			libtrace->uridata = strdup(filename);
			return;
		}
	}
	
	/* Oh well */
	return;
}

/* Creates an input trace from a URI
 *
 * @params char * containing a valid libtrace URI
 * @returns opaque pointer to a libtrace_t
 *
 * Some valid URI's are:
 *  erf:/path/to/erf/file
 *  erf:/path/to/erf/file.gz
 *  erf:-  			(stdin)
 *  dag:/dev/dagcard
 *  pcapint:pcapinterface 		(eg: pcapint:eth0)
 *  pcapfile:/path/to/pcap/file
 *  pcapfile:-
 *  int:interface			(eg: int:eth0) only on Linux
 *  rt:hostname
 *  rt:hostname:port
 *
 * If an error occured when attempting to open a trace, NULL is returned
 * and an error is output to stdout.
 */
DLLEXPORT libtrace_t *trace_create(const char *uri) {
        libtrace_t *libtrace = 
			(libtrace_t *)malloc(sizeof(libtrace_t));
        char *scan = 0;
        const char *uridata = 0;                  

	trace_init();

	assert(uri && "Passing NULL to trace_create makes me a very sad program");

	if (!libtrace) {
		/* Out of memory */
		return NULL;
	}
	
	libtrace->err.err_num = TRACE_ERR_NOERROR;
	libtrace->format=NULL;
        
	libtrace->event.tdelta = 0.0;
	libtrace->event.packet = NULL;
	libtrace->event.psize = 0;
	libtrace->event.trace_last_ts = 0.0;
	libtrace->event.waiting = false;
	libtrace->filter = NULL;
	libtrace->snaplen = 0;
	libtrace->started=false;
	libtrace->uridata = NULL;
	libtrace->io = NULL;
	libtrace->filtered_packets = 0;
	libtrace->accepted_packets = 0;

        /* Parse the URI to determine what sort of trace we are dealing with */
	if ((uridata = trace_parse_uri(uri, &scan)) == 0) {
		/* Could not parse the URI nicely */
		guess_format(libtrace,uri);
		if (!libtrace->format) {
			trace_set_err(libtrace,TRACE_ERR_BAD_FORMAT,"Unable to guess format (%s)",uri);
			return libtrace;
		}
	}
	else {
		struct libtrace_format_t *tmp;

		/* Find a format that matches the first part of the URI */
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
	}
        /* libtrace->format now contains the type of uri
         * libtrace->uridata contains the appropriate data for this
	 */
       
       	/* Call the init_input function for the matching capture format */ 
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
	
	if (scan)
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
		xstrncpy(scan,uri, (size_t)(uridata - uri));
	}
	
	libtrace->err.err_num = TRACE_ERR_NOERROR;
	libtrace->format=NULL;
        
	libtrace->event.tdelta = 0.0;
	libtrace->event.packet = NULL;
	libtrace->event.psize = 0;
	libtrace->event.trace_last_ts = 0.0;
	libtrace->filter = NULL;
	libtrace->snaplen = 0;
	libtrace->started=false;
	libtrace->uridata = NULL;
	libtrace->io = NULL;
	libtrace->filtered_packets = 0;
	
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

/* Creates an output trace from a URI. 
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
        libtrace->format = NULL;
	libtrace->uridata = NULL;
	
        /* Parse the URI to determine what capture format we want to write */

	if ((uridata = trace_parse_uri(uri, &scan)) == 0) {
		trace_set_err_out(libtrace,TRACE_ERR_BAD_FORMAT,
				"Bad uri format (%s)",uri);
		return libtrace;
	}
	
	/* Attempt to find the format in the list of supported formats */
	for(tmp=formats_list;tmp;tmp=tmp->next) {
                if (strlen(scan) == strlen(tmp->name) &&
                                !strncasecmp(scan,
                                        tmp->name,
                                        strlen(scan))) {
                                libtrace->format=tmp;
                                break;
                                }
        }
	free(scan);

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
				assert(!"Internal error: init_output() should return -1 for failure, or 0 for success");
		}
	} else {
		trace_set_err_out(libtrace,TRACE_ERR_UNSUPPORTED,
				"Format does not support writing (%s)",scan);
                return libtrace;
        }


	libtrace->started=false;
	return libtrace;
}

/* Start an input trace
 * @param libtrace	the input trace to start
 * @returns 0 on success
 *
 * This does the work associated with actually starting up
 * the trace.  it may fail.
 */
DLLEXPORT int trace_start(libtrace_t *libtrace)
{
	assert(libtrace);
	if (trace_is_err(libtrace))
		return -1;
	if (libtrace->format->start_input) {
		int ret=libtrace->format->start_input(libtrace);
		if (ret < 0) {
			return ret;
		}
	}

	libtrace->started=true;
	return 0;
}

/* Start an output trace */
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
	if (!libtrace->started) {
		trace_set_err(libtrace,TRACE_ERR_BAD_STATE, "You must call trace_start() before calling trace_pause()");
		return -1;
	}
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

	if (trace_is_err(libtrace)) {
		return -1;
	}
	
	/* If the capture format supports configuration, try using their
	 * native configuration first */
	if (libtrace->format->config_input) {
		ret=libtrace->format->config_input(libtrace,option,value);
		if (ret==0)
			return 0;
	}

	/* If we get here, either the native configuration failed or the
	 * format did not support configuration. However, libtrace can 
	 * deal with some options itself, so give that a go */
	switch(option) {
		case TRACE_OPTION_SNAPLEN:
			/* Clear the error if there was one */
			if (trace_is_err(libtrace)) {
				trace_get_err(libtrace);
			}
			if (*(int*)value<0 
				|| *(int*)value>LIBTRACE_PACKET_BUFSIZE) {
				trace_set_err(libtrace,TRACE_ERR_BAD_STATE,
					"Invalid snap length");
			}
			libtrace->snaplen=*(int*)value;
			return 0;
		case TRACE_OPTION_FILTER:
			/* Clear the error if there was one */
			if (trace_is_err(libtrace)) {
				trace_get_err(libtrace);
			}
			libtrace->filter=(libtrace_filter_t *)value;
			return 0;
		case TRACE_OPTION_PROMISC:
			if (!trace_is_err(libtrace)) {
				trace_set_err(libtrace,TRACE_ERR_OPTION_UNAVAIL,
						"Promisc mode is not supported by this format module");
			}
			return -1;
		case TRACE_OPTION_META_FREQ:
			if (!trace_is_err(libtrace)) {
				trace_set_err(libtrace, 
						TRACE_ERR_OPTION_UNAVAIL,
						"This format does not support meta-data gathering");
			}
			return -1;
		case TRACE_OPTION_EVENT_REALTIME:
			if (!trace_is_err(libtrace)) {
				trace_set_err(libtrace, 
						TRACE_ERR_OPTION_UNAVAIL,
						"This format does not support realtime events");
			}
			return -1;
			
	}
	if (!trace_is_err(libtrace)) {
		trace_set_err(libtrace,TRACE_ERR_UNKNOWN_OPTION,
			"Unknown option %i", option);
	}
	return -1;
}

DLLEXPORT int trace_config_output(libtrace_out_t *libtrace, 
		trace_option_output_t option,
		void *value) {
	
	/* Unlike the input options, libtrace does not natively support any of
	 * the output options - the format module must be able to deal with
	 * them. */
	if (libtrace->format->config_output) {
		return libtrace->format->config_output(libtrace, option, value);
	}
	return -1;
}

/* Close an input trace file, freeing up any resources it may have been using
 *
 */
DLLEXPORT void trace_destroy(libtrace_t *libtrace) {
        assert(libtrace);
	if (libtrace->format) {
		if (libtrace->started && libtrace->format->pause_input)
			libtrace->format->pause_input(libtrace);
		if (libtrace->format->fin_input)
			libtrace->format->fin_input(libtrace);
	}
        /* Need to free things! */
        if (libtrace->uridata)
		free(libtrace->uridata);
	if (libtrace->event.packet) {
		/* Don't use trace_destroy_packet here - there is almost
		 * certainly going to be another libtrace_packet_t that is
		 * pointing to the buffer for this packet, so we don't want
		 * to free it. Rather, it will get freed when the user calls
		 * trace_destroy_packet on the libtrace_packet_t that they
		 * own.
		 *
		 * All we need to do then is free our packet structure itself.
		 */
		 free(libtrace->event.packet);
	}
        free(libtrace);
}


DLLEXPORT void trace_destroy_dead(libtrace_t *libtrace) {
	assert(libtrace);

	/* Don't call pause_input or fin_input, because we should never have
	 * used this trace to do any reading anyway. Do make sure we free
	 * any format_data that has been created, though. */
	if (libtrace->format_data)
		free(libtrace->format_data);
	free(libtrace);
}
/* Close an output trace file, freeing up any resources it may have been using
 *
 * @param libtrace	the output trace file to be destroyed
 */
DLLEXPORT void trace_destroy_output(libtrace_out_t *libtrace) 
{
	assert(libtrace);
	if (libtrace->format && libtrace->format->fin_output)
		libtrace->format->fin_output(libtrace);
	if (libtrace->uridata)
		free(libtrace->uridata);
	free(libtrace);
}

DLLEXPORT libtrace_packet_t *trace_create_packet(void) 
{
	libtrace_packet_t *packet = 
		(libtrace_packet_t*)calloc((size_t)1,sizeof(libtrace_packet_t));

	packet->buf_control=TRACE_CTRL_PACKET;
	trace_clear_cache(packet);
	return packet;
}

DLLEXPORT libtrace_packet_t *trace_copy_packet(const libtrace_packet_t *packet) {
	libtrace_packet_t *dest = 
		(libtrace_packet_t *)malloc(sizeof(libtrace_packet_t));
	if (!dest) {
		printf("Out of memory constructing packet\n");
		abort();
	}
	dest->trace=packet->trace;
	dest->buffer=malloc(65536);
	if (!dest->buffer) {
		printf("Out of memory allocating buffer memory\n");
		abort();
	}
	dest->header=dest->buffer;
	dest->payload=(void*)
		((char*)dest->buffer+trace_get_framing_length(packet));
	dest->type=packet->type;
	dest->buf_control=TRACE_CTRL_PACKET;
	/* Reset the cache - better to recalculate than try to convert
	 * the values over to the new packet */
	trace_clear_cache(dest);	
	/* Ooooh nasty memcpys! This is why we want to avoid copying packets
	 * as much as possible */
	memcpy(dest->header,packet->header,trace_get_framing_length(packet));
	memcpy(dest->payload,packet->payload,trace_get_capture_length(packet));

	return dest;
}

/** Destroy a packet object
 */
DLLEXPORT void trace_destroy_packet(libtrace_packet_t *packet) {
	if (packet->buf_control == TRACE_CTRL_PACKET && packet->buffer) {
		free(packet->buffer);
	}
	packet->buf_control=(buf_control_t)'\0'; 
				/* A "bad" value to force an assert
				 * if this packet is ever reused
				 */
	free(packet);
}	

/* Read one packet from the trace into buffer. Note that this function will
 * block until a packet is read (or EOF is reached).
 *
 * @param libtrace 	the libtrace opaque pointer
 * @param packet  	the packet opaque pointer
 * @returns 0 on EOF, negative value on error
 *
 */
DLLEXPORT int trace_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {

	assert(libtrace && "You called trace_read_packet() with a NULL libtrace parameter!\n");
	if (trace_is_err(libtrace))
		return -1;
	if (!libtrace->started) {
		trace_set_err(libtrace,TRACE_ERR_BAD_STATE,"You must call libtrace_start() before trace_read_packet()\n");
		return -1;
	}
	if (!(packet->buf_control==TRACE_CTRL_PACKET || packet->buf_control==TRACE_CTRL_EXTERNAL)) {
		trace_set_err(libtrace,TRACE_ERR_BAD_STATE,"Packet passed to trace_read_packet() is invalid\n");
		return -1;
	}
	assert(packet);
      
	/* Store the trace we are reading from into the packet opaque 
	 * structure */
	packet->trace = libtrace;

	/* Finalise the packet, freeing any resources the format module
	 * may have allocated it
	 */
	if (libtrace->format->fin_packet) {
		libtrace->format->fin_packet(packet);
	}


	if (libtrace->format->read_packet) {
		do {
			size_t ret;
                        int filtret;
			/* Clear the packet cache */
			trace_clear_cache(packet);
			ret=libtrace->format->read_packet(libtrace,packet);
			if (ret==(size_t)-1 || ret==0) {
				return ret;
			}
			if (libtrace->filter) {
				/* If the filter doesn't match, read another
				 * packet
				 */
                                filtret = trace_apply_filter(libtrace->filter, packet);
                                if (filtret == -1) {
                                        /* Error compiling filter, probably */
                                        return ~0U;
                                }
                                
                                if (filtret == 0) {
					++libtrace->filtered_packets;
					continue;
				}
			}
			if (libtrace->snaplen>0) {
				/* Snap the packet */
				trace_set_capture_length(packet,
						libtrace->snaplen);
			}
			++libtrace->accepted_packets;
			return ret;
		} while(1);
	}
	trace_set_err(libtrace,TRACE_ERR_UNSUPPORTED,"This format does not support reading packets\n");
	return ~0U;
}

/* Converts the provided buffer into a libtrace packet of the given type.
 *
 * Unlike trace_construct_packet, the buffer is expected to begin with the
 * appropriate capture format header for the format type that the packet is
 * being converted to. This also allows for a packet to be converted into
 * just about capture format that is supported by libtrace, provided the 
 * format header is present in the buffer.
 *
 * This function is primarily used to convert packets received via the RT
 * protocol back into their original capture format. The RT header encapsulates
 * the original capture format header, so after removing it the packet must 
 * have it's header and payload pointers updated and the packet format and type
 * changed, amongst other things.
 *
 * Intended only for internal use at this point - this function is not 
 * available through the external libtrace API.
 */
int trace_prepare_packet(libtrace_t *trace, libtrace_packet_t *packet,
		void *buffer, libtrace_rt_types_t rt_type, uint32_t flags) {

	assert(packet);
	assert(trace);
	
	/* XXX Proper error handling?? */
	if (buffer == NULL)
		return -1;

	if (!(packet->buf_control==TRACE_CTRL_PACKET || packet->buf_control==TRACE_CTRL_EXTERNAL)) {
		trace_set_err(trace,TRACE_ERR_BAD_STATE,"Packet passed to trace_read_packet() is invalid\n");
		return -1;
	}
	
	packet->trace = trace;
	
	/* Clear packet cache */
	trace_clear_cache(packet);

	if (trace->format->prepare_packet) {
		return trace->format->prepare_packet(trace, packet,
				buffer, rt_type, flags);
	}
	trace_set_err(trace, TRACE_ERR_UNSUPPORTED, 
			"This format does not support preparing packets\n");
	return -1;

}

/* Writes a packet to the specified output trace
 *
 * @param libtrace	describes the output format, destination, etc.
 * @param packet	the packet to be written out
 * @returns the number of bytes written, -1 if write failed
 */
DLLEXPORT int trace_write_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	assert(libtrace);
	assert(packet);	
	/* Verify the packet is valid */
	if (!libtrace->started) {
		trace_set_err_out(libtrace,TRACE_ERR_BAD_STATE,
			"Trace is not started before trace_write_packet");
		return -1;
	}

	if (libtrace->format->write_packet) {
		return libtrace->format->write_packet(libtrace, packet);
	}
	trace_set_err_out(libtrace,TRACE_ERR_UNSUPPORTED,
		"This format does not support writing packets");
	return -1;
}

/* Get a pointer to the first byte of the packet payload */
DLLEXPORT void *trace_get_packet_buffer(const libtrace_packet_t *packet,
		libtrace_linktype_t *linktype, uint32_t *remaining) {
	int cap_len;
	int wire_len;

	assert(packet != NULL);
	if (linktype) *linktype = trace_get_link_type(packet);
	if (remaining) {
		/* I think we should choose the minimum of the capture and
		 * wire lengths to be the "remaining" value. If the packet has
		 * been padded to increase the capture length, we don't want
		 * to allow subsequent protocol decoders to consider the 
		 * padding as part of the packet.
		 *
		 * For example, in Auck 4 there is a trace where the IP header
		 * length is incorrect (24 bytes) followed by a 20 byte TCP
		 * header. Total IP length is 40 bytes. As a result, the
		 * legacyatm padding gets treated as the "missing" bytes of
		 * the TCP header, which isn't the greatest. We're probably
		 * better off returning an incomplete TCP header in that case.
		 */
		
		cap_len = trace_get_capture_length(packet);
		wire_len = trace_get_wire_length(packet);

		assert(cap_len >= 0);

		/* There is the odd corrupt packet, e.g. in IPLS II, that have
		 * massively negative wire lens. We could assert fail here on
		 * them, but we could at least try the capture length instead.
		 * 
		 * You may still run into problems if you try to write that
		 * packet, but at least reading should work OK.
		 */
		if (wire_len < 0)
			*remaining = cap_len;
		else if (wire_len < cap_len)
			*remaining = wire_len;
		else
			*remaining = cap_len;
		/* *remaining = trace_get_capture_length(packet); */
	}
	return (void *) packet->payload;
}


/* Get a pointer to the first byte of the packet payload 
 *
 * DEPRECATED - use trace_get_packet_buffer() instead */
DLLEXPORT void *trace_get_link(const libtrace_packet_t *packet) {
	return (void *)packet->payload;
}

/* Get the current time in DAG time format 
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns a 64 bit timestamp in DAG ERF format (upper 32 bits are the seconds
 * past 1970-01-01, the lower 32bits are partial seconds)
 */ 
DLLEXPORT uint64_t trace_get_erf_timestamp(const libtrace_packet_t *packet) {
	if (packet->trace->format->get_erf_timestamp) {
		/* timestamp -> timestamp */
		return packet->trace->format->get_erf_timestamp(packet);
	} else if (packet->trace->format->get_timespec) {
		/* timespec -> timestamp */
		struct timespec ts;
		ts = packet->trace->format->get_timespec(packet);
		return ((((uint64_t)ts.tv_sec) << 32) +
				(((uint64_t)ts.tv_nsec << 32)/1000000000));
	} else if (packet->trace->format->get_timeval) {
		/* timeval -> timestamp */
		struct timeval tv;
		tv = packet->trace->format->get_timeval(packet);
		return ((((uint64_t)tv.tv_sec) << 32) +
				(((uint64_t)tv.tv_usec << 32)/1000000));
	} else if (packet->trace->format->get_seconds) {
		/* seconds -> timestamp */
		double seconds = packet->trace->format->get_seconds(packet);
		return (((uint64_t)seconds)<<32)
		          + (uint64_t)((seconds-(uint64_t)seconds)*UINT_MAX);
	}
	else {
		return (uint64_t)0;
	}
		      
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
	if (packet->trace->format->get_timeval) {
		/* timeval -> timeval */
		tv = packet->trace->format->get_timeval(packet);
	} else if (packet->trace->format->get_erf_timestamp) {
		/* timestamp -> timeval */
		ts = packet->trace->format->get_erf_timestamp(packet);
		tv.tv_sec = ts >> 32;
		tv.tv_usec = ((ts&0xFFFFFFFF)*1000000)>>32;
       		if (tv.tv_usec >= 1000000) {
               		tv.tv_usec -= 1000000;
               		tv.tv_sec += 1;
       		}
	} else if (packet->trace->format->get_timespec) {
		struct timespec ts = packet->trace->format->get_timespec(packet);
		tv.tv_sec = ts.tv_sec;
		tv.tv_usec = ts.tv_nsec/1000;
	} else if (packet->trace->format->get_seconds) {
		/* seconds -> timeval */
		double seconds = packet->trace->format->get_seconds(packet);
		tv.tv_sec = (uint32_t)seconds;
		tv.tv_usec = (uint32_t)(((seconds - tv.tv_sec) * 1000000)/UINT_MAX);
	}
	else {
		tv.tv_sec=-1;
		tv.tv_usec=-1;
	}

        return tv;
}

DLLEXPORT struct timespec trace_get_timespec(const libtrace_packet_t *packet) {
	struct timespec ts;

	if (packet->trace->format->get_timespec) {
		return packet->trace->format->get_timespec(packet);
	} else if (packet->trace->format->get_erf_timestamp) {
		/* timestamp -> timeval */
		uint64_t erfts = packet->trace->format->get_erf_timestamp(packet);
		ts.tv_sec = erfts >> 32;
		ts.tv_nsec = ((erfts&0xFFFFFFFF)*1000000000)>>32;
       		if (ts.tv_nsec >= 1000000000) {
               		ts.tv_nsec -= 1000000000;
               		ts.tv_sec += 1;
       		}
		return ts;
	} else if (packet->trace->format->get_timeval) {
		/* timeval -> timespec */
		struct timeval tv = packet->trace->format->get_timeval(packet);
		ts.tv_sec = tv.tv_sec;
		ts.tv_nsec = tv.tv_usec*1000;
		return ts;
	} else if (packet->trace->format->get_seconds) {
		/* seconds -> timespec */
		double seconds = packet->trace->format->get_seconds(packet);
		ts.tv_sec = (uint32_t)seconds;
		ts.tv_nsec = (long)(((seconds - ts.tv_sec) * 1000000000)/UINT_MAX);
		return ts;
	}
	else {
		ts.tv_sec=-1;
		ts.tv_nsec=-1;
		return ts;
	}
}


/* Get the current time in floating point seconds
 * @param packet 	a pointer to a libtrace_packet structure
 * @returns time that this packet was seen in 64bit floating point seconds
 */ 
DLLEXPORT double trace_get_seconds(const libtrace_packet_t *packet) {
	double seconds = 0.0;

	if (packet->trace->format->get_seconds) {
		/* seconds->seconds */
		seconds = packet->trace->format->get_seconds(packet);
	} else if (packet->trace->format->get_erf_timestamp) {
		/* timestamp -> seconds */
		uint64_t ts = 0;
		ts = packet->trace->format->get_erf_timestamp(packet);
		seconds =  (ts>>32) + ((ts & UINT_MAX)*1.0 / UINT_MAX);
	} else if (packet->trace->format->get_timespec) {
		/* timespec -> seconds */
		struct timespec ts;
		ts = packet->trace->format->get_timespec(packet);
		seconds = ts.tv_sec + ((ts.tv_nsec * 1.0) / 1000000000);
	} else if (packet->trace->format->get_timeval) {
		/* timeval -> seconds */
		struct timeval tv;
		tv = packet->trace->format->get_timeval(packet);
		seconds = tv.tv_sec + ((tv.tv_usec * 1.0) / 1000000);
	}

	return seconds;
}

DLLEXPORT size_t trace_get_capture_length(const libtrace_packet_t *packet) 
{
	/* Cache the capture length */
	if (packet->capture_length == -1) {
		if (!packet->trace->format->get_capture_length)
			return ~0U;
		/* Cast away constness because this is "just" a cache */
		((libtrace_packet_t*)packet)->capture_length = 
			packet->trace->format->get_capture_length(packet);
	}

	assert(packet->capture_length < LIBTRACE_PACKET_BUFSIZE);

	return packet->capture_length;
}
	
/* Get the size of the packet as it was seen on the wire.
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns the size of the packet as it was on the wire.
 * @note Due to the trace being a header capture, or anonymisation this may
 * not be the same as the Capture Len.
 */ 
DLLEXPORT size_t trace_get_wire_length(const libtrace_packet_t *packet){
	
	if (packet->wire_length == -1) {
		if (!packet->trace->format->get_wire_length) 
			return ~0U;
		((libtrace_packet_t *)packet)->wire_length = 
			packet->trace->format->get_wire_length(packet);
	}

	assert(packet->wire_length < LIBTRACE_PACKET_BUFSIZE);
	return packet->wire_length;

}

/* Get the length of the capture framing headers.
 * @param packet  	the packet opaque pointer
 * @returns the size of the packet as it was on the wire.
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
 */
DLLEXPORT libtrace_linktype_t trace_get_link_type(const libtrace_packet_t *packet ) {

	if (packet->link_type == 0) {
		if (!packet->trace->format->get_link_type)
			return TRACE_TYPE_UNKNOWN;
		((libtrace_packet_t *)packet)->link_type =
			packet->trace->format->get_link_type(packet);
	}

	return packet->link_type;
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
 */
DLLEXPORT libtrace_eventobj_t trace_event(libtrace_t *trace, 
		libtrace_packet_t *packet) {
	libtrace_eventobj_t event = {TRACE_EVENT_IOWAIT,0,0.0,0};

	if (!trace) {
		fprintf(stderr,"You called trace_event() with a NULL trace object!\n");
	}
	assert(trace);
	assert(packet);

	/* Clear the packet cache */
	trace_clear_cache(packet);
	
	/* Store the trace we are reading from into the packet opaque
	 * structure */
	packet->trace = trace;

	if (packet->trace->format->trace_event) {
		/* Note: incrementing accepted, filtered etc. packet
                 * counters is handled by the format-specific 
                 * function so don't increment them here.
                 */
                event=packet->trace->format->trace_event(trace,packet);
	}
	return event;

}

/** Setup a BPF filter based on pre-compiled byte-code.
 * @param bf_insns	A pointer to the start of the byte-code
 * @param bf_len	The number of BPF instructions
 * @returns		an opaque pointer to a libtrace_filter_t object
 * @note		The supplied byte-code is not checked for correctness.
 * @author		Scott Raynel
 */
DLLEXPORT libtrace_filter_t *
trace_create_filter_from_bytecode(void *bf_insns, unsigned int bf_len)
{
#ifndef HAVE_BPF_FILTER
	fprintf(stderr, "This version of libtrace does not have BPF support\n");
	return NULL;
#else
	struct libtrace_filter_t *filter = (struct libtrace_filter_t *)
		malloc(sizeof(struct libtrace_filter_t));
	filter->filter.bf_insns = (struct bpf_insn *)
		malloc(sizeof(struct bpf_insn) * bf_len);
	
	memcpy(filter->filter.bf_insns, bf_insns,
			bf_len * sizeof(struct bpf_insn));
	
	filter->filter.bf_len = bf_len;
	filter->filterstring = NULL;
	filter->jitfilter = NULL;
	/* "flag" indicates that the filter member is valid */
	filter->flag = 1; 
	
	return filter;
#endif
}

/* Create a BPF filter
 * @param filterstring a char * containing the bpf filter string
 * @returns opaque pointer pointer to a libtrace_filter_t object
 */
DLLEXPORT libtrace_filter_t *trace_create_filter(const char *filterstring) {
#ifdef HAVE_BPF_FILTER
	libtrace_filter_t *filter = (libtrace_filter_t*)
				malloc(sizeof(libtrace_filter_t));
	filter->filterstring = strdup(filterstring);
	filter->jitfilter = NULL;
	filter->flag = 0;
	return filter;
#else
	fprintf(stderr,"This version of libtrace does not have bpf filter support\n");
	return NULL;
#endif
}

DLLEXPORT void trace_destroy_filter(libtrace_filter_t *filter)
{
#ifdef HAVE_BPF_FILTER
	free(filter->filterstring);
	if (filter->flag)
		pcap_freecode(&filter->filter);
#ifdef HAVE_LLVM
	if (filter->jitfilter) 
		destroy_program(filter->jitfilter);
#endif
	free(filter);
#else

#endif
}

/* Compile a bpf filter, now we know the link type for the trace that we're
 * applying it to.
 *
 * @internal
 *
 * @returns -1 on error, 0 on success
 */
static int trace_bpf_compile(libtrace_filter_t *filter,
		const libtrace_packet_t *packet,
		void *linkptr, 
		libtrace_linktype_t linktype	) {
#ifdef HAVE_BPF_FILTER
	assert(filter);

	/* If this isn't a real packet, then fail */
	if (!linkptr) {
		trace_set_err(packet->trace,
				TRACE_ERR_BAD_FILTER,"Packet has no payload");
		return -1;
	}
	
	if (filter->filterstring && ! filter->flag) {
		pcap_t *pcap = NULL;
		if (linktype==(libtrace_linktype_t)-1) {
			trace_set_err(packet->trace,
					TRACE_ERR_BAD_FILTER,
					"Packet has an unknown linktype");
			return -1;
		}
		if (libtrace_to_pcap_dlt(linktype) == TRACE_DLT_ERROR) {
			trace_set_err(packet->trace,TRACE_ERR_BAD_FILTER,
					"Unknown pcap equivalent linktype");
			return -1;
		}
		pcap=(pcap_t *)pcap_open_dead(
				(int)libtrace_to_pcap_dlt(linktype),
				1500U);
		/* build filter */
		assert(pcap);
		if (pcap_compile( pcap, &filter->filter, filter->filterstring, 
					1, 0)) {
			trace_set_err(packet->trace,TRACE_ERR_BAD_FILTER,
					"Unable to compile the filter \"%s\": %s", 
					filter->filterstring,
					pcap_geterr(pcap));
			pcap_close(pcap);
			return -1;
		}
		pcap_close(pcap);
		filter->flag=1;
	}
	return 0;
#else
	assert(!"Internal bug: This should never be called when BPF not enabled");
	trace_set_err(packet->trace,TRACE_ERR_OPTION_UNAVAIL,
				"Feature unavailable");
	return -1;
#endif
}

DLLEXPORT int trace_apply_filter(libtrace_filter_t *filter,
			const libtrace_packet_t *packet) {
#ifdef HAVE_BPF_FILTER
	void *linkptr = 0;
	uint32_t clen = 0;
	bool free_packet_needed = false;
	int ret;
	libtrace_linktype_t linktype;
	libtrace_packet_t *packet_copy = (libtrace_packet_t*)packet;

	assert(filter);
	assert(packet);

	/* Match all non-data packets as we probably want them to pass
	 * through to the caller */
	linktype = trace_get_link_type(packet);

	if (linktype == TRACE_TYPE_NONDATA)
		return 1;	

	if (libtrace_to_pcap_dlt(linktype)==TRACE_DLT_ERROR) {
		
		/* If we cannot get a suitable DLT for the packet, it may
		 * be because the packet is encapsulated in a link type that
		 * does not correspond to a DLT. Therefore, we should try
		 * popping off headers until we either can find a suitable
		 * link type or we can't do any more sensible decapsulation. */
		
		/* Copy the packet, as we don't want to trash the one we
		 * were passed in */
		packet_copy=trace_copy_packet(packet);
		free_packet_needed=true;

		while (libtrace_to_pcap_dlt(linktype) == TRACE_DLT_ERROR) {
			if (!demote_packet(packet_copy)) {
				trace_set_err(packet->trace, 
						TRACE_ERR_NO_CONVERSION,
						"pcap does not support this format");
				if (free_packet_needed) {
					trace_destroy_packet(packet_copy);
				}
				return -1;
			}
			linktype = trace_get_link_type(packet_copy);
		}

	}
	
	linkptr = trace_get_packet_buffer(packet_copy,NULL,&clen);
	if (!linkptr) {
		if (free_packet_needed) {
			trace_destroy_packet(packet_copy);
		}
		return 0;
	}

	/* We need to compile the filter now, because before we didn't know 
	 * what the link type was
	 */
	if (trace_bpf_compile(filter,packet_copy,linkptr,linktype)==-1) {
		if (free_packet_needed) {
			trace_destroy_packet(packet_copy);
		}
		return -1;
	}

	/* If we're jitting, we may need to JIT the BPF code now too */
#if HAVE_LLVM
	if (!filter->jitfilter) {
		filter->jitfilter = compile_program(filter->filter.bf_insns, filter->filter.bf_len);
	}
#endif

	assert(filter->flag);
	/* Now execute the filter */
#if HAVE_LLVM
	ret=filter->jitfilter->bpf_run((unsigned char *)linkptr, clen);
#else
	ret=bpf_filter(filter->filter.bf_insns,(u_char*)linkptr,(unsigned int)clen,(unsigned int)clen);
#endif

	/* If we copied the packet earlier, make sure that we free it */
	if (free_packet_needed) {
		trace_destroy_packet(packet_copy);
	}
	return ret;
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
 */
DLLEXPORT libtrace_direction_t trace_get_direction(const libtrace_packet_t *packet) 
{
	assert(packet);
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
	if (DYNAMIC(source) && DYNAMIC(dest)) {
		if (source < dest)
			return USE_SOURCE;
		return USE_DEST;
	}
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
 */
DLLEXPORT size_t trace_set_capture_length(libtrace_packet_t *packet, size_t size) {
	assert(packet);

	if (packet->trace->format->set_capture_length) {
		packet->capture_length = packet->trace->format->set_capture_length(packet,size);
		return packet->capture_length;
	}

	return ~0U;
}

/* Splits a URI into two components - the format component which is seen before
 * the ':', and the uridata which follows the ':'.
 *
 * Returns a pointer to the URI data, but updates the format parameter to
 * point to a copy of the format component. 
 */

DLLEXPORT const char * trace_parse_uri(const char *uri, char **format) {
	const char *uridata = 0;
	
	if((uridata = strchr(uri,':')) == NULL) {
                /* Badly formed URI - needs a : */
                return 0;
        }

        if ((unsigned)(uridata - uri) > URI_PROTO_LINE) {
                /* Badly formed URI - uri type is too long */
                return 0;
        }

	/* NOTE: this is allocated memory - it should be freed by the caller
	 * once they are done with it */
        *format=xstrndup(uri, (size_t)(uridata - uri));

	/* Push uridata past the delimiter */
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

/* Prints the input error status to standard error and clears the error state */
DLLEXPORT void trace_perror(libtrace_t *trace,const char *msg,...)
{
	char buf[256];
	va_list va;
	va_start(va,msg);
	vsnprintf(buf,sizeof(buf),msg,va);
	va_end(va);
	if(trace->err.err_num) {
		if (trace->uridata) {
			fprintf(stderr,"%s(%s): %s\n",
					buf,trace->uridata,trace->err.problem);
		} else {
			fprintf(stderr,"%s: %s\n", buf, trace->err.problem);
		}
	} else {
		if (trace->uridata) {
			fprintf(stderr,"%s(%s): No error\n",buf,trace->uridata);
		} else {
			fprintf(stderr,"%s: No error\n", buf);
		}
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

/* Prints the output error status to standard error and clears the error state
 */
DLLEXPORT void trace_perror_output(libtrace_out_t *trace,const char *msg,...)
{
	char buf[256];
	va_list va;
	va_start(va,msg);
	vsnprintf(buf,sizeof(buf),msg,va);
	va_end(va);
	if(trace->err.err_num) {
		fprintf(stderr,"%s(%s): %s\n",
				buf,
				trace->uridata?trace->uridata:"no uri",
				trace->err.problem);
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
			tv.tv_usec = ((ts >> 32) * 1000000) & 0xFFFFFFFF;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			tv.tv_sec = ts >> 32;
			tv.tv_usec = ((ts&0xFFFFFFFF)*1000000)>>32;
#else
#error "What on earth are you running this on?"
#endif
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

/* Converts a binary ethernet MAC address into a printable string */
DLLEXPORT char *trace_ether_ntoa(const uint8_t *addr, char *buf)
{
	static char staticbuf[18]={0,};
	if (!buf)
		buf=staticbuf;
	snprintf(buf,(size_t)18,"%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0],addr[1],addr[2],
			addr[3],addr[4],addr[5]);
	return buf;
}

/* Converts a printable ethernet MAC address into a binary format */
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


/* Creates a libtrace packet from scratch using the contents of the provided 
 * buffer as the packet payload.
 *
 * Unlike trace_prepare_packet(), the buffer should not contain any capture
 * format headers; instead this function will add the PCAP header to the 
 * packet record. This also means only PCAP packets can be constructed using
 * this function.
 *
 */
DLLEXPORT
void trace_construct_packet(libtrace_packet_t *packet,
		libtrace_linktype_t linktype,
		const void *data,
		uint16_t len)
{
	size_t size;
	static libtrace_t *deadtrace=NULL;
	libtrace_pcapfile_pkt_hdr_t hdr;
#ifdef WIN32
	struct _timeb tstruct;
#else
	struct timeval tv;
#endif

	/* We need a trace to attach the constructed packet to (and it needs
	 * to be PCAP) */
	if (NULL == deadtrace) 
		deadtrace=trace_create_dead("pcapfile");

	/* Fill in the new PCAP header */
#ifdef WIN32
	_ftime(&tstruct);
	hdr.ts_sec=tstruct.time;
	hdr.ts_usec=tstruct.millitm * 1000;
#else
	gettimeofday(&tv,NULL);
	hdr.ts_sec=tv.tv_sec;
	hdr.ts_usec=tv.tv_usec;
#endif

	hdr.caplen=len;
	hdr.wirelen=len;

	/* Now fill in the libtrace packet itself */
	packet->trace=deadtrace;
	size=len+sizeof(hdr);
	if (packet->buf_control==TRACE_CTRL_PACKET) {
		packet->buffer=realloc(packet->buffer,size);
	}
	else {
		packet->buffer=malloc(size);
	}
	packet->buf_control=TRACE_CTRL_PACKET;
	packet->header=packet->buffer;
	packet->payload=(void*)((char*)packet->buffer+sizeof(hdr));
	
	/* Ugh, memcpy - sadly necessary */
	memcpy(packet->header,&hdr,sizeof(hdr));
	memcpy(packet->payload,data,(size_t)len);
	packet->type=pcap_linktype_to_rt(libtrace_to_pcap_linktype(linktype));

	trace_clear_cache(packet);
}


uint64_t trace_get_received_packets(libtrace_t *trace)
{
	assert(trace);
	if (trace->format->get_received_packets) {
		return trace->format->get_received_packets(trace);
	}
	return (uint64_t)-1;
}

uint64_t trace_get_filtered_packets(libtrace_t *trace)
{
	assert(trace);
	if (trace->format->get_filtered_packets) {
		return trace->format->get_filtered_packets(trace)+
			trace->filtered_packets;
	}
	return trace->filtered_packets;
}

uint64_t trace_get_dropped_packets(libtrace_t *trace)
{
	assert(trace);
	if (trace->format->get_dropped_packets) {
		return trace->format->get_dropped_packets(trace);
	}
	return (uint64_t)-1;
}

uint64_t trace_get_accepted_packets(libtrace_t *trace)
{
	assert(trace);
	return trace->accepted_packets;
}

void trace_clear_cache(libtrace_packet_t *packet) {

	packet->l2_header = NULL;
	packet->l3_header = NULL;
	packet->l4_header = NULL;
	packet->link_type = 0;
	packet->l3_ethertype = 0;
	packet->transport_proto = 0;
	packet->capture_length = -1;
	packet->wire_length = -1;
	packet->payload_length = -1;
	packet->l2_remaining = 0;
	packet->l3_remaining = 0;
	packet->l4_remaining = 0;

}

void trace_interrupt(void) {
	libtrace_halt = 1;
}

void register_format(struct libtrace_format_t *f) {
	assert(f->next==NULL); /* Can't register a format twice */
	f->next=formats_list;
	formats_list=f;

	/* Now, verify that the format has at least the minimum functionality.
	 * 
	 * This #if can be changed to a 1 to output warnings about inconsistent
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

