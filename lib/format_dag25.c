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

#include "config.h"
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "format_erf.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <sys/mman.h>
/* XXX: Windows doesn't have pthreads, but this code doesn't compile under
 * Windows anyway so we'll worry about this more later :] */
#include <pthread.h>


#ifdef WIN32
#  include <io.h>
#  include <share.h>
#  define PATH_MAX _MAX_PATH
#  define snprintf sprintf_s
#else
#  include <netdb.h>
#  ifndef PATH_MAX
#       define PATH_MAX 4096
#  endif
#  include <sys/ioctl.h>
#endif

/* This format deals with DAG cards that are using drivers from the 2.5 version
 * onwards, including 3.X.
 *
 * DAG is a LIVE capture format.
 *
 * This format does support writing, provided the DAG card that you are using
 * has transmit (Tx) support. Additionally, packets read using this format
 * are in the ERF format, so can easily be written as ERF traces without
 * losing any data.
 */


#define DATA(x) ((struct dag_format_data_t *)x->format_data)
#define DATA_OUT(x) ((struct dag_format_data_out_t *)x->format_data)

#define FORMAT_DATA DATA(libtrace)
#define FORMAT_DATA_OUT DATA_OUT(libtrace)

#define DUCK FORMAT_DATA->duck
static struct libtrace_format_t dag;

/* A DAG device - a DAG device can support multiple streams (and therefore
 * multiple input traces) so each trace needs to refer to a device */
struct dag_dev_t {
	char * dev_name;		/* Device name */
	int fd;				/* File descriptor */
	uint16_t ref_count;		/* Number of input / output traces
					   that are using this device */
	struct dag_dev_t *prev;		/* Pointer to the previous device in
					   the device list */
	struct dag_dev_t *next;		/* Pointer to the next device in the
					   device list */
};

/* "Global" data that is stored for each DAG output trace */
struct dag_format_data_out_t {
        /* String containing the DAG device name */
	char *device_name;
	/* The DAG device being used for writing */
	struct dag_dev_t *device;
	/* The DAG stream that is being written on */
	unsigned int dagstream;
	/* Boolean flag indicating whether the stream is currently attached */
	int stream_attached;
	/* The amount of data waiting to be transmitted, in bytes */
	uint64_t waiting;
	/* A buffer to hold the data to be transmittted */
	uint8_t *txbuffer;
};

/* "Global" data that is stored for each DAG input trace */
struct dag_format_data_t {

	/* Data required for regular DUCK reporting */
	struct {
		/* Timestamp of the last DUCK report */
		uint32_t last_duck;
		/* The number of seconds between each DUCK report */
                uint32_t duck_freq;
		/* Timestamp of the last packet read from the DAG card */
                uint32_t last_pkt;
		/* Dummy trace to ensure DUCK packets are dealt with using the
		 * DUCK format functions */
                libtrace_t *dummy_duck;
        } duck;

        /* String containing the DAG device name */
	char *device_name;
        /* The DAG device that we are reading from */
	struct dag_dev_t *device;
	/* The DAG stream that we are reading from */
	unsigned int dagstream;
	/* Boolean flag indicating whether the stream is currently attached */
	int stream_attached;
	/* Pointer to the first unread byte in the DAG memory hole */
	uint8_t *bottom;
	/* Pointer to the last unread byte in the DAG memory hole */
	uint8_t *top;
	/* The amount of data processed thus far from the bottom pointer */
	uint32_t processed;
	/* The number of packets that have been dropped */
	uint64_t drops;

	uint8_t seeninterface[4];
};

/* To be thread-safe, we're going to need a mutex for operating on the list
 * of DAG devices */
pthread_mutex_t open_dag_mutex;

/* The list of DAG devices that have been opened by libtrace.
 *
 * We can only open each DAG device once, but we might want to read from
 * multiple streams. Therefore, we need to maintain a list of devices that we
 * have opened (with ref counts!) so that we don't try to open a device too
 * many times or close a device that we're still using */
struct dag_dev_t *open_dags = NULL;

/* Returns the amount of padding between the ERF header and the start of the
 * captured packet data */
static int dag_get_padding(const libtrace_packet_t *packet)
{
	/* ERF Ethernet records have a 2 byte padding before the packet itself
	 * so that the IP header is aligned on a 32 bit boundary.
	 */
	if (packet->trace->format->type==TRACE_FORMAT_ERF) {
		dag_record_t *erfptr = (dag_record_t *)packet->header;
		switch(erfptr->type) {
			case TYPE_ETH:
			case TYPE_DSM_COLOR_ETH:
				return 2;
			default: 		return 0;
		}
	}
	else {
		switch(trace_get_link_type(packet)) {
			case TRACE_TYPE_ETH:	return 2;
			default:		return 0;
		}
	}
}

/* Attempts to determine if the given filename refers to a DAG device */
static int dag_probe_filename(const char *filename)
{
	struct stat statbuf;
	/* Can we stat the file? */
	if (stat(filename, &statbuf) != 0) {
		return 0;
	}
	/* Is it a character device? */
	if (!S_ISCHR(statbuf.st_mode)) {
		return 0;
	}
	/* Yeah, it's probably us. */
	return 1;
}

/* Initialises the DAG output data structure */
static void dag_init_format_out_data(libtrace_out_t *libtrace) {
	libtrace->format_data = (struct dag_format_data_out_t *) malloc(sizeof(struct dag_format_data_out_t));
	// no DUCK on output
	FORMAT_DATA_OUT->stream_attached = 0;
	FORMAT_DATA_OUT->device = NULL;
	FORMAT_DATA_OUT->device_name = NULL;
	FORMAT_DATA_OUT->dagstream = 0;
	FORMAT_DATA_OUT->waiting = 0;

}

/* Initialises the DAG input data structure */
static void dag_init_format_data(libtrace_t *libtrace) {
	libtrace->format_data = (struct dag_format_data_t *)
		malloc(sizeof(struct dag_format_data_t));
	DUCK.last_duck = 0;
        DUCK.duck_freq = 0;
        DUCK.last_pkt = 0;
        DUCK.dummy_duck = NULL;
	FORMAT_DATA->stream_attached = 0;
	FORMAT_DATA->drops = 0;
	FORMAT_DATA->device_name = NULL;
	FORMAT_DATA->device = NULL;
	FORMAT_DATA->dagstream = 0;
	FORMAT_DATA->processed = 0;
	FORMAT_DATA->bottom = NULL;
	FORMAT_DATA->top = NULL;
	memset(FORMAT_DATA->seeninterface, 0, sizeof(FORMAT_DATA->seeninterface));
}

/* Determines if there is already an entry for the given DAG device in the
 * device list and increments the reference count for that device, if found.
 *
 * NOTE: This function assumes the open_dag_mutex is held by the caller */
static struct dag_dev_t *dag_find_open_device(char *dev_name) {
	struct dag_dev_t *dag_dev;

	dag_dev = open_dags;

	/* XXX: Not exactly zippy, but how often are we going to be dealing
	 * with multiple dag cards? */
	while (dag_dev != NULL) {
		if (strcmp(dag_dev->dev_name, dev_name) == 0) {
			dag_dev->ref_count ++;
			return dag_dev;

		}
		dag_dev = dag_dev->next;
	}
	return NULL;


}

/* Closes a DAG device and removes it from the device list.
 *
 * Attempting to close a DAG device that has a non-zero reference count will
 * cause an assertion failure!
 *
 * NOTE: This function assumes the open_dag_mutex is held by the caller */
static void dag_close_device(struct dag_dev_t *dev) {
	/* Need to remove from the device list */

	assert(dev->ref_count == 0);

	if (dev->prev == NULL) {
		open_dags = dev->next;
		if (dev->next)
			dev->next->prev = NULL;
	} else {
		dev->prev->next = dev->next;
		if (dev->next)
			dev->next->prev = dev->prev;
	}

	dag_close(dev->fd);
	if (dev->dev_name)
		free(dev->dev_name);
	free(dev);
}


/* Opens a new DAG device for writing and adds it to the DAG device list
 *
 * NOTE: this function should only be called when opening a DAG device for
 * writing - there is little practical difference between this and the 
 * function below that covers the reading case, but we need the output trace
 * object to report errors properly so the two functions take slightly 
 * different arguments. This is really lame and there should be a much better
 * way of doing this.
 *
 * NOTE: This function assumes the open_dag_mutex is held by the caller 
 */
static struct dag_dev_t *dag_open_output_device(libtrace_out_t *libtrace, char *dev_name) {
	struct stat buf;
	int fd;
	struct dag_dev_t *new_dev;

	/* Make sure the device exists */
	if (stat(dev_name, &buf) == -1) {
		trace_set_err_out(libtrace,errno,"stat(%s)",dev_name);
		return NULL;
}

	/* Make sure it is the appropriate type of device */
	if (S_ISCHR(buf.st_mode)) {
		/* Try opening the DAG device */
		if((fd = dag_open(dev_name)) < 0) {
			trace_set_err_out(libtrace,errno,"Cannot open DAG %s",
					dev_name);
			return NULL;
		}
	} else {
		trace_set_err_out(libtrace,errno,"Not a valid dag device: %s",
				dev_name);
		return NULL;
	}

	/* Add the device to our device list - it is just a doubly linked
	 * list with no inherent ordering; just tack the new one on the front
	 */
	new_dev = (struct dag_dev_t *)malloc(sizeof(struct dag_dev_t));
	new_dev->fd = fd;
	new_dev->dev_name = dev_name;
	new_dev->ref_count = 1;

	new_dev->prev = NULL;
	new_dev->next = open_dags;
	if (open_dags)
		open_dags->prev = new_dev;

	open_dags = new_dev;

	return new_dev;
}

/* Opens a new DAG device for reading and adds it to the DAG device list
 *
 * NOTE: this function should only be called when opening a DAG device for
 * reading - there is little practical difference between this and the 
 * function above that covers the writing case, but we need the input trace
 * object to report errors properly so the two functions take slightly 
 * different arguments. This is really lame and there should be a much better
 * way of doing this.
 *
 * NOTE: This function assumes the open_dag_mutex is held by the caller */
static struct dag_dev_t *dag_open_device(libtrace_t *libtrace, char *dev_name) {
	struct stat buf;
	int fd;
	struct dag_dev_t *new_dev;

	/* Make sure the device exists */
        if (stat(dev_name, &buf) == -1) {
                trace_set_err(libtrace,errno,"stat(%s)",dev_name);
                return NULL;
        }

	/* Make sure it is the appropriate type of device */
	if (S_ISCHR(buf.st_mode)) {
		/* Try opening the DAG device */
		if((fd = dag_open(dev_name)) < 0) {
                        trace_set_err(libtrace,errno,"Cannot open DAG %s",
                                        dev_name);
                        return NULL;
                }
	} else {
		trace_set_err(libtrace,errno,"Not a valid dag device: %s",
                                dev_name);
                return NULL;
        }

	/* Add the device to our device list - it is just a doubly linked
	 * list with no inherent ordering; just tack the new one on the front
	 */
	new_dev = (struct dag_dev_t *)malloc(sizeof(struct dag_dev_t));
	new_dev->fd = fd;
	new_dev->dev_name = dev_name;
	new_dev->ref_count = 1;

	new_dev->prev = NULL;
	new_dev->next = open_dags;
	if (open_dags)
		open_dags->prev = new_dev;

	open_dags = new_dev;

	return new_dev;
}

/* Creates and initialises a DAG output trace */
static int dag_init_output(libtrace_out_t *libtrace) {
	char *scan = NULL;
	struct dag_dev_t *dag_device = NULL;
	int stream = 1;
	
	/* XXX I don't know if this is important or not, but this function
	 * isn't present in all of the driver releases that this code is
	 * supposed to support! */
	/*
	unsigned long wake_time;
	dagutil_sleep_get_wake_time(&wake_time,0);
	*/

	dag_init_format_out_data(libtrace);
	/* Grab the mutex while we're likely to be messing with the device 
	 * list */
	pthread_mutex_lock(&open_dag_mutex);
	
	/* Specific streams are signified using a comma in the libtrace URI,
	 * e.g. dag:/dev/dag0,1 refers to stream 1 on the dag0 device.
	 *
	 * If no stream is specified, we will write using stream 1 */
	if ((scan = strchr(libtrace->uridata,',')) == NULL) {
		FORMAT_DATA_OUT->device_name = strdup(libtrace->uridata);
	} else {
		FORMAT_DATA_OUT->device_name = 
                                (char *)strndup(libtrace->uridata,
				(size_t)(scan - libtrace->uridata));
		stream = atoi(++scan);
	}
	FORMAT_DATA_OUT->dagstream = stream;

	/* See if our DAG device is already open */
	dag_device = dag_find_open_device(FORMAT_DATA_OUT->device_name);

	if (dag_device == NULL) {
		/* Device not yet opened - open it ourselves */
		dag_device = dag_open_output_device(libtrace, 
                                FORMAT_DATA_OUT->device_name);
	}

	/* Make sure we have successfully opened a DAG device */
	if (dag_device == NULL) {
		if (FORMAT_DATA_OUT->device_name) {
			free(FORMAT_DATA_OUT->device_name);
                        FORMAT_DATA_OUT->device_name = NULL;
		}
		pthread_mutex_unlock(&open_dag_mutex);
		return -1;
	}

	FORMAT_DATA_OUT->device = dag_device;
	pthread_mutex_unlock(&open_dag_mutex);
	return 0;
}

/* Creates and initialises a DAG input trace */
static int dag_init_input(libtrace_t *libtrace) {
	char *scan = NULL;
	int stream = 0;
	struct dag_dev_t *dag_device = NULL;

	dag_init_format_data(libtrace);
	/* Grab the mutex while we're likely to be messing with the device 
	 * list */
	pthread_mutex_lock(&open_dag_mutex);
	
	
	/* Specific streams are signified using a comma in the libtrace URI,
	 * e.g. dag:/dev/dag0,2 refers to stream 2 on the dag0 device.
	 *
	 * If no stream is specified, we will read from stream 0 */
	if ((scan = strchr(libtrace->uridata,',')) == NULL) {
		FORMAT_DATA->device_name = strdup(libtrace->uridata);
	} else {
		FORMAT_DATA->device_name = (char *)strndup(libtrace->uridata,
				(size_t)(scan - libtrace->uridata));
		stream = atoi(++scan);
	}

	FORMAT_DATA->dagstream = stream;

	/* See if our DAG device is already open */
	dag_device = dag_find_open_device(FORMAT_DATA->device_name);

	if (dag_device == NULL) {
		/* Device not yet opened - open it ourselves */
		dag_device=dag_open_device(libtrace, FORMAT_DATA->device_name);
	}

	/* Make sure we have successfully opened a DAG device */
	if (dag_device == NULL) {
		if (FORMAT_DATA->device_name)
			free(FORMAT_DATA->device_name);
		FORMAT_DATA->device_name = NULL;
		pthread_mutex_unlock(&open_dag_mutex);
		return -1;
	}

	FORMAT_DATA->device = dag_device;

	/* See Config_Status_API_Programming_Guide.pdf from the Endace Dag Documentation */
	/* Check kBooleanAttributeActive is true -- no point capturing on an interface that's disabled
 
	*  The symptom of the port being disabled is that libtrace will appear to hang.
	*/
	/* Check kBooleanAttributeFault is false */
	/* Check kBooleanAttributeLocalFault is false */
	/* Check kBooleanAttributeLock is true ? */
	/* Check kBooleanAttributePeerLink ? */

	/* Set kBooleanAttributePromisc/kBooleanPromiscuousMode based on libtrace promisc attribute?*/
	/* Set kUint32AttributeSnapLength to the snaplength */

	pthread_mutex_unlock(&open_dag_mutex);
        return 0;
}

/* Configures a DAG input trace */
static int dag_config_input(libtrace_t *libtrace, trace_option_t option,
                                void *data) {
        char conf_str[4096];
	switch(option) {
                case TRACE_OPTION_META_FREQ:
			/* This option is used to specify the frequency of DUCK
			 * updates */
			DUCK.duck_freq = *(int *)data;
                        return 0;
                case TRACE_OPTION_SNAPLEN:
			/* Tell the card our new snap length */
                        snprintf(conf_str, 4096, "varlen slen=%i", *(int *)data);
			if (dag_configure(FORMAT_DATA->device->fd,
						conf_str) != 0) {
				trace_set_err(libtrace, errno, "Failed to configure snaplen on DAG card: %s", libtrace->uridata);
				return -1;
			}
			return 0;
                case TRACE_OPTION_PROMISC:
                        /* DAG already operates in a promisc fashion */
                        return -1;
                case TRACE_OPTION_FILTER:
			/* We don't yet support pushing filters into DAG 
			 * cards */
                        return -1;
                case TRACE_OPTION_EVENT_REALTIME:
			/* Live capture is always going to be realtime */
			return -1;
        }
	return -1;
}

/* Starts a DAG output trace */
static int dag_start_output(libtrace_out_t *libtrace) {
	struct timeval zero, nopoll;

	zero.tv_sec = 0;
	zero.tv_usec = 0;
	nopoll = zero;

	/* Attach and start the DAG stream */

	if (dag_attach_stream(FORMAT_DATA_OUT->device->fd,
			FORMAT_DATA_OUT->dagstream, 0, 4 * 1024 * 1024) < 0) {
		trace_set_err_out(libtrace, errno, "Cannot attach DAG stream");
		return -1;
	}

	if (dag_start_stream(FORMAT_DATA_OUT->device->fd,
			FORMAT_DATA_OUT->dagstream) < 0) {
		trace_set_err_out(libtrace, errno, "Cannot start DAG stream");
		return -1;
	}
	FORMAT_DATA_OUT->stream_attached = 1;

	/* We don't want the dag card to do any sleeping */

	dag_set_stream_poll(FORMAT_DATA_OUT->device->fd,
			FORMAT_DATA_OUT->dagstream, 0, &zero,
			&nopoll);

	return 0;
}

/* Starts a DAG input trace */
static int dag_start_input(libtrace_t *libtrace) {
        struct timeval zero, nopoll;
        uint8_t *top, *bottom, *starttop;
	top = bottom = NULL;

	zero.tv_sec = 0;
        zero.tv_usec = 10000;
        nopoll = zero;

	/* Attach and start the DAG stream */
	if (dag_attach_stream(FORMAT_DATA->device->fd,
				FORMAT_DATA->dagstream, 0, 0) < 0) {
                trace_set_err(libtrace, errno, "Cannot attach DAG stream");
                return -1;
        }

	if (dag_start_stream(FORMAT_DATA->device->fd,
				FORMAT_DATA->dagstream) < 0) {
                trace_set_err(libtrace, errno, "Cannot start DAG stream");
                return -1;
        }
	FORMAT_DATA->stream_attached = 1;
	
	/* We don't want the dag card to do any sleeping */
        dag_set_stream_poll(FORMAT_DATA->device->fd,
				FORMAT_DATA->dagstream, 0, &zero,
				&nopoll);

	starttop = dag_advance_stream(FORMAT_DATA->device->fd,
                                        FORMAT_DATA->dagstream,
                                        &bottom);

	/* Should probably flush the memory hole now */
	top = starttop;
        while (starttop - bottom > 0) {
		bottom += (starttop - bottom);
		top = dag_advance_stream(FORMAT_DATA->device->fd,
					FORMAT_DATA->dagstream,
					&bottom);
	}
	FORMAT_DATA->top = top;
	FORMAT_DATA->bottom = bottom;
	FORMAT_DATA->processed = 0;
	FORMAT_DATA->drops = 0;

	return 0;
}

/* Pauses a DAG output trace */
static int dag_pause_output(libtrace_out_t *libtrace) {

	/* Stop and detach the stream */
	if (dag_stop_stream(FORMAT_DATA_OUT->device->fd,
			FORMAT_DATA_OUT->dagstream) < 0) {
		trace_set_err_out(libtrace, errno, "Could not stop DAG stream");
		return -1;
	}
	if (dag_detach_stream(FORMAT_DATA_OUT->device->fd,
			FORMAT_DATA_OUT->dagstream) < 0) {
		trace_set_err_out(libtrace, errno, "Could not detach DAG stream");
		return -1;
	}
	FORMAT_DATA_OUT->stream_attached = 0;
	return 0;
}

/* Pauses a DAG input trace */
static int dag_pause_input(libtrace_t *libtrace) {

	/* Stop and detach the stream */
	if (dag_stop_stream(FORMAT_DATA->device->fd,
				FORMAT_DATA->dagstream) < 0) {
                trace_set_err(libtrace, errno, "Could not stop DAG stream");
                return -1;
        }
        if (dag_detach_stream(FORMAT_DATA->device->fd,
				FORMAT_DATA->dagstream) < 0) {
                trace_set_err(libtrace, errno, "Could not detach DAG stream");
                return -1;
	}
	FORMAT_DATA->stream_attached = 0;
	return 0;
}

/* Closes a DAG input trace */
static int dag_fin_input(libtrace_t *libtrace) {
	/* Need the lock, since we're going to be handling the device list */
	pthread_mutex_lock(&open_dag_mutex);
	
	/* Detach the stream if we are not paused */
	if (FORMAT_DATA->stream_attached)
		dag_pause_input(libtrace);
	FORMAT_DATA->device->ref_count --;

	/* Close the DAG device if there are no more references to it */
	if (FORMAT_DATA->device->ref_count == 0)
		dag_close_device(FORMAT_DATA->device);
	if (DUCK.dummy_duck)
		trace_destroy_dead(DUCK.dummy_duck);
        if (FORMAT_DATA->device_name)
                free(FORMAT_DATA->device_name);
	free(libtrace->format_data);
	pthread_mutex_unlock(&open_dag_mutex);
        return 0; /* success */
}

/* Closes a DAG output trace */
static int dag_fin_output(libtrace_out_t *libtrace) {
	
	/* Commit any outstanding traffic in the txbuffer */
	if (FORMAT_DATA_OUT->waiting) {
		dag_tx_stream_commit_bytes(FORMAT_DATA_OUT->device->fd, FORMAT_DATA_OUT->dagstream,
				FORMAT_DATA_OUT->waiting );
	}

	/* Wait until the buffer is nearly clear before exiting the program, 
	 * as we will lose packets otherwise */
	dag_tx_get_stream_space(FORMAT_DATA_OUT->device->fd,
			FORMAT_DATA_OUT->dagstream,
			dag_get_stream_buffer_size(FORMAT_DATA_OUT->device->fd,
					FORMAT_DATA_OUT->dagstream) - 8
			);

	/* Need the lock, since we're going to be handling the device list */
	pthread_mutex_lock(&open_dag_mutex);

	/* Detach the stream if we are not paused */
	if (FORMAT_DATA_OUT->stream_attached)
		dag_pause_output(libtrace);
	FORMAT_DATA_OUT->device->ref_count --;

	/* Close the DAG device if there are no more references to it */
	if (FORMAT_DATA_OUT->device->ref_count == 0)
		dag_close_device(FORMAT_DATA_OUT->device);
        if (FORMAT_DATA_OUT->device_name)
                free(FORMAT_DATA_OUT->device_name);
	free(libtrace->format_data);
	pthread_mutex_unlock(&open_dag_mutex);
	return 0; /* success */
}

#ifdef DAGIOC_CARD_DUCK
#define LIBTRACE_DUCK_IOCTL DAGIOC_CARD_DUCK
#define LIBTRACE_DUCK_VERSION TRACE_RT_DUCK_5_0
#else 
#ifdef DAGIOCDUCK
#define LIBTRACE_DUCK_IOCTL DAGIOCDUCK
#define LIBTRACE_DUCK_VERSION TRACE_RT_DUCK_2_5
#else
#warning "DAG appears to be missing DUCK support"
#endif
#endif

/* Extracts DUCK information from the DAG card and produces a DUCK packet */
static int dag_get_duckinfo(libtrace_t *libtrace,
                                libtrace_packet_t *packet) {

	if (DUCK.duck_freq == 0)
		return 0;

#ifndef LIBTRACE_DUCK_IOCTL
	trace_set_err(libtrace, errno, 
		"Requested DUCK information but unable to determine the correct ioctl for DUCK");
	DUCK.duck_freq = 0;
	return -1;
#endif

	if (DUCK.last_pkt - DUCK.last_duck < DUCK.duck_freq)
		return 0;

	/* Allocate memory for the DUCK data */
        if (packet->buf_control == TRACE_CTRL_EXTERNAL ||
                        !packet->buffer) {
                packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
                packet->buf_control = TRACE_CTRL_PACKET;
                if (!packet->buffer) {
                        trace_set_err(libtrace, errno,
                                        "Cannot allocate packet buffer");
                        return -1;
                }
        }

	/* DUCK doesn't have a format header */
        packet->header = 0;
        packet->payload = packet->buffer;

        /* No need to check if we can get DUCK or not - we're modern
         * enough so just grab the DUCK info */
        if ((ioctl(FORMAT_DATA->device->fd, LIBTRACE_DUCK_IOCTL,
					(duckinf_t *)packet->payload) < 0)) {
                trace_set_err(libtrace, errno, "Error using DUCK ioctl");
		DUCK.duck_freq = 0;
                return -1;
        }

        packet->type = LIBTRACE_DUCK_VERSION;

	/* Set the packet's trace to point at a DUCK trace, so that the
	 * DUCK format functions will be called on the packet rather than the
	 * DAG ones */
        if (!DUCK.dummy_duck)
                DUCK.dummy_duck = trace_create_dead("duck:dummy");
        packet->trace = DUCK.dummy_duck;
        DUCK.last_duck = DUCK.last_pkt;
        return sizeof(duckinf_t);
}

/* Determines the amount of data available to read from the DAG card */
static int dag_available(libtrace_t *libtrace) {
	uint32_t diff = FORMAT_DATA->top - FORMAT_DATA->bottom;

	/* If we've processed more than 4MB of data since we last called
	 * dag_advance_stream, then we should call it again to allow the
	 * space occupied by that 4MB to be released */
	if (diff >= dag_record_size && FORMAT_DATA->processed < 4 * 1024 * 1024)
		return diff;
	
	/* Update the top and bottom pointers */
	FORMAT_DATA->top = dag_advance_stream(FORMAT_DATA->device->fd,
			FORMAT_DATA->dagstream,
			&(FORMAT_DATA->bottom));
	
	if (FORMAT_DATA->top == NULL) {
		trace_set_err(libtrace, errno, "dag_advance_stream failed!");
		return -1;
	}
	FORMAT_DATA->processed = 0;
	diff = FORMAT_DATA->top - FORMAT_DATA->bottom;
	return diff;
}

/* Returns a pointer to the start of the next complete ERF record */
static dag_record_t *dag_get_record(libtrace_t *libtrace) {
        dag_record_t *erfptr = NULL;
        uint16_t size;
	erfptr = (dag_record_t *)FORMAT_DATA->bottom;
	if (!erfptr)
                return NULL;
        size = ntohs(erfptr->rlen);
        assert( size >= dag_record_size );
	/* Make certain we have the full packet available */
	if (size > (FORMAT_DATA->top - FORMAT_DATA->bottom))
		return NULL;
	FORMAT_DATA->bottom += size;
	FORMAT_DATA->processed += size;
	return erfptr;
}

/* Converts a buffer containing a recently read DAG packet record into a
 * libtrace packet */
static int dag_prepare_packet(libtrace_t *libtrace, libtrace_packet_t *packet,
		void *buffer, libtrace_rt_types_t rt_type, uint32_t flags) {

	dag_record_t *erfptr;
	
	/* If the packet previously owned a buffer that is not the buffer
         * that contains the new packet data, we're going to need to free the
         * old one to avoid memory leaks */
	if (packet->buffer != buffer &&
			packet->buf_control == TRACE_CTRL_PACKET) {
		free(packet->buffer);
	}

	/* Set the buffer owner appropriately */
	if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER) {
		packet->buf_control = TRACE_CTRL_PACKET;
	} else
		packet->buf_control = TRACE_CTRL_EXTERNAL;

	/* Update the packet pointers and type appropriately */
	erfptr = (dag_record_t *)buffer;
	packet->buffer = erfptr;
        packet->header = erfptr;
        packet->type = rt_type;

	if (erfptr->flags.rxerror == 1) {
                /* rxerror means the payload is corrupt - drop the payload
                 * by tweaking rlen */
                packet->payload = NULL;
                erfptr->rlen = htons(erf_get_framing_length(packet));
        } else {
                packet->payload = (char*)packet->buffer
                        + erf_get_framing_length(packet);
        }

	if (libtrace->format_data == NULL) {
		dag_init_format_data(libtrace);
	}

	/* Update the dropped packets counter */

	/* No loss counter for DSM coloured records - have to use
	 * some other API */
	if (erfptr->type == TYPE_DSM_COLOR_ETH) {
		/* TODO */
	} else {
		/* Use the ERF loss counter */
		if (FORMAT_DATA->seeninterface[erfptr->flags.iface] == 0) {
			FORMAT_DATA->seeninterface[erfptr->flags.iface] = 1;
		} else {
			FORMAT_DATA->drops += ntohs(erfptr->lctr);
		}
	}

	return 0;
}

/*
 * dag_write_packet() at this stage attempts to improve tx performance
 * by delaying sending a dag_tx_stream_commit_bytes() until a threshold
 * has been met. I observed approximately 270% performance increase
 * through this relatively naive tweak. No optimisation of buffer sizes
 * was attempted.
 */

/* Pushes an ERF record onto the transmit stream */
static int dag_dump_packet(libtrace_out_t *libtrace,
		dag_record_t *erfptr, unsigned int pad, void *buffer) {
	int size;

	/*
	 * If we've got 0 bytes waiting in the txqueue, assume that we haven't
	 * requested any space yet, and request some, storing the pointer at
	 * FORMAT_DATA_OUT->txbuffer.
	 *
	 * The amount to request is slightly magical at the moment - it's
	 * 16Mebibytes + 128 kibibytes to ensure that we can copy a packet into
	 * the buffer and handle overruns.
	 */
	if (FORMAT_DATA_OUT->waiting == 0) {
		FORMAT_DATA_OUT->txbuffer = dag_tx_get_stream_space(FORMAT_DATA_OUT->device->fd,
				FORMAT_DATA_OUT->dagstream, 16908288);
	}

	/*
	 * Copy the header separately to the body, as we can't guarantee they 
	 * are in contiguous memory
	 */
	memcpy(FORMAT_DATA_OUT->txbuffer + FORMAT_DATA_OUT->waiting,erfptr,(dag_record_size + pad));
	FORMAT_DATA_OUT->waiting += (dag_record_size + pad);



	/*
	 * Copy our incoming packet into the outgoing buffer, and increment 
	 * our waiting count
	 */
	size = ntohs(erfptr->rlen)-(dag_record_size + pad);
	memcpy(FORMAT_DATA_OUT->txbuffer + FORMAT_DATA_OUT->waiting,buffer,size);
	FORMAT_DATA_OUT->waiting += size;

	/*
	 * If our output buffer has more than 16 Mebibytes in it, commit those 
	 * bytes and reset the waiting count to 0.
	 * Note: dag_fin_output will also call dag_tx_stream_commit_bytes() in 
	 * case there is still data in the buffer at program exit.
	 */

	if (FORMAT_DATA_OUT->waiting >= 16*1024*1024) {
		FORMAT_DATA_OUT->txbuffer = dag_tx_stream_commit_bytes(FORMAT_DATA_OUT->device->fd, FORMAT_DATA_OUT->dagstream,
			FORMAT_DATA_OUT->waiting );
		FORMAT_DATA_OUT->waiting = 0;
	}

	return size + pad + dag_record_size;

}

/* Attempts to determine a suitable ERF type for a given packet. Returns true
 * if one is found, false otherwise */
static bool find_compatible_linktype(libtrace_out_t *libtrace,
				libtrace_packet_t *packet, char *type)
{
	 // Keep trying to simplify the packet until we can find
	 //something we can do with it

	do {
		*type=libtrace_to_erf_type(trace_get_link_type(packet));

		// Success
		if (*type != (char)-1)
			return true;

		if (!demote_packet(packet)) {
			trace_set_err_out(libtrace,
					TRACE_ERR_NO_CONVERSION,
					"No erf type for packet (%i)",
					trace_get_link_type(packet));
			return false;
		}

	} while(1);

	return true;
}

/* Writes a packet to the provided DAG output trace */
static int dag_write_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet) {
	/*
	 * This is heavily borrowed from erf_write_packet(). Yes, CnP coding 
	 * sucks, sorry about that.
	 */
	unsigned int pad = 0;
	int numbytes;
	void *payload = packet->payload;
	dag_record_t *header = (dag_record_t *)packet->header;
	char erf_type = 0;

	if(!packet->header) {
		/* No header, probably an RT packet. Lifted from 
		 * erf_write_packet(). */
		return -1;
	}

	if (trace_get_link_type(packet) == TRACE_TYPE_NONDATA)
		return 0;

	pad = dag_get_padding(packet);

	/*
	 * If the payload is null, adjust the rlen. Discussion of this is
	 * attached to erf_write_packet()
	 */
	if (payload == NULL) {
		header->rlen = htons(dag_record_size + pad);
	}

	if (packet->type == TRACE_RT_DATA_ERF) {
		numbytes = dag_dump_packet(libtrace,
				header,
				pad,
				payload
				);

	} else {
		/* Build up a new packet header from the existing header */

		/* Simplify the packet first - if we can't do this, break 
		 * early */
		if (!find_compatible_linktype(libtrace,packet,&erf_type))
			return -1;

		dag_record_t erfhdr;

		erfhdr.ts = bswap_host_to_le64(trace_get_erf_timestamp(packet));
		payload=packet->payload;
		pad = dag_get_padding(packet);

		/* Flags. Can't do this */
		memset(&erfhdr.flags,1,sizeof(erfhdr.flags));
		if (trace_get_direction(packet)!=(int)~0U)
			erfhdr.flags.iface = trace_get_direction(packet);

		erfhdr.type = erf_type;

		/* Packet length (rlen includes format overhead) */
		assert(trace_get_capture_length(packet)>0
				&& trace_get_capture_length(packet)<=65536);
		assert(erf_get_framing_length(packet)>0
				&& trace_get_framing_length(packet)<=65536);
		assert(trace_get_capture_length(packet)+erf_get_framing_length(packet)>0
		      &&trace_get_capture_length(packet)+erf_get_framing_length(packet)<=65536);

		erfhdr.rlen = htons(trace_get_capture_length(packet)
			+ erf_get_framing_length(packet));


		/* Loss counter. Can't do this */
		erfhdr.lctr = 0;
		/* Wire length, does not include padding! */
		erfhdr.wlen = htons(trace_get_wire_length(packet));

		/* Write it out */
		numbytes = dag_dump_packet(libtrace,
				&erfhdr,
				pad,
				payload);

	}

	return numbytes;
}

/* Reads the next available packet from a DAG card, in a BLOCKING fashion
 *
 * If DUCK reporting is enabled, the packet returned may be a DUCK update
 */
static int dag_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
        int size = 0;
        struct timeval tv;
        dag_record_t *erfptr = NULL;
	int numbytes = 0;
	uint32_t flags = 0;
	struct timeval maxwait;
	struct timeval pollwait;

	pollwait.tv_sec = 0;
	pollwait.tv_usec = 10000;
	maxwait.tv_sec = 0;
	maxwait.tv_usec = 250000;

        /* Check if we're due for a DUCK report */
	size = dag_get_duckinfo(libtrace, packet);

	if (size != 0)
		return size;


	/* Don't let anyone try to free our DAG memory hole! */
	flags |= TRACE_PREP_DO_NOT_OWN_BUFFER;

	/* If the packet buffer is currently owned by libtrace, free it so
	 * that we can set the packet to point into the DAG memory hole */
        if (packet->buf_control == TRACE_CTRL_PACKET) {
                free(packet->buffer);
                packet->buffer = 0;
        }
	
	if (dag_set_stream_poll(FORMAT_DATA->device->fd, 
			FORMAT_DATA->dagstream, sizeof(dag_record_t), &maxwait, 
			&pollwait) == -1)
	{
		trace_set_err(libtrace, errno, "dag_set_stream_poll");
		return -1;
	}


	/* Grab a full ERF record */
	do {
		numbytes = dag_available(libtrace);
		if (numbytes < 0)
			return numbytes;
		if (numbytes < dag_record_size) {
			if (libtrace_halt)
				return 0;
			/* Block until we see a packet */
			continue;
		}
		erfptr = dag_get_record(libtrace);
	} while (erfptr == NULL);

	/* Prepare the libtrace packet */
	if (dag_prepare_packet(libtrace, packet, erfptr, TRACE_RT_DATA_ERF,
				flags))
		return -1;

	/* Update the DUCK timer */
	tv = trace_get_timeval(packet);
        DUCK.last_pkt = tv.tv_sec;

	return packet->payload ? htons(erfptr->rlen) :
				erf_get_framing_length(packet);
}

/* Attempts to read a packet from a DAG card in a NON-BLOCKING fashion. If a
 * packet is available, we will return a packet event. Otherwise we will
 * return a SLEEP event (as we cannot select on the DAG file descriptor).
 */
static libtrace_eventobj_t trace_event_dag(libtrace_t *libtrace,
                                        libtrace_packet_t *packet) {
        libtrace_eventobj_t event = {0,0,0.0,0};
	dag_record_t *erfptr = NULL;
	int numbytes;
	uint32_t flags = 0;
	struct timeval minwait, tv;
	
	minwait.tv_sec = 0;
	minwait.tv_usec = 10000;

	/* Check if we're meant to provide a DUCK update */
	numbytes = dag_get_duckinfo(libtrace, packet);
	if (numbytes < 0) {
		event.type = TRACE_EVENT_TERMINATE;
		return event;
	} else if (numbytes > 0) {
		event.type = TRACE_EVENT_PACKET;
		return event;
	}
	
	if (dag_set_stream_poll(FORMAT_DATA->device->fd, 
			FORMAT_DATA->dagstream, 0, &minwait, 
			&minwait) == -1)
	{
		trace_set_err(libtrace, errno, "dag_set_stream_poll");
		event.type = TRACE_EVENT_TERMINATE;
		return event;
	}

	do {
		erfptr = NULL;
		numbytes = 0;
	
		/* Need to call dag_available so that the top pointer will get
		 * updated, otherwise we'll never see any data! */
		numbytes = dag_available(libtrace);

		/* May as well not bother calling dag_get_record if 
		 * dag_available suggests that there's no data */
		if (numbytes != 0)
			erfptr = dag_get_record(libtrace);
		if (erfptr == NULL) {
			/* No packet available - sleep for a very short time */
			if (libtrace_halt) {
				event.type = TRACE_EVENT_TERMINATE;
			} else {			
				event.type = TRACE_EVENT_SLEEP;
				event.seconds = 0.0001;
			}
			break;
		}
		if (dag_prepare_packet(libtrace, packet, erfptr, 
					TRACE_RT_DATA_ERF, flags)) {
			event.type = TRACE_EVENT_TERMINATE;
			break;
		}


		event.size = trace_get_capture_length(packet) + 
				trace_get_framing_length(packet);
		
		/* XXX trace_read_packet() normally applies the following
		 * config options for us, but this function is called via
		 * trace_event() so we have to do it ourselves */

		if (libtrace->filter) {
			int filtret = trace_apply_filter(libtrace->filter, 
					packet);
			if (filtret == -1) {
				trace_set_err(libtrace, TRACE_ERR_BAD_FILTER,
						"Bad BPF Filter");
				event.type = TRACE_EVENT_TERMINATE;
				break;
			}

			if (filtret == 0) {
				/* This packet isn't useful so we want to
				 * immediately see if there is another suitable
				 * one - we definitely DO NOT want to return
				 * a sleep event in this case, like we used to
				 * do! */
                                libtrace->filtered_packets ++;
				trace_clear_cache(packet);
				continue;
			}
				
			event.type = TRACE_EVENT_PACKET;
		} else {
			event.type = TRACE_EVENT_PACKET;
		}

		/* Update the DUCK timer */
		tv = trace_get_timeval(packet);
		DUCK.last_pkt = tv.tv_sec;
		
		if (libtrace->snaplen > 0) {
			trace_set_capture_length(packet, libtrace->snaplen);
		}
                libtrace->accepted_packets ++;
		break;
	} while (1);

	return event;
}

/* Gets the number of dropped packets */
static uint64_t dag_get_dropped_packets(libtrace_t *trace) {
	if (trace->format_data == NULL)
		return (uint64_t)-1;
	return DATA(trace)->drops;
}

/* Prints some semi-useful help text about the DAG format module */
static void dag_help(void) {
        printf("dag format module: $Revision: 1755 $\n");
        printf("Supported input URIs:\n");
        printf("\tdag:/dev/dagn\n");
        printf("\n");
        printf("\te.g.: dag:/dev/dag0\n");
        printf("\n");
        printf("Supported output URIs:\n");
        printf("\tnone\n");
        printf("\n");
}

static struct libtrace_format_t dag = {
        "dag",
        "$Id$",
        TRACE_FORMAT_ERF,
	dag_probe_filename,		/* probe filename */
	NULL,				/* probe magic */
        dag_init_input,                 /* init_input */
        dag_config_input,               /* config_input */
        dag_start_input,                /* start_input */
        dag_pause_input,                /* pause_input */
	dag_init_output,		/* init_output */
        NULL,                           /* config_output */
	dag_start_output,               /* start_output */
        dag_fin_input,                  /* fin_input */
	dag_fin_output,                 /* fin_output */
        dag_read_packet,                /* read_packet */
        dag_prepare_packet,		/* prepare_packet */
	NULL,                           /* fin_packet */
	dag_write_packet,               /* write_packet */
        erf_get_link_type,              /* get_link_type */
        erf_get_direction,              /* get_direction */
        erf_set_direction,              /* set_direction */
        erf_get_erf_timestamp,          /* get_erf_timestamp */
        NULL,                           /* get_timeval */
        NULL,                           /* get_seconds */
	NULL,				/* get_timespec */
        NULL,                           /* seek_erf */
        NULL,                           /* seek_timeval */
        NULL,                           /* seek_seconds */
        erf_get_capture_length,         /* get_capture_length */
        erf_get_wire_length,            /* get_wire_length */
        erf_get_framing_length,         /* get_framing_length */
        erf_set_capture_length,         /* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	dag_get_dropped_packets,	/* get_dropped_packets */
	NULL,				/* get_captured_packets */
        NULL,                           /* get_fd */
        trace_event_dag,                /* trace_event */
        dag_help,                       /* help */
        NULL                            /* next pointer */
};

void dag_constructor(void) {
	register_format(&dag);
}
