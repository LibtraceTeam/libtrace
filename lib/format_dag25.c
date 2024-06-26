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
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif

#include "config.h"
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "format_erf.h"

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

#ifdef HAVE_DAG_CONFIG_API_H
#    include <dag_config_api.h>
#endif

#ifdef WIN32
#    include <io.h>
#    include <share.h>
#    define PATH_MAX _MAX_PATH
#    define snprintf sprintf_s
#else
#    include <netdb.h>
#    ifndef PATH_MAX
#        define PATH_MAX 4096
#    endif
#    include <sys/ioctl.h>
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
#define STREAM_DATA(x) ((struct dag_per_stream_t *)x->data)

#define FORMAT_DATA DATA(libtrace)
#define FORMAT_DATA_OUT DATA_OUT(libtrace)

#define DUCK FORMAT_DATA->duck

#define FORMAT_DATA_HEAD FORMAT_DATA->per_stream->head
#define FORMAT_DATA_FIRST ((struct dag_per_stream_t *)FORMAT_DATA_HEAD->data)

/* The size in bytes by which to overlap the TX ringbuffer
 *
 * E.g.               Ringbuffer          Extra window overlap (0x800 bytes)
 * Virtual:  [0x01000     ->     0x02000] [0x02000 -> 0x02800]
 *                        ^                        ^
 *                        |                        |
 * Physical: [0xf1000     ->     0xf2000] [0xf1000 -> 0xf1800]
 * Note, TX cannot reserve/write more than the extra window overlap size
 * at one time
 * Default: 4MB
 **/
#define TX_EXTRA_WINDOW 4 * 1024 * 1024
/* The number of bytes to request 256 KB, much larger sizes than this show no
 * clear benefit */
#define TX_BATCH_SIZE 256 * 1024
/* The threshold to reach before sending, 2x 64KB (largest packet size) is safe
 */
#define TX_BATCH_THOLD (TX_BATCH_SIZE - (2 * 1024 * 64))

/* Compile time asserts, check sizes are valid */
ct_assert(TX_BATCH_SIZE > TX_BATCH_THOLD);
ct_assert(TX_BATCH_THOLD > 0);
ct_assert(!TX_EXTRA_WINDOW || TX_EXTRA_WINDOW > TX_BATCH_SIZE);

static struct libtrace_format_t dag;

/* A DAG device - a DAG device can support multiple streams (and therefore
 * multiple input traces) so each trace needs to refer to a device */
struct dag_dev_t {
    char *dev_name;         /* Device name */
    int fd;                 /* File descriptor */
    uint16_t ref_count;     /* Number of input / output traces
                               that are using this device */
    struct dag_dev_t *prev; /* Pointer to the previous device in
                               the device list */
    struct dag_dev_t *next; /* Pointer to the next device in the
                               device list */
};

/* "Global" data that is stored for each DAG output trace */
struct dag_format_data_out_t {
    /* The DAG device being used for writing */
    struct dag_dev_t *device;
    /* The DAG stream that is being written on */
    unsigned int dagstream;
    /* Boolean flag indicating whether the stream is currently attached */
    int stream_attached;
    /* The amount of data waiting to be transmitted, in bytes */
    uint64_t waiting;
    /* A buffer to hold the data to be transmitted */
    uint8_t *txbuffer;
};

/* Data that is stored against each input stream */
struct dag_per_stream_t {
    /* DAG stream number */
    uint16_t dagstream;
    /* Pointer to the last unread byte in the DAG memory */
    uint8_t *top;
    /* Pointer to the first unread byte in the DAG memory */
    uint8_t *bottom;
    /* Amount of data processed from the bottom pointer */
    uint32_t processed;
    /* Number of packets seen by the stream */
    uint64_t pkt_count;
    /* Drop count for this particular stream */
    uint64_t drops;
    /* Boolean values to indicate if a particular interface has been seen
     * or not. This is limited to four interfaces, which is enough to
     * support all current DAG cards */
    uint8_t seeninterface[4];
};

/* "Global" data that is stored for each DAG input trace */
struct dag_format_data_t {
    /* DAG device */
    struct dag_dev_t *device;
    /* Boolean flag indicating whether the trace is currently attached */
    int stream_attached;
    /* Data stored against each DAG input stream */
    libtrace_list_t *per_stream;

    /* Data required for regular DUCK reporting.
     * We put this on a new cache line otherwise we have a lot of false
     * sharing caused by updating the last_pkt.
     * This should only ever be accessed by the first thread stream,
     * that includes both read and write operations.
     */
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
    } duck ALIGNED(CACHE_LINE_SIZE);
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

static int libtrace_to_dag_hdr(libtrace_out_t *libtrace,
                               libtrace_packet_t *packet, dag_record_t *erf,
                               int *framinglen, int *caplen, int *padding);

static bool dag_can_write(libtrace_packet_t *packet)
{
    /* Get the linktype */
    libtrace_linktype_t ltype = trace_get_link_type(packet);

    if (ltype == TRACE_TYPE_CONTENT_INVALID) {
        return false;
    }

    /* TODO erf meta should definitely be writable, pcapng meta
     * could probably be converted into erf meta */
    if (ltype == TRACE_TYPE_ERF_META || ltype == TRACE_TYPE_NONDATA ||
        ltype == TRACE_TYPE_PCAPNG_META) {
        return false;
    }

    return true;
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
static void dag_init_format_out_data(libtrace_out_t *libtrace)
{
    libtrace->format_data = (struct dag_format_data_out_t *)malloc(
        sizeof(struct dag_format_data_out_t));
    // no DUCK on output
    FORMAT_DATA_OUT->stream_attached = 0;
    FORMAT_DATA_OUT->device = NULL;
    FORMAT_DATA_OUT->dagstream = 0;
    FORMAT_DATA_OUT->waiting = 0;
}

/* Initialises the DAG input data structure */
static void dag_init_format_data(libtrace_t *libtrace)
{
    struct dag_per_stream_t stream_data;

    libtrace->format_data =
        (struct dag_format_data_t *)malloc(sizeof(struct dag_format_data_t));
    DUCK.last_duck = 0;
    DUCK.duck_freq = 0;
    DUCK.last_pkt = 0;
    DUCK.dummy_duck = NULL;

    FORMAT_DATA->per_stream = libtrace_list_init(sizeof(stream_data));
    if (FORMAT_DATA->per_stream == NULL) {
        trace_set_err(
            libtrace, TRACE_ERR_INIT_FAILED,
            "Unable to create list for stream in dag_init_format_data()");
        return;
    }

    /* We'll start with just one instance of stream_data, and we'll
     * add more later if we need them */
    memset(&stream_data, 0, sizeof(stream_data));
    libtrace_list_push_back(FORMAT_DATA->per_stream, &stream_data);
}

/* Determines if there is already an entry for the given DAG device in the
 * device list and increments the reference count for that device, if found.
 *
 * NOTE: This function assumes the open_dag_mutex is held by the caller */
static struct dag_dev_t *dag_find_open_device(char *dev_name)
{
    struct dag_dev_t *dag_dev;

    dag_dev = open_dags;

    /* XXX: Not exactly zippy, but how often are we going to be dealing
     * with multiple dag cards? */
    while (dag_dev != NULL) {
        if (strcmp(dag_dev->dev_name, dev_name) == 0) {
            dag_dev->ref_count++;
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
static void dag_close_device(struct dag_dev_t *dev)
{
    /* Need to remove from the device list */
    if (dev->ref_count != 0) {
        fprintf(stderr, "Cannot close DAG device with non zero reference in "
                        "dag_close_device()\n");
        return;
    }

    if (dev->prev == NULL) {
        open_dags = dev->next;
        if (dev->next)
            dev->next->prev = NULL;
    } else {
        dev->prev->next = dev->next;
        if (dev->next)
            dev->next->prev = dev->prev;
    }

    if (dev->dev_name)
        free(dev->dev_name);

    dag_close(dev->fd);
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
static struct dag_dev_t *dag_open_output_device(libtrace_out_t *libtrace,
                                                char *dev_name)
{
    struct stat buf;
    int fd;
    struct dag_dev_t *new_dev;

    /* Make sure the device exists */
    if (stat(dev_name, &buf) == -1) {
        trace_set_err_out(libtrace, errno, "stat(%s)", dev_name);
        return NULL;
    }

    /* Make sure it is the appropriate type of device */
    if (S_ISCHR(buf.st_mode)) {
        /* Try opening the DAG device */
        if ((fd = dag_open(dev_name)) < 0) {
            trace_set_err_out(libtrace, errno, "Cannot open DAG %s", dev_name);
            return NULL;
        }
    } else {
        trace_set_err_out(libtrace, errno, "Not a valid dag device: %s",
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
static struct dag_dev_t *dag_open_device(libtrace_t *libtrace, char *dev_name)
{
    struct stat buf;
    int fd;
    struct dag_dev_t *new_dev;

    /* Make sure the device exists */
    if (stat(dev_name, &buf) == -1) {
        trace_set_err(libtrace, errno, "stat(%s)", dev_name);
        return NULL;
    }

    /* Make sure it is the appropriate type of device */
    if (S_ISCHR(buf.st_mode)) {
        /* Try opening the DAG device */
        if ((fd = dag_open(dev_name)) < 0) {
            trace_set_err(libtrace, errno, "Cannot open DAG %s", dev_name);
            return NULL;
        }
    } else {
        trace_set_err(libtrace, errno, "Not a valid dag device: %s", dev_name);
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
static int dag_init_output(libtrace_out_t *libtrace)
{
    /* Upon successful creation, the device name is stored against the
     * device and free when it is free()d */
    char *dag_dev_name = NULL;
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
    if ((scan = strchr(libtrace->uridata, ',')) == NULL) {
        dag_dev_name = strdup(libtrace->uridata);
    } else {
        dag_dev_name = (char *)strndup(libtrace->uridata,
                                       (size_t)(scan - libtrace->uridata));
        stream = atoi(++scan);
    }
    FORMAT_DATA_OUT->dagstream = stream;

    /* See if our DAG device is already open */
    dag_device = dag_find_open_device(dag_dev_name);

    if (dag_device == NULL) {
        /* Device not yet opened - open it ourselves */
        dag_device = dag_open_output_device(libtrace, dag_dev_name);
    } else {
        /* Otherwise, just use the existing one */
        free(dag_dev_name);
        dag_dev_name = NULL;
    }

    /* Make sure we have successfully opened a DAG device */
    if (dag_device == NULL) {
        if (dag_dev_name) {
            free(dag_dev_name);
        }
        pthread_mutex_unlock(&open_dag_mutex);
        return -1;
    }

    FORMAT_DATA_OUT->device = dag_device;
    pthread_mutex_unlock(&open_dag_mutex);
    return 0;
}

/* Creates and initialises a DAG input trace */
static int dag_init_input(libtrace_t *libtrace)
{
    /* Upon successful creation, the device name is stored against the
     * device and free when it is free()d */
    char *dag_dev_name = NULL;
    char *scan = NULL;
    int stream = 0;
    struct dag_dev_t *dag_device = NULL;

    dag_init_format_data(libtrace);
    /* Grab the mutex while we're likely to be messing with the device
     * list */
    pthread_mutex_lock(&open_dag_mutex);

    FORMAT_DATA->stream_attached = 0;
    /* DAG cards support multiple streams. In a single threaded capture,
     * these are specified using a comma in the libtrace URI,
     * e.g. dag:/dev/dag0,2 refers to stream 2 on the dag0 device.
     *
     * If no stream is specified, we will read from stream 0 with
     * one thread
     */
    if ((scan = strchr(libtrace->uridata, ',')) == NULL) {
        dag_dev_name = strdup(libtrace->uridata);
    } else {
        dag_dev_name = (char *)strndup(libtrace->uridata,
                                       (size_t)(scan - libtrace->uridata));
        stream = atoi(++scan);
    }

    FORMAT_DATA_FIRST->dagstream = stream;

    /* See if our DAG device is already open */
    dag_device = dag_find_open_device(dag_dev_name);

    if (dag_device == NULL) {
        /* Device not yet opened - open it ourselves */
        dag_device = dag_open_device(libtrace, dag_dev_name);
    } else {
        /* Otherwise, just use the existing one */
        free(dag_dev_name);
        dag_dev_name = NULL;
    }

    /* Make sure we have successfully opened a DAG device */
    if (dag_device == NULL) {
        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
                      "Unable to open DAG device %s", dag_dev_name);
        if (dag_dev_name)
            free(dag_dev_name);
        dag_dev_name = NULL;
        pthread_mutex_unlock(&open_dag_mutex);
        return -1;
    }

    FORMAT_DATA->device = dag_device;

    /* See Config_Status_API_Programming_Guide.pdf from the Endace
       Dag Documentation */
    /* Check kBooleanAttributeActive is true -- no point capturing
     * on an interface that's disabled
     *
     * The symptom of the port being disabled is that libtrace
     * will appear to hang. */
    /* Check kBooleanAttributeFault is false */
    /* Check kBooleanAttributeLocalFault is false */
    /* Check kBooleanAttributeLock is true ? */
    /* Check kBooleanAttributePeerLink ? */

    /* Set kBooleanAttributePromisc/kBooleanPromiscuousMode based
       on libtrace promisc attribute?*/
    /* Set kUint32AttributeSnapLength to the snaplength */

    pthread_mutex_unlock(&open_dag_mutex);
    return 0;
}

#ifdef HAVE_DAG_CONFIG_API_H
static int dag_csapi_set_snaplen(libtrace_t *libtrace, int slen)
{
    dag_card_ref_t card_ref = NULL;
    dag_component_t root = NULL;
    attr_uuid_t uuid = 0;

    if (slen < 0)
        slen = 0;

    card_ref = dag_config_init(FORMAT_DATA->device->dev_name);
    root = dag_config_get_root_component(card_ref);

    uuid =
        dag_component_get_config_attribute_uuid(root, kBooleanAttributeVarlen);
    dag_config_set_boolean_attribute(card_ref, uuid, true);

    uuid = dag_component_get_config_attribute_uuid(root,
                                                   kUint32AttributeSnaplength);
    dag_config_set_uint32_attribute(card_ref, uuid, (uint32_t)slen);

    return 0;
}
#endif /* HAVE_DAG_CONFIG_API_H */

/* Configures a DAG input trace */
static int dag_config_input(libtrace_t *libtrace, trace_option_t option,
                            void *data)
{
    switch (option) {
    case TRACE_OPTION_META_FREQ:
        /* This option is used to specify the frequency of DUCK
         * updates */
        DUCK.duck_freq = *(int *)data;
        return 0;
    case TRACE_OPTION_SNAPLEN:
#ifdef HAVE_DAG_CONFIG_API_H
        return dag_csapi_set_snaplen(libtrace, *(int *)data);
#else
        /* Tell the card our new snap length */
        {
            char conf_str[4096];
            snprintf(conf_str, 4096, "varlen slen=%i", *(int *)data);
            if (dag_configure(FORMAT_DATA->device->fd, conf_str) != 0) {
                trace_set_err(libtrace, errno,
                              "Failed to configure "
                              "snaplen on DAG card: %s",
                              libtrace->uridata);
                return -1;
            }
        }
#endif /* HAVE_DAG_CONFIG_API_H */

        return 0;
    case TRACE_OPTION_PROMISC:
        /* DAG already operates in a promisc fashion */
        return -1;
    case TRACE_OPTION_FILTER:
        /* We don't yet support pushing filters into DAG
         * cards */
        return -1;
    case TRACE_OPTION_EVENT_REALTIME:
    case TRACE_OPTION_REPLAY_SPEEDUP:
        /* Live capture is always going to be realtime */
        return -1;
    case TRACE_OPTION_HASHER:
        return -1;
    case TRACE_OPTION_CONSTANT_ERF_FRAMING:
        return -1;
    case TRACE_OPTION_DISCARD_META:
    case TRACE_OPTION_XDP_HARDWARE_OFFLOAD:
    case TRACE_OPTION_XDP_SKB_MODE:
    case TRACE_OPTION_XDP_DRV_MODE:
    case TRACE_OPTION_XDP_ZERO_COPY_MODE:
    case TRACE_OPTION_XDP_COPY_MODE:
        return -1;
    }
    return -1;
}

/* Starts a DAG output trace */
static int dag_start_output(libtrace_out_t *libtrace)
{
    struct timeval zero, nopoll;

    zero.tv_sec = 0;
    zero.tv_usec = 0;
    nopoll = zero;

    /* if trying to perform TX on a RX stream (rx streams are even numbers)
     * put the card in reverse mode. */
    if (FORMAT_DATA_OUT->dagstream % 2 == 0) {
        // @param mode DAG_REVERSE_MODE (1) or DAG_NORMAL_MODE (0)
        if (dag_set_mode(FORMAT_DATA_OUT->device->fd,
                         FORMAT_DATA_OUT->dagstream, 1) != 0) {

            trace_set_err_out(libtrace, errno, "Cannot set DAG reverse mode");
            return -1;
        }
        fprintf(stderr, "Opening %s in reverse mode\n", libtrace->uridata);
    }

    /* Attach and start the DAG stream */
    if (dag_attach_stream64(FORMAT_DATA_OUT->device->fd,
                            FORMAT_DATA_OUT->dagstream, 0,
                            TX_EXTRA_WINDOW) < 0) {
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
    dag_set_stream_poll64(FORMAT_DATA_OUT->device->fd,
                          FORMAT_DATA_OUT->dagstream, 0, &zero, &nopoll);

    return 0;
}

static int dag_start_input_stream(libtrace_t *libtrace,
                                  struct dag_per_stream_t *stream)
{
    struct timeval zero, nopoll;
    uint8_t *top, *bottom, *starttop;
    top = bottom = NULL;

    zero.tv_sec = 0;
    zero.tv_usec = 10000;
    nopoll = zero;

    /* if trying to perform RX on a TX stream (tx streams are even odd numbers)
     * put the card in reverse mode. */
    if (stream->dagstream % 2 != 0) {
        // @param mode DAG_REVERSE_MODE (1) or DAG_NORMAL_MODE (0)
        if (dag_set_mode(FORMAT_DATA->device->fd, stream->dagstream, 1) != 0) {

            trace_set_err(libtrace, errno, "Cannot set DAG reverse mode");
            return -1;
        }
        fprintf(stderr, "Opening %s in reverse mode\n", libtrace->uridata);
    }

    /* Attach and start the DAG stream */
    if (dag_attach_stream64(FORMAT_DATA->device->fd, stream->dagstream, 0, 0) <
        0) {
        trace_set_err(libtrace, errno, "Cannot attach DAG stream #%u",
                      stream->dagstream);
        return -1;
    }

    if (dag_start_stream(FORMAT_DATA->device->fd, stream->dagstream) < 0) {
        trace_set_err(libtrace, errno, "Cannot start DAG stream #%u",
                      stream->dagstream);
        return -1;
    }
    FORMAT_DATA->stream_attached = 1;

    /* We don't want the dag card to do any sleeping */
    if (dag_set_stream_poll64(FORMAT_DATA->device->fd, stream->dagstream, 0,
                              &zero, &nopoll) < 0) {
        trace_set_err(libtrace, errno, "dag_set_stream_poll failed!");
        return -1;
    }

    starttop =
        dag_advance_stream(FORMAT_DATA->device->fd, stream->dagstream, &bottom);

    /* Should probably flush the memory hole now */
    top = starttop;
    while (starttop - bottom > 0) {
        bottom += (starttop - bottom);
        top = dag_advance_stream(FORMAT_DATA->device->fd, stream->dagstream,
                                 &bottom);
    }
    stream->top = top;
    stream->bottom = bottom;
    stream->processed = 0;
    stream->drops = 0;

    return 0;
}

/* Starts a DAG input trace */
static int dag_start_input(libtrace_t *libtrace)
{
    return dag_start_input_stream(libtrace, FORMAT_DATA_FIRST);
}

static int dag_pstart_input(libtrace_t *libtrace)
{
    char *scan, *tok;
    uint16_t stream_count = 0, max_streams;
    int iserror = 0;
    struct dag_per_stream_t stream_data;
    libtrace_list_node_t *streams = FORMAT_DATA_HEAD;

    /* Check we aren't trying to create more threads than the DAG card can
     * handle */
    max_streams = dag_rx_get_stream_count(FORMAT_DATA->device->fd);
    if (libtrace->perpkt_thread_count > max_streams) {
        fprintf(stderr,
                "WARNING: DAG has only %u streams available, "
                "capping total number of threads at this value.",
                max_streams);
        libtrace->perpkt_thread_count = max_streams;
    }

    /* Get the stream names from the uri */
    if ((scan = strchr(libtrace->uridata, ',')) == NULL) {
        trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT,
                      "Format uri doesn't specify the DAG streams");
        iserror = 1;
        goto cleanup;
    }

    scan++;

    tok = strtok(scan, ",");
    while (tok != NULL) {
        /* Ensure we haven't specified too many streams */
        if (stream_count >= libtrace->perpkt_thread_count) {
            fprintf(stderr,
                    "WARNING: Format uri specifies too many "
                    "streams. Maximum is %u, so only using "
                    "the first %u from the uri.",
                    libtrace->perpkt_thread_count,
                    libtrace->perpkt_thread_count);
            break;
        }

        /* Save the stream details */
        if (stream_count == 0) {
            /* Special case where we update the existing stream
             * data structure */
            FORMAT_DATA_FIRST->dagstream = (uint16_t)atoi(tok);
        } else {
            memset(&stream_data, 0, sizeof(stream_data));
            stream_data.dagstream = (uint16_t)atoi(tok);
            libtrace_list_push_back(FORMAT_DATA->per_stream, &stream_data);
        }

        stream_count++;
        tok = strtok(NULL, ",");
    }

    if (stream_count < libtrace->perpkt_thread_count) {
        libtrace->perpkt_thread_count = stream_count;
    }

    /* Attach and start each DAG stream */
    while (streams != NULL) {
        if (dag_start_input_stream(libtrace, streams->data) < 0) {
            return -1;
        }
        streams = streams->next;
    }

    FORMAT_DATA->stream_attached = 1;

cleanup:
    if (iserror) {
        return -1;
    } else {
        return 0;
    }
}

/* Pauses a DAG output trace */
static int dag_pause_output(libtrace_out_t *libtrace)
{
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
static int dag_pause_input(libtrace_t *libtrace)
{
    libtrace_list_node_t *tmp = FORMAT_DATA_HEAD;

    /* Stop and detach each stream */
    while (tmp != NULL) {
        if (dag_stop_stream(FORMAT_DATA->device->fd,
                            STREAM_DATA(tmp)->dagstream) < 0) {
            trace_set_err(libtrace, errno, "Could not stop DAG stream");
            return -1;
        }
        if (dag_detach_stream(FORMAT_DATA->device->fd,
                              STREAM_DATA(tmp)->dagstream) < 0) {
            trace_set_err(libtrace, errno, "Could not detach DAG stream");
            return -1;
        }

        tmp = tmp->next;
    }

    FORMAT_DATA->stream_attached = 0;
    return 0;
}

/* Closes a DAG input trace */
static int dag_fin_input(libtrace_t *libtrace)
{
    /* Need the lock, since we're going to be handling the device list */
    pthread_mutex_lock(&open_dag_mutex);

    /* Detach the stream if we are not paused */
    if (FORMAT_DATA->stream_attached)
        dag_pause_input(libtrace);
    FORMAT_DATA->device->ref_count--;

    /* Close the DAG device if there are no more references to it */
    if (FORMAT_DATA->device->ref_count == 0)
        dag_close_device(FORMAT_DATA->device);
    if (DUCK.dummy_duck)
        trace_destroy_dead(DUCK.dummy_duck);

    /* Clear the list */
    libtrace_list_deinit(FORMAT_DATA->per_stream);
    free(libtrace->format_data);
    pthread_mutex_unlock(&open_dag_mutex);
    return 0; /* success */
}

static int dag_flush_output(libtrace_out_t *libtrace)
{

    /* Commit any outstanding traffic in the txbuffer */
    if (FORMAT_DATA_OUT->waiting) {
        /* dag_tx_stream_commit_bytes64 does not successfully write to vDAGs
         * so we use dag_tx_stream_commit_records64 instead, both have the same
         * behaviour when writing to a DAG card.
         */
        FORMAT_DATA_OUT->txbuffer = dag_tx_stream_commit_records64(
            FORMAT_DATA_OUT->device->fd, FORMAT_DATA_OUT->dagstream,
            FORMAT_DATA_OUT->waiting);
        if (FORMAT_DATA_OUT->txbuffer == NULL) {
            trace_set_err_out(libtrace, TRACE_ERR_BAD_IO,
                              "DAG25: unable to commit tx stream");
        }
        FORMAT_DATA_OUT->waiting = 0;
    }

    return 0;
}

/* Closes a DAG output trace */
static int dag_fin_output(libtrace_out_t *libtrace)
{

    /* Commit any outstanding traffic in the txbuffer */
    dag_flush_output(libtrace);

    int out;
    int last = 0;
    /* Wait until the buffer is clear before exiting the program,
     * as we will lose packets otherwise */
    while ((out = dag_get_stream_buffer_level64(FORMAT_DATA_OUT->device->fd,
                                                FORMAT_DATA_OUT->dagstream))) {
        /* Wait for dag to complete writing all data */

        /* This is very unpredictable, Sometimes we get 0 returned,
         * sometimes 8 when using a vDAG and other time some random
         * number, so if a identical value is returned skip over this...
         */
        if (last == out) {
            break;
        }

        if (out == 8) {
            break;
        }

        last = out;

        /* give some time to write output */
        usleep(500);
    }

    /* Need the lock, since we're going to be handling the device list */
    pthread_mutex_lock(&open_dag_mutex);

    /* Detach the stream if we are not paused */
    if (FORMAT_DATA_OUT->stream_attached)
        dag_pause_output(libtrace);
    FORMAT_DATA_OUT->device->ref_count--;

    /* Close the DAG device if there are no more references to it */
    if (FORMAT_DATA_OUT->device->ref_count == 0)
        dag_close_device(FORMAT_DATA_OUT->device);
    free(libtrace->format_data);
    pthread_mutex_unlock(&open_dag_mutex);
    return 0; /* success */
}

#ifdef DAGIOC_CARD_DUCK
#    define LIBTRACE_DUCK_IOCTL DAGIOC_CARD_DUCK
#    define LIBTRACE_DUCK_VERSION TRACE_RT_DUCK_5_0
#else
#    ifdef DAGIOCDUCK
#        define LIBTRACE_DUCK_IOCTL DAGIOCDUCK
#        define LIBTRACE_DUCK_VERSION TRACE_RT_DUCK_2_5
#    else
#        warning "DAG appears to be missing DUCK support"
#    endif
#endif

/* Extracts DUCK information from the DAG card and produces a DUCK packet */
static int dag_get_duckinfo(libtrace_t *libtrace, libtrace_packet_t *packet)
{

    if (DUCK.duck_freq == 0)
        return 0;

#ifndef LIBTRACE_DUCK_IOCTL
    trace_set_err(libtrace, errno,
                  "Requested DUCK information but unable to determine the "
                  "correct ioctl for DUCK");
    DUCK.duck_freq = 0;
    return -1;
#endif

    if (DUCK.last_pkt - DUCK.last_duck < DUCK.duck_freq)
        return 0;

    /* Allocate memory for the DUCK data */
    if (packet->buf_control == TRACE_CTRL_EXTERNAL || !packet->buffer) {
        packet->buffer = malloc(LIBTRACE_PACKET_BUFSIZE);
        packet->buf_control = TRACE_CTRL_PACKET;
        if (!packet->buffer) {
            trace_set_err(libtrace, errno, "Cannot allocate packet buffer");
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
    packet->error = sizeof(duckinf_t);
    return sizeof(duckinf_t);
}

/* Determines the amount of data available to read from the DAG card */
static int dag_available(libtrace_t *libtrace,
                         struct dag_per_stream_t *stream_data)
{
    uint32_t diff = stream_data->top - stream_data->bottom;

    /* If we've processed more than 4MB of data since we last called
     * dag_advance_stream, then we should call it again to allow the
     * space occupied by that 4MB to be released */
    if (diff >= dag_record_size && stream_data->processed < 4 * 1024 * 1024)
        return diff;

    /* Update the top and bottom pointers */
    stream_data->top =
        dag_advance_stream(FORMAT_DATA->device->fd, stream_data->dagstream,
                           &(stream_data->bottom));

    if (stream_data->top == NULL) {
        trace_set_err(libtrace, errno, "dag_advance_stream failed!");
        return -1;
    }
    stream_data->processed = 0;
    diff = stream_data->top - stream_data->bottom;
    return diff;
}

/* Returns a pointer to the start of the next complete ERF record */
static int dag_get_record(struct dag_per_stream_t *stream_data,
                          dag_record_t **erfptr)
{
    uint16_t size;

    *erfptr = (dag_record_t *)stream_data->bottom;
    if (!(*erfptr))
        return 0;

    size = ntohs((*erfptr)->rlen);
    if (size < dag_record_size) {
        fprintf(stderr,
                "DAG2.5 rlen is invalid (rlen %u, must be at least %u\n", size,
                dag_record_size);
        *erfptr = NULL;
        return -1;
    }

    /* Make certain we have the full packet available */
    if (size > (stream_data->top - stream_data->bottom)) {
        *erfptr = NULL;
        return 0;
    }

    stream_data->bottom += size;
    stream_data->processed += size;
    return 1;
}

/* Converts a buffer containing a recently read DAG packet record into a
 * libtrace packet */
static int dag_prepare_packet_stream(libtrace_t *libtrace,
                                     struct dag_per_stream_t *stream_data,
                                     libtrace_packet_t *packet, void *buffer,
                                     libtrace_rt_types_t rt_type,
                                     uint32_t flags)
{
    dag_record_t *erfptr;

    /* If the packet previously owned a buffer that is not the buffer
     * that contains the new packet data, we're going to need to free the
     * old one to avoid memory leaks */
    if (packet->buffer != buffer && packet->buf_control == TRACE_CTRL_PACKET) {
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
        packet->payload =
            (char *)packet->buffer + erf_get_framing_length(packet);
    }

    if (libtrace->format_data == NULL) {
        dag_init_format_data(libtrace);
    }

    /* Update the dropped packets counter */
    /* No loss counter for DSM coloured records - have to use some
     * other API */
    if (erf_is_color_type(erfptr->type)) {
        /* TODO */
    } else {
        /* Use the ERF loss counter */
        if (stream_data->seeninterface[erfptr->flags.iface] == 0) {
            stream_data->seeninterface[erfptr->flags.iface] = 1;
        } else {
            stream_data->drops += ntohs(erfptr->lctr);
        }
    }

    return 0;
}

static int dag_prepare_packet(libtrace_t *libtrace, libtrace_packet_t *packet,
                              void *buffer, libtrace_rt_types_t rt_type,
                              uint32_t flags)
{
    return dag_prepare_packet_stream(libtrace, FORMAT_DATA_FIRST, packet,
                                     buffer, rt_type, flags);
}

/*
 * dag_write_packet() at this stage attempts to improve tx performance
 * by delaying sending a dag_tx_stream_commit_bytes() until a threshold
 * has been met. I observed approximately 270% performance increase
 * through this relatively naive tweak. No optimisation of buffer sizes
 * was attempted.
 */

/* Pushes an ERF record onto the transmit stream */
static int dag_dump_packet(libtrace_out_t *libtrace, dag_record_t *erfptr,
                           int framinglen, void *buffer, int caplen,
                           int padding)
{

    uint64_t padding_buf = 0;

    /*
     * If we've got 0 bytes waiting in the txqueue, assume that we
     * haven't requested any space yet, and request some, storing
     * the pointer at FORMAT_DATA_OUT->txbuffer.
     */
    if (FORMAT_DATA_OUT->waiting == 0) {
        while (1) {
            if ((FORMAT_DATA_OUT->txbuffer = dag_tx_get_stream_space64(
                     FORMAT_DATA_OUT->device->fd, FORMAT_DATA_OUT->dagstream,
                     TX_BATCH_SIZE)) == NULL) {
                if (errno == EAGAIN)
                    continue;
                trace_set_err_out(
                    libtrace, TRACE_ERR_BAD_IO,
                    "DAG25: unable "
                    "to reserve stream space dag_tx_get_stream_space64()");
                return 0;
            } else
                break;
        }
    }

    /*
     * Copy the header separately to the body, as we can't guarantee they
     * are in contiguous memory
     */
    memcpy(FORMAT_DATA_OUT->txbuffer + FORMAT_DATA_OUT->waiting, erfptr,
           framinglen);
    FORMAT_DATA_OUT->waiting += framinglen;

    /*
     * Copy our incoming packet into the outgoing buffer, and increment
     * our waiting count
     */
    memcpy(FORMAT_DATA_OUT->txbuffer + FORMAT_DATA_OUT->waiting, buffer,
           caplen);
    FORMAT_DATA_OUT->waiting += caplen;

    // add padding to payload to align with 8 bytes
    memcpy(FORMAT_DATA_OUT->txbuffer + FORMAT_DATA_OUT->waiting, &padding_buf,
           padding);
    FORMAT_DATA_OUT->waiting += padding;

    /*
     * If our output buffer has more than TX_BATCH_THOLD bytes queued, commit
     * those bytes to the network and reset the waiting count to 0. Note:
     * dag_fin_output() will also call dag_flush_output() in case there is still
     * data in the buffer at program exit.
     */
    if (FORMAT_DATA_OUT->waiting >= TX_BATCH_THOLD) {
        dag_flush_output(libtrace);
    }

    return framinglen + caplen + padding;
}

static int libtrace_to_dag_hdr(libtrace_out_t *libtrace,
                               libtrace_packet_t *packet, dag_record_t *erf,
                               int *framinglen, int *caplen, int *padding)
{

    int wlen;

    /* If we've had an rxerror, we have no payload to write.
     * So we cannot write this packet.
     */
    if (packet->buffer == NULL)
        return -1;

    /* Demote the packet to a linktype we can send, e.g. find Ethernet */
    if (!find_compatible_linktype(libtrace, packet))
        return -1;

    erf->ts = trace_get_erf_timestamp(packet);
    /* Fill in the packet size, it may have changed after demotion */
    if (packet->type == TRACE_RT_DATA_ERF) {
        *framinglen = trace_get_framing_length(packet);
        // update port
        erf->flags.iface = 0;
    } else {
        *framinglen = dag_record_size + erf_get_padding(packet);
        // init flags and set port to 0
        memset(&erf->flags, 0, sizeof(erf->flags));
    }

    *caplen = trace_get_capture_length(packet);

    if (trace_get_link_type(packet) == TRACE_TYPE_ETH)
        wlen = MIN((*caplen) + 4, trace_get_wire_length(packet));
    else
        wlen = MIN(*caplen, trace_get_wire_length(packet));

    *padding =
        (sizeof(uint64_t) - ((*framinglen + *caplen) % sizeof(uint64_t))) %
        sizeof(uint64_t);

    if (*caplen <= 0 || *caplen > 65536) {
        trace_set_err_out(
            libtrace, TRACE_ERR_BAD_PACKET,
            "Capture length is out of range in libtrace_to_dag_hdr()");
        return -1;
    }

    if (*framinglen > 65536) {
        trace_set_err_out(
            libtrace, TRACE_ERR_BAD_PACKET,
            "Framing length is to large in libtrace_to_dag_hdr()");
        return -1;
    }

    if (*caplen + *framinglen <= 0 || *caplen + *framinglen > 65536) {
        trace_set_err_out(libtrace, TRACE_ERR_BAD_PACKET,
                          "Capture + framing length is out of range in "
                          "libtrace_to_dag_hdr()");
        return -1;
    }

    erf->type = libtrace_to_erf_type(trace_get_link_type(packet));
    erf->rlen = htons(*framinglen + *caplen + *padding);
    // loss counter. Can't do this
    erf->lctr = 0;
    erf->wlen = htons(wlen);

    return 0;
}

/* Writes a packet to the provided DAG output trace */
static int dag_write_packet(libtrace_out_t *libtrace, libtrace_packet_t *packet)
{
    /* Check dag can write this type of packet */
    if (!dag_can_write(packet)) {
        return 0;
    }

    int framinglen;
    int caplen;
    int padding;
    dag_record_t *dag_hdr;

    if (!packet->header) {
        /* No header, probably an RT packet. Lifted from
         * erf_write_packet(). */
        return -1;
    }

    if (packet->type == TRACE_RT_DATA_ERF) {
        dag_hdr = (dag_record_t *)packet->header;
        if (libtrace_to_dag_hdr(libtrace, packet, dag_hdr, &framinglen, &caplen,
                                &padding) < 0)
            return -1;
        return dag_dump_packet(libtrace, dag_hdr, framinglen, packet->payload,
                               caplen, padding);
    } else {
        dag_record_t erfhdr;
        if (libtrace_to_dag_hdr(libtrace, packet, &erfhdr, &framinglen, &caplen,
                                &padding) < 0)
            return -1;
        return dag_dump_packet(libtrace, &erfhdr, framinglen, packet->payload,
                               caplen, padding);
    }
}

/* Reads the next available packet from a DAG card, in a BLOCKING fashion
 *
 * If DUCK reporting is enabled, the packet returned may be a DUCK update
 */
static int dag_read_packet_stream(libtrace_t *libtrace,
                                  struct dag_per_stream_t *stream_data,
                                  libtrace_thread_t *t, /* Optional */
                                  libtrace_packet_t *packet)
{
    int size = 0;
    dag_record_t *erfptr = NULL;
    struct timeval tv;
    int numbytes = 0;
    uint32_t flags = 0;
    struct timeval maxwait, pollwait;

    pollwait.tv_sec = 0;
    pollwait.tv_usec = 10000;
    maxwait.tv_sec = 0;
    maxwait.tv_usec = 250000;

    /* Check if we're due for a DUCK report - only report on the first thread */
    if (stream_data == FORMAT_DATA_FIRST) {
        size = dag_get_duckinfo(libtrace, packet);
        if (size != 0)
            return size;
    }

    /* Don't let anyone try to free our DAG memory hole! */
    flags |= TRACE_PREP_DO_NOT_OWN_BUFFER;

    /* If the packet buffer is currently owned by libtrace, free it so
     * that we can set the packet to point into the DAG memory hole */
    if (packet->buf_control == TRACE_CTRL_PACKET) {
        free(packet->buffer);
        packet->buffer = 0;
    }

    if (dag_set_stream_poll64(FORMAT_DATA->device->fd, stream_data->dagstream,
                              sizeof(dag_record_t), &maxwait,
                              &pollwait) == -1) {
        trace_set_err(libtrace, errno, "dag_set_stream_poll");
        return -1;
    }

    /* Grab a full ERF record */
    do {
        numbytes = dag_available(libtrace, stream_data);
        if (numbytes < 0)
            return numbytes;
        if (numbytes < dag_record_size) {
            /* if we have access to the message queue check for a message
             * otherwise we need to return and let libtrace check for a message
             */
            if ((t && libtrace_message_queue_count(&t->messages) > 0) || !t)
                return READ_MESSAGE;

            if ((numbytes = is_halted(libtrace)) != -1)
                return numbytes;

            /* Block until we see a packet */
            continue;
        }
        if (dag_get_record(stream_data, &erfptr) < 0) {
            trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "corrupt DAG record");
            return -1;
        }
    } while (erfptr == NULL && !libtrace_halt);

    if (libtrace_halt) {
        return 0;
    }

    packet->trace = libtrace;

    /* Prepare the libtrace packet */
    if (dag_prepare_packet_stream(libtrace, stream_data, packet, erfptr,
                                  TRACE_RT_DATA_ERF, flags))
        return -1;

    /* Update the DUCK timer - don't re-order this check (false-sharing) */
    if (stream_data == FORMAT_DATA_FIRST && DUCK.duck_freq != 0) {
        tv = trace_get_timeval(packet);
        DUCK.last_pkt = tv.tv_sec;
    }

    packet->order = erf_get_erf_timestamp(packet);
    packet->error =
        packet->payload ? htons(erfptr->rlen) : erf_get_framing_length(packet);

    return packet->error;
}

static int dag_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet)
{
    return dag_read_packet_stream(libtrace, FORMAT_DATA_FIRST, NULL, packet);
}

static int dag_pread_packets(libtrace_t *libtrace, libtrace_thread_t *t,
                             libtrace_packet_t **packets, size_t nb_packets)
{
    int ret;
    size_t read_packets = 0;
    int numbytes = 0;

    struct dag_per_stream_t *stream_data =
        (struct dag_per_stream_t *)t->format_data;

    /* Read as many packets as we can, but read atleast one packet */
    do {
        ret = dag_read_packet_stream(libtrace, stream_data, t,
                                     packets[read_packets]);
        if (ret < 0)
            return ret;

        read_packets++;

        /* Make sure we don't read too many packets..! */
        if (read_packets >= nb_packets)
            break;

        numbytes = dag_available(libtrace, stream_data);
    } while (numbytes >= dag_record_size);

    return read_packets;
}

/* Attempts to read a packet from a DAG card in a NON-BLOCKING fashion. If a
 * packet is available, we will return a packet event. Otherwise we will
 * return a SLEEP event (as we cannot select on the DAG file descriptor).
 */
static libtrace_eventobj_t trace_event_dag(libtrace_t *libtrace,
                                           libtrace_packet_t *packet)
{
    libtrace_eventobj_t event = {0, 0, 0.0, 0};
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

    if (dag_set_stream_poll64(FORMAT_DATA->device->fd,
                              FORMAT_DATA_FIRST->dagstream, 0, &minwait,
                              &minwait) == -1) {
        trace_set_err(libtrace, errno, "dag_set_stream_poll");
        event.type = TRACE_EVENT_TERMINATE;
        return event;
    }

    do {
        erfptr = NULL;
        numbytes = 0;

        /* Need to call dag_available so that the top pointer will get
         * updated, otherwise we'll never see any data! */
        numbytes = dag_available(libtrace, FORMAT_DATA_FIRST);

        /* May as well not bother calling dag_get_record if
         * dag_available suggests that there's no data */
        if (numbytes != 0) {
            if (dag_get_record(FORMAT_DATA_FIRST, &erfptr) < 0) {
                trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
                              "corrupt DAG record");
                event.type = TRACE_EVENT_TERMINATE;
                return event;
            }
        }

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
        if (dag_prepare_packet_stream(libtrace, FORMAT_DATA_FIRST, packet,
                                      erfptr, TRACE_RT_DATA_ERF, flags)) {
            event.type = TRACE_EVENT_TERMINATE;
            break;
        }

        event.size =
            trace_get_capture_length(packet) + trace_get_framing_length(packet);

        /* XXX trace_read_packet() normally applies the following
         * config options for us, but this function is called via
         * trace_event() so we have to do it ourselves */

        if (libtrace->filter) {
            int filtret = trace_apply_filter(libtrace->filter, packet);
            if (filtret == -1) {
                trace_set_err(libtrace, TRACE_ERR_BAD_FILTER, "Bad BPF Filter");
                event.type = TRACE_EVENT_TERMINATE;
                break;
            }

            if (filtret == 0) {
                /* This packet isn't useful so we want to
                 * immediately see if there is another suitable
                 * one - we definitely DO NOT want to return
                 * a sleep event in this case, like we used to
                 * do! */
                libtrace->filtered_packets++;
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
        libtrace->accepted_packets++;
        break;
    } while (1);

    return event;
}

static void dag_get_statistics(libtrace_t *libtrace, libtrace_stat_t *stat)
{
    libtrace_list_node_t *tmp;
    if (!libtrace) {
        fprintf(stderr, "NULL trace passed into dag_get_statistics()\n");
        return;
    }
    if (!stat) {
        trace_set_err(libtrace, TRACE_ERR_STAT,
                      "NULL stat passed into dag_get_statistics()");
        return;
    }
    tmp = FORMAT_DATA_HEAD;

    /* Dropped packets */
    stat->dropped_valid = 1;
    stat->dropped = 0;
    while (tmp != NULL) {
        stat->dropped += STREAM_DATA(tmp)->drops;
        tmp = tmp->next;
    }
}

static void dag_get_thread_statistics(libtrace_t *libtrace,
                                      libtrace_thread_t *t,
                                      libtrace_stat_t *stat)
{
    struct dag_per_stream_t *stream_data = t->format_data;
    if (!libtrace) {
        fprintf(stderr, "NULL trace passed into dag_get_thread_statistics()\n");
        return;
    }
    if (!stat) {
        trace_set_err(libtrace, TRACE_ERR_STAT,
                      "NULL stat passed into dag_get_thread_statistics()");
        return;
    }
    stat->dropped_valid = 1;
    stat->dropped = stream_data->drops;

    stat->filtered_valid = 1;
    stat->filtered = 0;
}

/* Prints some semi-useful help text about the DAG format module */
static void dag_help(void)
{
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

static int dag_pregister_thread(libtrace_t *libtrace, libtrace_thread_t *t,
                                bool reader)
{
    struct dag_per_stream_t *stream_data;
    libtrace_list_node_t *node;

    if (reader && t->type == THREAD_PERPKT) {
        node = libtrace_list_get_index(FORMAT_DATA->per_stream, t->perpkt_num);
        if (node == NULL) {
            return -1;
        }
        stream_data = node->data;

        /* Pass the per thread data to the thread */
        t->format_data = stream_data;
    }

    return 0;
}

static struct libtrace_format_t dag = {
    "dag",
    "$Id$",
    TRACE_FORMAT_ERF,
    dag_probe_filename,     /* probe filename */
    NULL,                   /* probe magic */
    dag_init_input,         /* init_input */
    dag_config_input,       /* config_input */
    dag_start_input,        /* start_input */
    dag_pause_input,        /* pause_input */
    dag_init_output,        /* init_output */
    NULL,                   /* config_output */
    dag_start_output,       /* start_output */
    dag_fin_input,          /* fin_input */
    dag_fin_output,         /* fin_output */
    dag_read_packet,        /* read_packet */
    dag_prepare_packet,     /* prepare_packet */
    NULL,                   /* fin_packet */
    NULL,                   /* can_hold_packet */
    dag_write_packet,       /* write_packet */
    dag_flush_output,       /* flush_output */
    erf_get_link_type,      /* get_link_type */
    erf_get_direction,      /* get_direction */
    erf_set_direction,      /* set_direction */
    erf_get_erf_timestamp,  /* get_erf_timestamp */
    NULL,                   /* get_timeval */
    NULL,                   /* get_seconds */
    NULL,                   /* get_timespec */
    NULL,                   /* get_meta_section */
    NULL,                   /* seek_erf */
    NULL,                   /* seek_timeval */
    NULL,                   /* seek_seconds */
    erf_get_capture_length, /* get_capture_length */
    erf_get_wire_length,    /* get_wire_length */
    erf_get_framing_length, /* get_framing_length */
    erf_set_capture_length, /* set_capture_length */
    NULL,                   /* get_received_packets */
    NULL,                   /* get_filtered_packets */
    NULL,                   /* get_dropped_packets */
    dag_get_statistics,     /* get_statistics */
    NULL,                   /* get_fd */
    trace_event_dag,        /* trace_event */
    dag_help,               /* help */
    NULL,                   /* next pointer */
    {true, 0},              /* live packet capture, thread limit TBD */
    dag_pstart_input,
    dag_pread_packets,
    dag_pause_input,
    NULL,
    dag_pregister_thread,
    NULL,
    dag_get_thread_statistics /* get thread stats */
};

void dag_constructor(void) { register_format(&dag); }
