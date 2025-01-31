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
#    include <sys/socket.h>
#endif
#include <stdarg.h>
#include <sys/param.h>

#ifdef HAVE_LIMITS_H
#    include <limits.h>
#endif

#ifdef HAVE_SYS_LIMITS_H
#    include <sys/limits.h>
#endif

#ifdef HAVE_NET_IF_ARP_H
#    include <net/if_arp.h>
#endif

#ifdef HAVE_NET_IF_H
#    include <net/if.h>
#endif

#ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#    include <net/ethernet.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
#    include <netinet/if_ether.h>
#endif

#include <time.h>
#ifdef WIN32
#    include <sys/timeb.h>
#endif

#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "rt_protocol.h"

#include <pthread.h>
#include <signal.h>

#define MAXOPTS 1024

/* This file contains much of the implementation of the libtrace API itself. */

static struct libtrace_format_t *formats_list = NULL;

volatile int libtrace_halt = 0;
/* Set once pstart is called used for backwards compatibility reasons */
int libtrace_parallel = 0;

static const libtrace_packet_cache_t clearcache = {
    -1, -1, -1, -1, NULL, 0, 0, NULL, 0, 0, NULL, 0, 0};

/* strncpy is not assured to copy the final \0, so we
 * will use our own one that does
 */
static inline void xstrncpy(char *dest, const char *src, size_t n,
                            size_t destlen)
{
    if (destlen == 0)
        return;

    size_t slen = destlen - 1;
    if (n < slen) {
        slen = n;
    }

    // suppress GCC warnings for string overflow
    LT_IGNORE_STRING_OVERFLOW
    strncpy(dest, src, slen);
    LT_PRAGMA_POP

    dest[slen] = '\0';
}

static char *xstrndup(const char *src, size_t n)
{
    char *ret = (char *)malloc(n + 1);
    if (ret == NULL) {
        fprintf(stderr, "Out of memory\n");
        exit(EXIT_FAILURE);
    }
    xstrncpy(ret, src, n, n + 1);
    return ret;
}

/* call all the constructors if they haven't yet all been called */
__attribute__((constructor)) static void trace_init(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand(tv.tv_sec);

    if (!formats_list) {
        duck_constructor();
        erf_constructor();
        tsh_constructor();
        legacy_constructor();
        atmhdr_constructor();
        linuxring_constructor();
        linuxnative_constructor();
#ifdef HAVE_LIBPCAP
        pcap_constructor();
#endif
        bpf_constructor();
        pcapfile_constructor();
        pcapng_constructor();
        tzsplive_constructor();
        rt_constructor();
        ndag_constructor();
#ifdef HAVE_WANDDER
        etsilive_constructor();
        etsifile_constructor();
#endif
#ifdef HAVE_DAG
        dag_constructor();
#endif
#ifdef HAVE_DPDK
        dpdk_constructor();
        dpdkndag_constructor();
#endif
#ifdef HAVE_LIBBPF
        linux_xdp_constructor();
#endif
#ifdef HAVE_PFRING
        pfringold_constructor();
        pfring_constructor();
#endif
    }
}

/* Prints help information for libtrace
 *
 * Function prints out some basic help information regarding libtrace,
 * and then prints out the help() function registered with each input module
 */
DLLEXPORT void trace_help(void)
{
    struct libtrace_format_t *tmp;
    trace_init();
    printf("libtrace %s\n\n", PACKAGE_VERSION);
    printf("Following this are a list of the format modules supported in "
           "this build of libtrace\n\n");
    for (tmp = formats_list; tmp; tmp = tmp->next) {
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
    for (tmp = formats_list; tmp; tmp = tmp->next) {
        if (tmp->probe_filename && tmp->probe_filename(filename)) {
            libtrace->format = tmp;
            libtrace->uridata = strdup(filename);
            return;
        }
    }

    libtrace->io = wandio_create(filename);
    if (!libtrace->io) {
        trace_set_err(libtrace, TRACE_ERR_URI_NOT_FOUND,
                      "Unable to find URI (%s)", filename);
        return;
    }

    /* Try and guess based on file magic */
    for (tmp = formats_list; tmp; tmp = tmp->next) {
        if (tmp->probe_magic && tmp->probe_magic(libtrace->io)) {
            libtrace->format = tmp;
            libtrace->uridata = strdup(filename);
            return;
        }
    }

    /* No formats matched -- make sure we clean up the IO object we
     * used to probe the file magic */
    wandio_destroy(libtrace->io);
    trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, "Unable to guess format (%s)",
                  filename);
    return;
}

DLLEXPORT const char *trace_get_uri_format(libtrace_t *trace) {

    if (trace == NULL) {
        return NULL;
    }
    if (trace->format == NULL) {
        return NULL;
    }

    return trace->format->name;
}

DLLEXPORT const char *trace_get_uri_body(libtrace_t *trace) {
    if (trace == NULL) {
        return NULL;
    }
    return (const char *)trace->uridata;
}

/* Creates an input trace from a URI
 *
 * @params char * containing a valid libtrace URI
 * @returns opaque pointer to a libtrace_t
 *
 * Some valid URI's are:
 *  erf:/path/to/erf/file
 *  erf:/path/to/erf/file.gz
 *  erf:-			(stdin)
 *  dag:/dev/dagcard
 *  pcapint:pcapinterface		(eg: pcapint:eth0)
 *  pcapfile:/path/to/pcap/file
 *  pcapfile:-
 *  int:interface			(eg: int:eth0) only on Linux
 *  rt:hostname
 *  rt:hostname:port
 *
 * A user may precede the URI with a comma-separated list of configuration
 * options, parsed by trace_set_configuration(), followed by a colon ':'.
 * i.e. option=value,...:URI
 *
 * For example:
 * cache_size=1024:int:eth0
 * coremap=[1,2,3],perpkt_threads=3:ring:eth0
 *
 * @see trace_set_configuration
 *
 * If an error occurred when attempting to open a trace, NULL is returned
 * and an error is output to stdout.
 */
DLLEXPORT libtrace_t *trace_create(const char *uri)
{
    libtrace_t *libtrace = (libtrace_t *)malloc(sizeof(libtrace_t));
    char *scan = 0;
    const char *uridata = 0;
    const char *uri_portion = 0;

    trace_init();

    if (!libtrace) {
        fprintf(stderr, "Unable to allocate memory in trace_create()\n");
        return NULL;
    }

    if (!uri) {
        trace_set_err(libtrace, TRACE_ERR_URI_NULL,
                      "NULL uri passed to trace_create()");
        return libtrace;
    }

    libtrace->err.err_num = TRACE_ERR_NOERROR;
    libtrace->format = NULL;

    libtrace->event.packet = NULL;
    libtrace->event.psize = 0;
    libtrace->event.first_ts = 0.0;
    libtrace->event.first_now = 0.0;
    libtrace->event.waiting = false;
    libtrace->filter = NULL;
    libtrace->snaplen = 0;
    libtrace->replayspeedup = 1;
    libtrace->started = false;
    libtrace->startcount = 0;
    libtrace->uridata = NULL;
    libtrace->io = NULL;
    libtrace->filtered_packets = 0;
    libtrace->accepted_packets = 0;
    libtrace->last_packet = NULL;

    /* Parallel inits */
    ASSERT_RET(pthread_mutex_init(&libtrace->libtrace_lock, NULL), == 0);
    ASSERT_RET(pthread_mutex_init(&libtrace->read_packet_lock, NULL), == 0);
    ASSERT_RET(pthread_cond_init(&libtrace->perpkt_cond, NULL), == 0);
    libtrace->state = STATE_NEW;
    libtrace->perpkt_queue_full = false;
    libtrace->global_blob = NULL;
    libtrace->hasher = NULL;
    libtrace->hasher_data = NULL;
    libtrace->hasher_owner = HASH_OWNED_EXTERNAL;
    libtrace_zero_ocache(&libtrace->packet_freelist);
    libtrace_zero_thread(&libtrace->hasher_thread);
    libtrace_zero_thread(&libtrace->reporter_thread);
    libtrace_zero_thread(&libtrace->keepalive_thread);
    libtrace->reporter_thread.type = THREAD_EMPTY;
    libtrace->perpkt_thread_count = 0;
    libtrace->perpkt_threads = NULL;
    libtrace->tracetime = 0;
    libtrace->first_packets.first = 0;
    libtrace->first_packets.count = 0;
    libtrace->first_packets.packets = NULL;
    libtrace->stats = NULL;
    libtrace->pread = NULL;
    libtrace->sequence_number = 0;
    ZERO_USER_CONFIG(libtrace->config);
    memset(&libtrace->combiner, 0, sizeof(libtrace->combiner));
    libtrace->perpkt_cbs = NULL;
    libtrace->reporter_cbs = NULL;

    if (_trace_set_configuration(libtrace, uri, &uri_portion) == 0) {
        if (uri_portion == NULL) {
            trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, "Unknown format (%s)",
                          uri);
            return libtrace;
        } else {
            uri = uri_portion;
        }
    } else {
        return libtrace;
    }
    /* Parse the URI to determine what sort of trace we are dealing with */
    if ((uridata = trace_parse_uri(uri, &scan)) == 0) {
        /* Could not parse the URI nicely */
        guess_format(libtrace, uri);
        if (trace_is_err(libtrace)) {
            if (scan) {
                free(scan);
            }
            return libtrace;
        }
    } else {
        struct libtrace_format_t *tmp;

        /* Find a format that matches the first part of the URI */
        for (tmp = formats_list; tmp; tmp = tmp->next) {
            if (strlen(scan) == strlen(tmp->name) &&
                strncasecmp(scan, tmp->name, strlen(scan)) == 0) {
                libtrace->format = tmp;
                break;
            }
        }

        if (libtrace->format == 0) {
            trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, "Unknown format (%s)",
                          scan);
            if (scan) {
                free(scan);
            }
            return libtrace;
        }

        libtrace->uridata = strdup(uridata);
    }
    /* libtrace->format now contains the type of uri
     * libtrace->uridata contains the appropriate data for this
     */

    /* Call the init_input function for the matching capture format */
    if (libtrace->format->init_input) {
        int err = libtrace->format->init_input(libtrace);
        if (err == -1) {
            /* init_input should call trace_set_err to set the
             * error message
             */
            if (scan) {
                free(scan);
            }
            return libtrace;
        }
    } else {
        trace_set_err(libtrace, TRACE_ERR_UNSUPPORTED,
                      "Format does not support input (%s)", scan);
        if (scan) {
            free(scan);
        }
        return libtrace;
    }

    if (scan)
        free(scan);
    libtrace->err.err_num = TRACE_ERR_NOERROR;
    libtrace->err.problem[0] = '\0';
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
DLLEXPORT libtrace_t *trace_create_dead(const char *uri)
{
    libtrace_t *libtrace = (libtrace_t *)malloc(sizeof(libtrace_t));
    char *scan = (char *)calloc(sizeof(char), URI_PROTO_LINE);
    char *uridata;
    struct libtrace_format_t *tmp;

    trace_init();

    libtrace->err.err_num = TRACE_ERR_NOERROR;

    if ((uridata = strchr(uri, ':')) == NULL) {
        xstrncpy(scan, uri, strlen(uri), URI_PROTO_LINE);
    } else {
        xstrncpy(scan, uri, (size_t)(uridata - uri), URI_PROTO_LINE);
    }

    libtrace->err.err_num = TRACE_ERR_NOERROR;
    libtrace->format = NULL;

    libtrace->event.packet = NULL;
    libtrace->event.psize = 0;
    libtrace->event.first_ts = 0;
    libtrace->event.first_now = 0;
    libtrace->filter = NULL;
    libtrace->snaplen = 0;
    libtrace->started = false;
    libtrace->startcount = 0;
    libtrace->uridata = NULL;
    libtrace->io = NULL;
    libtrace->filtered_packets = 0;
    libtrace->accepted_packets = 0;
    libtrace->last_packet = NULL;

    /* Parallel inits */
    ASSERT_RET(pthread_mutex_init(&libtrace->libtrace_lock, NULL), == 0);
    ASSERT_RET(pthread_mutex_init(&libtrace->read_packet_lock, NULL), == 0);
    ASSERT_RET(pthread_cond_init(&libtrace->perpkt_cond, NULL), == 0);
    libtrace->state = STATE_NEW; // TODO MAYBE DEAD
    libtrace->perpkt_queue_full = false;
    libtrace->global_blob = NULL;
    libtrace->hasher = NULL;
    libtrace_zero_ocache(&libtrace->packet_freelist);
    libtrace_zero_thread(&libtrace->hasher_thread);
    libtrace_zero_thread(&libtrace->reporter_thread);
    libtrace_zero_thread(&libtrace->keepalive_thread);
    libtrace->reporter_thread.type = THREAD_EMPTY;
    libtrace->perpkt_thread_count = 0;
    libtrace->perpkt_threads = NULL;
    libtrace->tracetime = 0;
    libtrace->stats = NULL;
    libtrace->pread = NULL;
    libtrace->sequence_number = 0;
    ZERO_USER_CONFIG(libtrace->config);
    memset(&libtrace->combiner, 0, sizeof(libtrace->combiner));
    libtrace->perpkt_cbs = NULL;
    libtrace->reporter_cbs = NULL;
    for (tmp = formats_list; tmp; tmp = tmp->next) {
        if (strlen(scan) == strlen(tmp->name) &&
            !strncasecmp(scan, tmp->name, strlen(scan))) {
            libtrace->format = tmp;
            break;
        }
    }
    if (libtrace->format == 0) {
        trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, "Unknown format (%s)",
                      scan);
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

DLLEXPORT libtrace_out_t *trace_create_output(const char *uri)
{
    libtrace_out_t *libtrace = (libtrace_out_t *)malloc(sizeof(libtrace_out_t));

    char *scan = 0;
    const char *uridata = 0;
    struct libtrace_format_t *tmp;

    trace_init();

    libtrace->err.err_num = TRACE_ERR_NOERROR;
    strcpy(libtrace->err.problem, "Error message set\n");
    libtrace->format = NULL;
    libtrace->uridata = NULL;

    /* Parse the URI to determine what capture format we want to write */

    if ((uridata = trace_parse_uri(uri, &scan)) == 0) {
        trace_set_err_out(libtrace, TRACE_ERR_BAD_FORMAT, "Bad uri format (%s)",
                          uri);
        return libtrace;
    }

    /* Attempt to find the format in the list of supported formats */
    for (tmp = formats_list; tmp; tmp = tmp->next) {
        if (strlen(scan) == strlen(tmp->name) &&
            !strncasecmp(scan, tmp->name, strlen(scan))) {
            libtrace->format = tmp;
            break;
        }
    }

    if (libtrace->format == NULL) {
        trace_set_err_out(libtrace, TRACE_ERR_BAD_FORMAT,
                          "Unknown output format (%s)", scan);
        free(scan);
        return libtrace;
    }
    libtrace->uridata = strdup(uridata);

    /* libtrace->format now contains the type of uri
     * libtrace->uridata contains the appropriate data for this
     */

    if (libtrace->format->init_output) {
        int err = libtrace->format->init_output(libtrace);
        if (err == -1) {
            /* init_output should call trace_set_err to set the
             * error message
             */
            free(scan);
            return libtrace;
        }
    } else {
        trace_set_err_out(libtrace, TRACE_ERR_UNSUPPORTED,
                          "Format does not support writing (%s)", scan);
        free(scan);
        return libtrace;
    }
    free(scan);

    libtrace->started = false;
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
    if (!libtrace) {
        fprintf(stderr, "NULL trace passed to trace_start()\n");
        return TRACE_ERR_NULL_TRACE;
    }

    if (trace_is_err(libtrace))
        return -1;
    if (libtrace->format->start_input) {
        int ret = libtrace->format->start_input(libtrace);
        if (ret < 0) {
            return ret;
        }
    }
    libtrace->startcount++;
    libtrace->started = true;
    return 0;
}

/* Start an output trace */
DLLEXPORT int trace_start_output(libtrace_out_t *libtrace)
{
    if (!libtrace) {
        fprintf(stderr, "NULL trace passed to trace_start_output()\n");
        return TRACE_ERR_NULL_TRACE;
    }
    if (libtrace->format->start_output) {
        int ret = libtrace->format->start_output(libtrace);
        if (ret < 0) {
            return ret;
        }
    }

    libtrace->started = true;
    return 0;
}

DLLEXPORT int trace_pause(libtrace_t *libtrace)
{
    if (!libtrace) {
        fprintf(stderr, "NULL trace passed to trace_pause()\n");
        return TRACE_ERR_NULL_TRACE;
    }
    if (!libtrace->started) {
        trace_set_err(
            libtrace, TRACE_ERR_BAD_STATE,
            "You must call trace_start() before calling trace_pause()");
        return -1;
    }

    /* Finish the last packet we read - for backwards compatibility */
    if (!libtrace_parallel && libtrace->last_packet)
        trace_fin_packet(libtrace->last_packet);
    if (libtrace->last_packet != NULL) {
        trace_set_err(libtrace, TRACE_ERR_PAUSE_FIN,
                      "Unable to remove all data stored against trace "
                      "in trace_pause()");
        return -1;
    }

    if (libtrace->format->pause_input)
        libtrace->format->pause_input(libtrace);

    libtrace->started = false;
    return 0;
}

DLLEXPORT int trace_config(libtrace_t *libtrace, trace_option_t option,
                           void *value)
{
    int ret;

    if (trace_is_err(libtrace)) {
        return -1;
    }

    if (option == TRACE_OPTION_HASHER)
        return trace_set_hasher(libtrace, (enum hasher_types) * ((int *)value),
                                NULL, NULL);

    /* If the capture format supports configuration, try using their
     * native configuration first */
    if (libtrace->format->config_input) {
        ret = libtrace->format->config_input(libtrace, option, value);
        if (ret == 0)
            return 0;
    }

    /* If we get here, either the native configuration failed or the
     * format did not support configuration. However, libtrace can
     * deal with some options itself, so give that a go */
    switch (option) {
    case TRACE_OPTION_REPLAY_SPEEDUP:
        /* Clear the error if there was one */
        if (trace_is_err(libtrace)) {
            trace_get_err(libtrace);
        }
        if (*(int *)value < 1 || *(int *)value > LIBTRACE_MAX_REPLAY_SPEEDUP) {
            trace_set_err(libtrace, TRACE_ERR_BAD_STATE,
                          "Invalid replay speed");
        }
        libtrace->replayspeedup = *(int *)value;
        return 0;

    case TRACE_OPTION_SNAPLEN:
        /* Clear the error if there was one */
        if (trace_is_err(libtrace)) {
            trace_get_err(libtrace);
        }
        if (*(int *)value < 0 || *(int *)value > LIBTRACE_PACKET_BUFSIZE) {
            trace_set_err(libtrace, TRACE_ERR_BAD_STATE, "Invalid snap length");
        }
        libtrace->snaplen = *(int *)value;
        return 0;
    case TRACE_OPTION_FILTER:
        /* Clear the error if there was one */
        if (trace_is_err(libtrace)) {
            trace_get_err(libtrace);
        }
        libtrace->filter = (libtrace_filter_t *)value;
        return 0;
    case TRACE_OPTION_PROMISC:
        if (!trace_is_err(libtrace)) {
            trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                          "Promisc mode is not supported by this "
                          "format module");
        }
        return -1;
    case TRACE_OPTION_META_FREQ:
        if (!trace_is_err(libtrace)) {
            trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                          "This format does not support meta-data gathering");
        }
        return -1;
    case TRACE_OPTION_EVENT_REALTIME:
        if (!trace_is_err(libtrace)) {
            trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                          "This format does not support realtime events");
        }
        return -1;
    case TRACE_OPTION_HASHER:
        /* Dealt with earlier */
        return -1;
    case TRACE_OPTION_CONSTANT_ERF_FRAMING:
        if (!trace_is_err(libtrace)) {
            trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                          "This format does not feature an ERF "
                          "header or does not support bypassing "
                          "the framing length calculation");
        }
        return -1;
    case TRACE_OPTION_DISCARD_META:
        if (!trace_is_err(libtrace)) {
            trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                          "Libtrace does not support meta packets "
                          "for this format");
        }
        return -1;
    case TRACE_OPTION_XDP_HARDWARE_OFFLOAD:
        if (!trace_is_err(libtrace)) {
            trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                          "Libtrace does not support XDP hardware "
                          "offloading for this format");
        }
        return -1;
    case TRACE_OPTION_XDP_ZERO_COPY_MODE:
        if (!trace_is_err(libtrace)) {
            trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                          "Libtrace does not support XDP zero copy "
                          "mode for this format");
        }
        return -1;
    case TRACE_OPTION_XDP_COPY_MODE:
        if (!trace_is_err(libtrace)) {
            trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                          "Libtrace does not support XDP copy mode "
                          "for this format");
        }
        return -1;
    case TRACE_OPTION_XDP_DRV_MODE:
        if (!trace_is_err(libtrace)) {
            trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                          "Libtrace does not support installing "
                          "XDP program in native/driver mode");
        }
        return -1;
    case TRACE_OPTION_XDP_SKB_MODE:
        if (!trace_is_err(libtrace)) {
            trace_set_err(libtrace, TRACE_ERR_OPTION_UNAVAIL,
                          "Libtrace does not support installing "
                          "XDP program in SKB (generic) mode");
        }
        return -1;
    }
    if (!trace_is_err(libtrace)) {
        trace_set_err(libtrace, TRACE_ERR_UNKNOWN_OPTION, "Unknown option %i",
                      option);
    }
    return -1;
}

DLLEXPORT int trace_set_snaplen(libtrace_t *trace, int snaplen)
{
    return trace_config(trace, TRACE_OPTION_SNAPLEN, &snaplen);
}

DLLEXPORT int trace_set_promisc(libtrace_t *trace, bool promisc)
{
    int tmp = promisc;
    return trace_config(trace, TRACE_OPTION_PROMISC, &tmp);
}

DLLEXPORT int trace_set_filter(libtrace_t *trace, libtrace_filter_t *filter)
{
    return trace_config(trace, TRACE_OPTION_FILTER, filter);
}

DLLEXPORT int trace_set_meta_freq(libtrace_t *trace, int freq)
{
    return trace_config(trace, TRACE_OPTION_META_FREQ, &freq);
}

DLLEXPORT int trace_set_event_realtime(libtrace_t *trace, bool realtime)
{
    int tmp = realtime;
    return trace_config(trace, TRACE_OPTION_EVENT_REALTIME, &tmp);
}

DLLEXPORT int trace_config_output(libtrace_out_t *libtrace,
                                  trace_option_output_t option, void *value)
{

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
DLLEXPORT void trace_destroy(libtrace_t *libtrace)
{
    int i;

    if (!libtrace) {
        fprintf(stderr, "NULL trace passed to trace_destroy()\n");
        return;
    }

    ASSERT_RET(pthread_mutex_destroy(&libtrace->libtrace_lock), == 0);
    ASSERT_RET(pthread_mutex_destroy(&libtrace->read_packet_lock), == 0);
    ASSERT_RET(pthread_cond_destroy(&libtrace->perpkt_cond), == 0);

    /* destroy any packets that are still around */
    if (libtrace->state != STATE_NEW && libtrace->first_packets.packets) {
        for (i = 0; i < libtrace->perpkt_thread_count; ++i) {
            if (libtrace->first_packets.packets[i].packet) {
                trace_destroy_packet(libtrace->first_packets.packets[i].packet);
            }
        }
        free(libtrace->first_packets.packets);
        ASSERT_RET(pthread_spin_destroy(&libtrace->first_packets.lock), == 0);
    }

    /* Finish any the last packet we read - for backwards compatibility */
    if (!libtrace_parallel && libtrace->last_packet) {
        trace_fin_packet(libtrace->last_packet);
    }
    if (libtrace->last_packet != NULL) {
        trace_set_err(libtrace, TRACE_ERR_PAUSE_FIN,
                      "Unable to remove all data stored against trace "
                      "in trace_destroy()");
        return;
    }

    if (libtrace->format) {
        if (libtrace->started && libtrace->format->pause_input)
            libtrace->format->pause_input(libtrace);
    }
    /* Need to free things! */
    if (libtrace->uridata)
        free(libtrace->uridata);

    if (libtrace->stats)
        free(libtrace->stats);

    /* Empty any packet memory */
    if (libtrace->state != STATE_NEW) {
        // This has all of our packets
        libtrace_ocache_destroy(&libtrace->packet_freelist);
        for (i = 0; i < libtrace->perpkt_thread_count; ++i) {
            libtrace_message_queue_destroy(
                &libtrace->perpkt_threads[i].messages);
        }
        if (libtrace->hasher_thread.type == THREAD_HASHER)
            libtrace_message_queue_destroy(&libtrace->hasher_thread.messages);
        if (libtrace->keepalive_thread.type == THREAD_KEEPALIVE)
            libtrace_message_queue_destroy(
                &libtrace->keepalive_thread.messages);
        if (libtrace->reporter_thread.type == THREAD_REPORTER)
            libtrace_message_queue_destroy(&libtrace->reporter_thread.messages);

        if (libtrace->combiner.destroy && libtrace->reporter_cbs)
            libtrace->combiner.destroy(libtrace, &libtrace->combiner);
        free(libtrace->perpkt_threads);
        libtrace->perpkt_threads = NULL;
        libtrace->perpkt_thread_count = 0;
    }

    if (libtrace->format) {
        if (libtrace->format->fin_input)
            libtrace->format->fin_input(libtrace);
    }

    if (libtrace->hasher_owner == HASH_OWNED_LIBTRACE) {
        if (libtrace->hasher_data) {
            free(libtrace->hasher_data);
        }
    }

    if (libtrace->perpkt_cbs)
        trace_destroy_callback_set(libtrace->perpkt_cbs);
    if (libtrace->reporter_cbs)
        trace_destroy_callback_set(libtrace->reporter_cbs);

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

DLLEXPORT void trace_destroy_dead(libtrace_t *libtrace)
{
    if (!libtrace) {
        fprintf(stderr, "NULL trace passed to trace_destroy_dead()\n");
        return;
    }

    ASSERT_RET(pthread_mutex_destroy(&libtrace->libtrace_lock), == 0);
    ASSERT_RET(pthread_mutex_destroy(&libtrace->read_packet_lock), == 0);
    ASSERT_RET(pthread_cond_destroy(&libtrace->perpkt_cond), == 0);

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
    if (!libtrace) {
        fprintf(stderr, "NULL trace passed to trace_destroy_output()\n");
        return;
    }
    if (libtrace->format && libtrace->format->fin_output)
        libtrace->format->fin_output(libtrace);
    if (libtrace->uridata)
        free(libtrace->uridata);
    free(libtrace);
}

DLLEXPORT int trace_flush_output(libtrace_out_t *libtrace)
{
    if (!libtrace) {
        fprintf(stderr, "NULL trace passed to trace_flush_output()\n");
        return TRACE_ERR_NULL_TRACE;
    }
    if (libtrace->format && libtrace->format->flush_output) {
        return libtrace->format->flush_output(libtrace);
    }

    return 0;
}

DLLEXPORT libtrace_packet_t *trace_create_packet(void)
{
    libtrace_packet_t *packet =
        (libtrace_packet_t *)calloc((size_t)1, sizeof(libtrace_packet_t));

    if (packet == NULL)
        return NULL;

    packet->buf_control = TRACE_CTRL_PACKET;
    packet->which_trace_start = 0;
    pthread_mutex_init(&(packet->ref_lock), NULL);
    trace_clear_cache(packet);
    return packet;
}

DLLEXPORT libtrace_packet_t *trace_copy_packet(const libtrace_packet_t *packet)
{
    libtrace_packet_t *dest;

    if (packet->which_trace_start != packet->trace->startcount) {
        return NULL;
    }

    dest = (libtrace_packet_t *)calloc((size_t)1, sizeof(libtrace_packet_t));
    if (!dest) {
        printf("Out of memory constructing packet\n");
        abort();
    }
    dest->trace = packet->trace;
    dest->buffer = malloc(65536);
    if (!dest->buffer) {
        printf("Out of memory allocating buffer memory\n");
        abort();
    }
    dest->header = dest->buffer;
    dest->payload =
        (void *)((char *)dest->buffer + trace_get_framing_length(packet));
    dest->type = packet->type;
    dest->buf_control = TRACE_CTRL_PACKET;
    dest->order = packet->order;
    dest->hash = packet->hash;
    dest->error = packet->error;
    dest->which_trace_start = packet->which_trace_start;
    pthread_mutex_init(&(dest->ref_lock), NULL);
    /* Reset the cache - better to recalculate than try to convert
     * the values over to the new packet */
    trace_clear_cache(dest);
    /* Ooooh nasty memcpys! This is why we want to avoid copying packets
     * as much as possible */
    memcpy(dest->header, packet->header, trace_get_framing_length(packet));
    memcpy(dest->payload, packet->payload, trace_get_capture_length(packet));

    return dest;
}

/** Destroy a packet object
 */
DLLEXPORT void trace_destroy_packet(libtrace_packet_t *packet)
{
    /* Free any resources possibly associated with the packet */
    if (libtrace_parallel && packet->trace &&
        packet->trace->format->fin_packet) {
        packet->trace->format->fin_packet(packet);
    }
    if (!libtrace_parallel && packet->trace &&
        packet->trace->last_packet == packet) {
        packet->trace->last_packet = NULL;
    }

    if (packet->buf_control == TRACE_CTRL_PACKET && packet->buffer) {
        free(packet->buffer);
    }
    pthread_mutex_destroy(&(packet->ref_lock));
    packet->buf_control = (buf_control_t)'\0';
    /* A "bad" value to force an assert
     * if this packet is ever reused
     */
    free(packet);
}

/**
 * Removes any possible data stored againt the trace and releases any data.
 * This will not destroy a reusable good malloc'd buffer (TRACE_CTRL_PACKET)
 * use trace_destroy_packet() for those diabolical purposes.
 */
void trace_fin_packet(libtrace_packet_t *packet)
{
    if (packet) {
        if (packet->trace && packet->trace->format->fin_packet) {
            packet->trace->format->fin_packet(packet);
        }

        if (packet->srcbucket && packet->internalid != 0) {
            libtrace_bucket_t *b = (libtrace_bucket_t *)packet->srcbucket;
            libtrace_release_bucket_id(b, packet->internalid);
        }

        if (packet->trace) {
            if (!libtrace_parallel && packet->trace->last_packet == packet) {
                packet->trace->last_packet = NULL;
            }
        }

        // No matter what we remove the header and link pointers
        packet->trace = NULL;
        packet->header = NULL;
        packet->payload = NULL;

        if (packet->buf_control != TRACE_CTRL_PACKET) {
            packet->buffer = NULL;
        }

        trace_clear_cache(packet);
        packet->hash = 0;
        packet->order = 0;
        packet->srcbucket = NULL;
        packet->fmtdata = NULL;
    }
}

/* Read one packet from the trace into buffer. Note that this function will
 * block until a packet is read (or EOF is reached).
 *
 * @param libtrace	the libtrace opaque pointer
 * @param packet	the packet opaque pointer
 * @returns 0 on EOF, negative value on error
 *
 */
DLLEXPORT int trace_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet)
{

    if (!libtrace) {
        fprintf(stderr, "NULL trace passed to trace_read_packet()\n");
        return TRACE_ERR_NULL_TRACE;
    }

    if (trace_is_err(libtrace))
        return -1;

    if (!libtrace->started) {
        trace_set_err(libtrace, TRACE_ERR_BAD_STATE,
                      "You must call trace_start() before trace_read_packet()");
        return -1;
    }

    if (!packet) {
        trace_set_err(libtrace, TRACE_ERR_NULL_PACKET,
                      "NULL packet passed into trace_read_packet()");
        return -1;
    }

    if (!(packet->buf_control == TRACE_CTRL_PACKET ||
          packet->buf_control == TRACE_CTRL_EXTERNAL)) {
        trace_set_err(libtrace, TRACE_ERR_BAD_STATE,
                      "Packet passed to trace_read_packet() is invalid");
        return -1;
    }

    if (libtrace->format->read_packet) {
        /* Finalise the packet, freeing any resources the format module
         * may have allocated it and zeroing all data associated with
         * it.
         */
        if (packet->trace == libtrace) {
            trace_fin_packet(packet);
        }
        do {
            size_t ret;
            int filtret;
            if ((ret = is_halted(libtrace)) != (size_t)-1)
                return ret;
            /* Store the trace we are reading from into the packet
             * opaque structure */
            packet->trace = libtrace;
            packet->which_trace_start = libtrace->startcount;
            ret = libtrace->format->read_packet(libtrace, packet);
            if (ret == (size_t)READ_MESSAGE) {
                continue;
            }
            if (ret == (size_t)-1 || ret == 0) {
                packet->trace = NULL;
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
                    trace_fin_packet(packet);
                    continue;
                }
            }
            if (libtrace->snaplen > 0) {
                /* Snap the packet */
                trace_set_capture_length(packet, libtrace->snaplen);
            }
            if (!IS_LIBTRACE_META_PACKET(packet)) {
                ++libtrace->accepted_packets;
            }
            if (packet->order == 0) {
                trace_packet_set_order(packet, libtrace->sequence_number);
            }
            ++libtrace->sequence_number;
            if (!libtrace_parallel && packet->trace == libtrace)
                libtrace->last_packet = packet;

            return ret;
        } while (1);
    }
    trace_set_err(libtrace, TRACE_ERR_UNSUPPORTED,
                  "This format does not support reading packets\n");
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
                         void *buffer, libtrace_rt_types_t rt_type,
                         uint32_t flags)
{

    if (!trace) {
        fprintf(stderr, "NULL trace passed into trace_prepare_packet()\n");
        return TRACE_ERR_NULL_TRACE;
    }

    if (!packet) {
        trace_set_err(trace, TRACE_ERR_NULL_TRACE,
                      "NULL packet passed into trace_prepare_packet()");
        return -1;
    }

    if (!buffer) {
        trace_set_err(trace, TRACE_ERR_NULL_BUFFER,
                      "NULL buffer passed into trace_prepare_packet()");
        return -1;
    }

    if (!(packet->buf_control == TRACE_CTRL_PACKET ||
          packet->buf_control == TRACE_CTRL_EXTERNAL)) {
        trace_set_err(trace, TRACE_ERR_BAD_STATE,
                      "Packet passed to trace_read_packet() is invalid");
        return -1;
    }

    packet->trace = trace;
    if (!libtrace_parallel)
        trace->last_packet = packet;
    /* Clear packet cache */
    trace_clear_cache(packet);

    if (trace->format->prepare_packet) {
        return trace->format->prepare_packet(trace, packet, buffer, rt_type,
                                             flags);
    }
    trace_set_err(trace, TRACE_ERR_UNSUPPORTED,
                  "This format does not support preparing packets");
    return -1;
}

/* Writes a packet to the specified output trace
 *
 * @param libtrace	describes the output format, destination, etc.
 * @param packet	the packet to be written out
 * @returns the number of bytes written, -1 if write failed
 */
DLLEXPORT int trace_write_packet(libtrace_out_t *libtrace,
                                 libtrace_packet_t *packet)
{

    if (!libtrace) {
        fprintf(stderr, "NULL trace passed into trace_write_packet()\n");
        return TRACE_ERR_NULL_TRACE;
    }
    if (!packet) {
        trace_set_err_out(libtrace, TRACE_ERR_NULL_PACKET,
                          "NULL trace passed into trace_write_packet()");
        return -1;
    }
    /* Verify the packet is valid */
    if (!libtrace->started) {
        trace_set_err_out(libtrace, TRACE_ERR_BAD_STATE,
                          "You must call trace_start_output() before "
                          "calling trace_write_packet()");
        return -1;
    }

    /* Don't try to convert meta-packets across formats */
    if (strcmp(libtrace->format->name, packet->trace->format->name) != 0 &&
        IS_LIBTRACE_META_PACKET(packet)) {
        return 0;
    }

    if (libtrace->format->write_packet) {
        return libtrace->format->write_packet(libtrace, packet);
    }
    trace_set_err_out(libtrace, TRACE_ERR_UNSUPPORTED,
                      "This format does not support writing packets");
    return -1;
}

/* Get a pointer to the first byte of the packet payload */
DLLEXPORT void *trace_get_packet_buffer(const libtrace_packet_t *packet,
                                        libtrace_linktype_t *linktype,
                                        uint32_t *remaining)
{
    libtrace_linktype_t ltype;

    if (!packet) {
        fprintf(stderr, "NULL packet passed into trace_get_packet_buffer()\n");
        return NULL;
    }
    ltype = trace_get_link_type(packet);

    if (linktype) {
        *linktype = ltype;
    }

    if (ltype == TRACE_TYPE_CONTENT_INVALID) {
        if (remaining) {
            *remaining = 0;
        }
        return NULL;
    }

    if (remaining) {
        *remaining = trace_get_capture_length(packet);
    }
    return (void *)packet->payload;
}

/* Get a pointer to the first byte of the packet payload
 *
 * DEPRECATED - use trace_get_packet_buffer() instead */
DLLEXPORT void *trace_get_link(const libtrace_packet_t *packet)
{
    return (void *)packet->payload;
}

/* Get the current time in DAG time format
 * @param packet	a pointer to a libtrace_packet structure
 * @returns a 64 bit timestamp in DAG ERF format (upper 32 bits are the seconds
 * past 1970-01-01, the lower 32bits are partial seconds)
 */
DLLEXPORT uint64_t trace_get_erf_timestamp(const libtrace_packet_t *packet)
{
    if (packet->which_trace_start != packet->trace->startcount) {
        return (uint64_t)0;
    }

    if (packet->trace->format->get_erf_timestamp) {
        /* timestamp -> timestamp */
        return packet->trace->format->get_erf_timestamp(packet);
    } else if (packet->trace->format->get_timespec) {
        /* timespec -> timestamp */
        struct timespec ts;
        ts = packet->trace->format->get_timespec(packet);
        return ((((uint64_t)ts.tv_sec) << 32) +
                (((uint64_t)ts.tv_nsec << 32) / 1000000000));
    } else if (packet->trace->format->get_timeval) {
        /* timeval -> timestamp */
        struct timeval tv;
        tv = packet->trace->format->get_timeval(packet);
        return ((((uint64_t)tv.tv_sec) << 32) +
                (((uint64_t)tv.tv_usec << 32) / 1000000));
    } else if (packet->trace->format->get_seconds) {
        /* seconds -> timestamp */
        double seconds = packet->trace->format->get_seconds(packet);
        return (((uint64_t)seconds) << 32) +
               (uint64_t)((seconds - (uint64_t)seconds) * UINT_MAX);
    } else {
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
DLLEXPORT struct timeval trace_get_timeval(const libtrace_packet_t *packet)
{
    struct timeval tv;
    uint64_t ts = 0;

    if (packet->which_trace_start != packet->trace->startcount) {
        tv.tv_sec = -1;
        tv.tv_usec = -1;
    } else if (packet->trace->format->get_timeval) {
        /* timeval -> timeval */
        tv = packet->trace->format->get_timeval(packet);
    } else if (packet->trace->format->get_erf_timestamp) {
        /* timestamp -> timeval */
        ts = packet->trace->format->get_erf_timestamp(packet);
        tv.tv_sec = ts >> 32;
        tv.tv_usec = ((ts & 0xFFFFFFFF) * 1000000) >> 32;
        if (tv.tv_usec >= 1000000) {
            tv.tv_usec -= 1000000;
            tv.tv_sec += 1;
        }
    } else if (packet->trace->format->get_timespec) {
        struct timespec ts = packet->trace->format->get_timespec(packet);
        tv.tv_sec = ts.tv_sec;
        tv.tv_usec = ts.tv_nsec / 1000;
    } else if (packet->trace->format->get_seconds) {
        /* seconds -> timeval */
        double seconds = packet->trace->format->get_seconds(packet);
        tv.tv_sec = (uint32_t)seconds;
        tv.tv_usec = (uint32_t)(((seconds - tv.tv_sec) * 1000000) / UINT_MAX);
    } else {
        tv.tv_sec = -1;
        tv.tv_usec = -1;
    }

    return tv;
}

DLLEXPORT struct timespec trace_get_timespec(const libtrace_packet_t *packet)
{
    struct timespec ts;

    if (packet->which_trace_start != packet->trace->startcount) {
        ts.tv_sec = -1;
        ts.tv_nsec = -1;
    } else if (packet->trace->format->get_timespec) {
        return packet->trace->format->get_timespec(packet);
    } else if (packet->trace->format->get_erf_timestamp) {
        /* timestamp -> timeval */
        uint64_t erfts = packet->trace->format->get_erf_timestamp(packet);
        ts.tv_sec = erfts >> 32;
        ts.tv_nsec = ((erfts & 0xFFFFFFFF) * 1000000000) >> 32;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_nsec -= 1000000000;
            ts.tv_sec += 1;
        }
    } else if (packet->trace->format->get_timeval) {
        /* timeval -> timespec */
        struct timeval tv = packet->trace->format->get_timeval(packet);
        ts.tv_sec = tv.tv_sec;
        ts.tv_nsec = tv.tv_usec * 1000;
    } else if (packet->trace->format->get_seconds) {
        /* seconds -> timespec */
        double seconds = packet->trace->format->get_seconds(packet);
        ts.tv_sec = (uint32_t)seconds;
        ts.tv_nsec = (long)(((seconds - ts.tv_sec) * 1000000000) / UINT_MAX);
    } else {
        ts.tv_sec = -1;
        ts.tv_nsec = -1;
    }
    return ts;
}

/* Get the current time in floating point seconds
 * @param packet	a pointer to a libtrace_packet structure
 * @returns time that this packet was seen in 64bit floating point seconds
 */
DLLEXPORT double trace_get_seconds(const libtrace_packet_t *packet)
{
    double seconds = 0.0;

    if (packet->which_trace_start != packet->trace->startcount) {
        return 0.0;
    }

    if (packet->trace->format->get_seconds) {
        /* seconds->seconds */
        seconds = packet->trace->format->get_seconds(packet);
    } else if (packet->trace->format->get_erf_timestamp) {
        /* timestamp -> seconds */
        uint64_t ts = 0;
        ts = packet->trace->format->get_erf_timestamp(packet);
        seconds = (ts >> 32) + ((ts & UINT_MAX) * 1.0 / UINT_MAX);
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
    if (packet->which_trace_start != packet->trace->startcount) {
        return ~0U;
    }
    if (packet->cached.capture_length == -1) {
        if (!packet->trace->format->get_capture_length)
            return ~0U;
        /* Cast away constness because this is "just" a cache */
        ((libtrace_packet_t *)packet)->cached.capture_length =
            packet->trace->format->get_capture_length(packet);
    }

    if (!(packet->cached.capture_length < LIBTRACE_PACKET_BUFSIZE)) {
        fprintf(stderr, "Capture length is greater than the buffer "
                        "size in trace_get_capture_length()\n");
        return 0;
        /* should we be returning ~OU here? */
    }

    return packet->cached.capture_length;
}

/* Get the size of the packet as it was seen on the wire.
 * @param packet	a pointer to a libtrace_packet structure
 *
 * @returns the size of the packet as it was on the wire.
 * @note Due to the trace being a header capture, or anonymisation this may
 * not be the same as the Capture Len.
 */
DLLEXPORT size_t trace_get_wire_length(const libtrace_packet_t *packet)
{

    size_t wiresub = 0;

    if (packet->which_trace_start != packet->trace->startcount) {
        return ~0U;
    }

    if (packet->cached.wire_length != -1) {
        return packet->cached.wire_length;
    }

    if (!packet->trace->format->get_wire_length)
        return ~0U;
    ((libtrace_packet_t *)packet)->cached.wire_length =
        packet->trace->format->get_wire_length(packet);

    if (packet->type >= TRACE_RT_DATA_DLT &&
        packet->type <= TRACE_RT_DATA_DLT_END) {

        /* pcap wire lengths in libtrace include an extra four bytes
         * for the FCS (to be consistent with other formats that do
         * capture the FCS), but these bytes don't actually exist on
         * the wire. Therefore, we shouldn't get upset if our "wire"
         * length exceeds the max buffer size by four bytes or less.
         */
        if (packet->cached.wire_length >= 4) {
            wiresub = 4;
        } else {
            wiresub = packet->cached.wire_length;
        }
    } else {
        wiresub = 0;
    }

    if (!(packet->cached.wire_length - wiresub < LIBTRACE_PACKET_BUFSIZE)) {
        fprintf(stderr,
                "Wire length %zu exceeds expected maximum packet size "
                "of %d -- packet is likely corrupt.\n",
                packet->cached.wire_length - wiresub, LIBTRACE_PACKET_BUFSIZE);

        /* should we be returning ~OU here? */
        ((libtrace_packet_t *)packet)->cached.wire_length = ~0U;
    }
    return packet->cached.wire_length;
}

/* Get the length of the capture framing headers.
 * @param packet	the packet opaque pointer
 * @returns the size of the packet as it was on the wire.
 * @note this length corresponds to the difference between the size of a
 * captured packet in memory, and the captured length of the packet
 */
DLLEXPORT SIMPLE_FUNCTION size_t
trace_get_framing_length(const libtrace_packet_t *packet)
{
    if (packet->which_trace_start != packet->trace->startcount) {
        return ~0U;
    }

    if (packet->cached.framing_length >= 0) {
        return packet->cached.framing_length;
    }

    if (packet->trace->format->get_framing_length) {
        ((libtrace_packet_t *)packet)->cached.framing_length =
            packet->trace->format->get_framing_length(packet);
        return packet->cached.framing_length;
    }
    return ~0U;
}

/* Get the type of the link layer
 * @param packet	a pointer to a libtrace_packet structure
 * @returns libtrace_linktype_t
 */
DLLEXPORT libtrace_linktype_t
trace_get_link_type(const libtrace_packet_t *packet)
{

    if (packet->which_trace_start != packet->trace->startcount) {
        return TRACE_TYPE_CONTENT_INVALID;
    }

    if (packet->cached.link_type == 0) {
        if (!packet->trace->format->get_link_type)
            return TRACE_TYPE_UNKNOWN;
        ((libtrace_packet_t *)packet)->cached.link_type =
            packet->trace->format->get_link_type(packet);
    }

    return packet->cached.link_type;
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
                                          libtrace_packet_t *packet)
{
    libtrace_eventobj_t event = {TRACE_EVENT_IOWAIT, 0, 0.0, 0};

    if (!trace) {
        fprintf(stderr, "NULL trace passed into trace_event()");
        /* Return default event on error? */
        return event;
    }
    if (!packet) {
        trace_set_err(trace, TRACE_ERR_NULL_PACKET,
                      "NULL packet passed into trace_event()");
        /* Return default event on error? */
        return event;
    }

    /* Free the last packet */
    trace_fin_packet(packet);
    /* Store the trace we are reading from into the packet opaque
     * structure */
    packet->trace = trace;

    if (packet->trace->format->trace_event) {
        /* Note: incrementing accepted, filtered etc. packet
         * counters is handled by the format-specific
         * function so don't increment them here.
         */
        packet->which_trace_start = trace->startcount;
        event = packet->trace->format->trace_event(trace, packet);
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
#ifndef HAVE_BPF
    fprintf(stderr, "This version of libtrace does not have BPF support\n");
    return NULL;
#else
    struct libtrace_filter_t *filter =
        (struct libtrace_filter_t *)calloc(1, sizeof(struct libtrace_filter_t));
    filter->filter.bf_insns =
        (struct bpf_insn *)malloc(sizeof(struct bpf_insn) * bf_len);

    memcpy(filter->filter.bf_insns, bf_insns, bf_len * sizeof(struct bpf_insn));

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
DLLEXPORT libtrace_filter_t *trace_create_filter(const char *filterstring)
{
#ifdef HAVE_BPF
    libtrace_filter_t *filter =
        (libtrace_filter_t *)calloc(1, sizeof(libtrace_filter_t));
    filter->filterstring = strdup(filterstring);
    filter->jitfilter = NULL;
    filter->flag = 0;
    return filter;
#else
    fprintf(stderr,
            "This version of libtrace does not have bpf filter support\n");
    return NULL;
#endif
}

DLLEXPORT void trace_destroy_filter(libtrace_filter_t *filter)
{
#ifdef HAVE_BPF
    free(filter->filterstring);
    if (filter->flag)
        pcap_freecode(&filter->filter);
#    ifdef HAVE_LLVM
    if (filter->jitfilter)
        destroy_program(filter->jitfilter);
#    endif
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
                             const libtrace_packet_t *packet, void *linkptr,
                             libtrace_linktype_t linktype)
{
#ifdef HAVE_BPF
    /* It just so happens that the underlying libs used by pthread arn't
     * thread safe, namely lex/flex thingys, so single threaded compile
     * multi threaded running should be safe.
     */
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    if (!packet) {
        fprintf(stderr, "NULL packet passed into trace_bpf_compile()");
        return TRACE_ERR_NULL_PACKET;
    }

    if (!filter) {
        trace_set_err(packet->trace, TRACE_ERR_NULL_FILTER,
                      "Filter is NULL trace_bpf_compile()");
        return -1;
    }

    /* If this isn't a real packet, then fail */
    if (!linkptr) {
        trace_set_err(packet->trace, TRACE_ERR_BAD_FILTER,
                      "Packet has no payload");
        return -1;
    }

    if (filter->filterstring && !filter->flag) {
        pcap_t *pcap = NULL;
        if (linktype == (libtrace_linktype_t)-1) {
            trace_set_err(packet->trace, TRACE_ERR_BAD_FILTER,
                          "Packet has an unknown linktype");
            return -1;
        }
        if (libtrace_to_pcap_dlt(linktype) == TRACE_DLT_ERROR) {
            trace_set_err(packet->trace, TRACE_ERR_BAD_FILTER,
                          "Unknown pcap equivalent linktype");
            return -1;
        }
        pthread_mutex_lock(&mutex);
        /* Make sure not one bet us to this */
        if (filter->flag) {
            pthread_mutex_unlock(&mutex);
            return 0;
        }
        pcap = (pcap_t *)pcap_open_dead((int)libtrace_to_pcap_dlt(linktype),
                                        1500U);
        /* build filter */
        if (!pcap) {
            trace_set_err(packet->trace, TRACE_ERR_BAD_FILTER,
                          "Unable to open pcap_t for compiling "
                          "filters trace_bpf_compile()");
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        if (pcap_compile(pcap, &filter->filter, filter->filterstring, 1, 0)) {
            trace_set_err(packet->trace, TRACE_ERR_BAD_FILTER,
                          "Unable to compile the filter \"%s\": %s",
                          filter->filterstring, pcap_geterr(pcap));
            pcap_close(pcap);
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        pcap_close(pcap);
        filter->flag = 1;
        pthread_mutex_unlock(&mutex);
    }
    return 0;
#else
    trace_set_err(packet->trace, TRACE_ERR_OPTION_UNAVAIL,
                  "Feature unavailable");
    return -1;
#endif
}

DLLEXPORT int trace_apply_filter(libtrace_filter_t *filter,
                                 const libtrace_packet_t *packet)
{
#ifdef HAVE_BPF
    void *linkptr = 0;
    uint32_t clen = 0;
    bool free_packet_needed = false;
    int ret;
    libtrace_linktype_t linktype;
    libtrace_packet_t *packet_copy = (libtrace_packet_t *)packet;
#    ifdef HAVE_LLVM
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#    endif

    if (!packet) {
        fprintf(stderr, "NULL packet passed into trace_apply_filter()\n");
        return TRACE_ERR_NULL_PACKET;
    }
    if (!filter) {
        trace_set_err(packet->trace, TRACE_ERR_NULL_FILTER,
                      "NULL filter passed into trace_apply_filter()");
        return -1;
    }

    /* Match all non-data packets as we probably want them to pass
     * through to the caller */
    linktype = trace_get_link_type(packet);

    if (linktype == TRACE_TYPE_NONDATA || linktype == TRACE_TYPE_ERF_META ||
        linktype == TRACE_TYPE_PCAPNG_META)
        return 1;

    if (libtrace_to_pcap_dlt(linktype) == TRACE_DLT_ERROR) {

        /* If we cannot get a suitable DLT for the packet, it may
         * be because the packet is encapsulated in a link type that
         * does not correspond to a DLT. Therefore, we should try
         * popping off headers until we either can find a suitable
         * link type or we can't do any more sensible decapsulation. */

        /* Copy the packet, as we don't want to trash the one we
         * were passed in */
        packet_copy = trace_copy_packet(packet);
        if (packet_copy == NULL) {
            trace_set_err(packet->trace, TRACE_ERR_NO_CONVERSION,
                          "failed to demote packet within "
                          "trace_apply_filter()");
            return -1;
        }
        free_packet_needed = true;

        while (libtrace_to_pcap_dlt(linktype) == TRACE_DLT_ERROR) {
            if (!demote_packet(packet_copy)) {
                trace_set_err(packet->trace, TRACE_ERR_NO_CONVERSION,
                              "pcap does not support this linktype so "
                              "cannot apply BPF filters");
                if (free_packet_needed) {
                    trace_destroy_packet(packet_copy);
                }
                return -1;
            }
            linktype = trace_get_link_type(packet_copy);
        }
    }

    linkptr = trace_get_packet_buffer(packet_copy, NULL, &clen);
    if (!linkptr) {
        if (free_packet_needed) {
            trace_destroy_packet(packet_copy);
        }
        return 0;
    }

    /* We need to compile the filter now, because before we didn't know
     * what the link type was
     */
    // Note internal mutex locking used here
    if (trace_bpf_compile(filter, packet_copy, linkptr, linktype) == -1) {
        if (free_packet_needed) {
            trace_destroy_packet(packet_copy);
        }
        return -1;
    }

    /* If we're jitting, we may need to JIT the BPF code now too */
#    if HAVE_LLVM
    if (!filter->jitfilter) {
        ASSERT_RET(pthread_mutex_lock(&mutex), == 0);
        /* Again double check here like the bpf filter */
        if (!filter->jitfilter)
            /* Looking at compile_program source this appears to be
             * thread safe however if this gets called twice we will
             * leak this memory :( as such lock here anyways */
            filter->jitfilter =
                compile_program(filter->filter.bf_insns, filter->filter.bf_len);
        ASSERT_RET(pthread_mutex_unlock(&mutex), == 0);
    }
#    endif

    if (!filter->flag) {
        trace_set_err(packet->trace, TRACE_ERR_BAD_FILTER,
                      "Bad filter passed into trace_apply_filter()");
        return -1;
    }
    /* Now execute the filter */
#    if HAVE_LLVM
    ret = filter->jitfilter->bpf_run((unsigned char *)linkptr, clen);
#    else
    ret = bpf_filter(filter->filter.bf_insns, (u_char *)linkptr,
                     (unsigned int)clen, (unsigned int)clen);
#    endif

    /* If we copied the packet earlier, make sure that we free it */
    if (free_packet_needed) {
        trace_destroy_packet(packet_copy);
    }
    return ret;
#else
    fprintf(stderr,
            "This version of libtrace does not have bpf filter support\n");
    return 0;
#endif
}

/* Set the direction flag, if it has one
 * @param packet the packet opaque pointer
 * @param direction the new direction (0,1,2,3)
 * @returns a signed value containing the direction flag, or -1 if this is not
 * supported
 */
DLLEXPORT libtrace_direction_t
trace_set_direction(libtrace_packet_t *packet, libtrace_direction_t direction)
{
    if (!packet) {
        fprintf(stderr, "NULL packet passed into trace_set_direction()\n");
        return (libtrace_direction_t)~0U;
    }
    if (packet->trace->format->set_direction) {
        return packet->trace->format->set_direction(packet, direction);
    }
    return (libtrace_direction_t)~0U;
}

/* Get the direction flag, if it has one
 * @param packet a pointer to a libtrace_packet structure
 * @returns a signed value containing the direction flag, or -1 if this is not
 * supported The direction is defined as 0 for packets originating locally (ie,
 * outbound) and 1 for packets originating remotely (ie, inbound). Other values
 * are possible, which might be overloaded to mean special things for a special
 * trace.
 */
DLLEXPORT libtrace_direction_t
trace_get_direction(const libtrace_packet_t *packet)
{
    if (!packet) {
        fprintf(stderr, "NULL packet passed into trace_set_direction()\n");
        return (libtrace_direction_t)~0U;
    }
    if (packet->which_trace_start != packet->trace->startcount) {
        return (libtrace_direction_t)~0U;
    }
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
DLLEXPORT int8_t trace_get_server_port(UNUSED uint8_t protocol, uint16_t source,
                                       uint16_t dest)
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
DLLEXPORT size_t trace_set_capture_length(libtrace_packet_t *packet,
                                          size_t size)
{
    if (!packet) {
        fprintf(stderr, "NULL packet passed into trace_set_capture_length()\n");
        return ~0U;
    }

    if (packet->trace->format->set_capture_length) {
        packet->cached.capture_length =
            packet->trace->format->set_capture_length(packet, size);
        return packet->cached.capture_length;
    }

    return ~0U;
}

DLLEXPORT const char *trace_parse_uri(const char *uri, char **format)
{
    const char *uridata = 0;

    if ((uridata = strchr(uri, ':')) == NULL) {
        /* Badly formed URI - needs a : */
        return 0;
    }

    if ((unsigned)(uridata - uri) > URI_PROTO_LINE) {
        /* Badly formed URI - uri type is too long */
        return 0;
    }

    /* NOTE: this is allocated memory - it should be freed by the caller
     * once they are done with it */
    *format = xstrndup(uri, (size_t)(uridata - uri));

    /* Push uridata past the delimiter */
    uridata++;

    return uridata;
}

enum base_format_t trace_get_format(libtrace_packet_t *packet)
{
    if (!packet) {
        fprintf(stderr, "NULL packet passed into trace_get_format()\n");
        return TRACE_FORMAT_UNKNOWN;
    }

    return packet->trace->format->type;
}

DLLEXPORT libtrace_err_t trace_get_err(libtrace_t *trace)
{
    libtrace_err_t err = trace->err;
    trace->err.err_num = 0; /* "OK" */
    trace->err.problem[0] = '\0';
    return err;
}

DLLEXPORT const char *trace_get_errstr(int errnum)
{
    switch (errnum) {
    case TRACE_ERR_NOERROR:
        return "no error";
    case TRACE_ERR_BAD_FORMAT:
        return "the uri passed to trace_create() is unsupported or "
               "badly formed";
    case TRACE_ERR_INIT_FAILED:
        return "the trace failed to initialize";
    case TRACE_ERR_UNKNOWN_OPTION:
        return "unknown config option";
    case TRACE_ERR_NO_CONVERSION:
        return "output uri cannot write packets of this type";
    case TRACE_ERR_BAD_PACKET:
        return "packet is corrupt or unusable for the action required";
    case TRACE_ERR_OPTION_UNAVAIL:
        return "option unsupported by this format";
    case TRACE_ERR_UNSUPPORTED:
        return "feature is unsupported";
    case TRACE_ERR_BAD_STATE:
        return "illegal use of the api";
    case TRACE_ERR_BAD_FILTER:
        return "failed to compile a bpf filter";
    case TRACE_ERR_RT_FAILURE:
        return "rt communication breakdown";
    case TRACE_ERR_UNSUPPORTED_COMPRESS:
        return "compression format unsupported";
    case TRACE_ERR_WANDIO_FAILED:
        return "wandio has returned an error";
    case TRACE_ERR_URI_NOT_FOUND:
        return "input uri not found";
    case TRACE_ERR_URI_NULL:
        return "null passed to create trace";
    case TRACE_ERR_NULL_TRACE:
        return "null trace passed to trace_start";
    case TRACE_ERR_PAUSE_FIN:
        return "unable to finish last packet in trace_pause";
    case TRACE_ERR_NULL_PACKET:
        return "packet is null";
    case TRACE_ERR_NULL_FILTER:
        return "filter is null";
    case TRACE_ERR_NULL_BUFFER:
        return "buffer is null";
    case TRACE_ERR_STAT:
        return "trace states error";
    case TRACE_ERR_CREATE_DEADTRACE:
        return "unable to create deadtrace";
    case TRACE_ERR_BAD_LINKTYPE:
        return "bad linktype";
    case TRACE_ERR_BAD_IO:
        return "bad io for the trace";
    case TRACE_ERR_BAD_HEADER:
        return "packet has a bad capture header";
    case TRACE_ERR_SEEK_ERF:
        return "error while seeking through an erf trace";
    case TRACE_ERR_COMBINER:
        return "combiner error";
    case TRACE_ERR_PAUSE_PTHREAD:
        return "error pausing processing thread";
    case TRACE_ERR_THREAD:
        return "error with trace thread";
    case TRACE_ERR_THREAD_STATE:
        return "thread in unexpected state";
    case TRACE_ERR_CONFIG:
        return "trace configuration error";
    case TRACE_ERR_NULL:
        return "unexpected null passed";
    case TRACE_ERR_OUTPUT_FILE:
        return "error with trace output file";
    case TRACE_ERR_OUT_OF_MEMORY:
        return "out of memory";
    default:
        return "unexpected error";
    }
}

DLLEXPORT bool trace_is_err(libtrace_t *trace)
{
    return trace->err.err_num != 0;
}

/* Prints the input error status to standard error and clears the error state */
DLLEXPORT void trace_perror(libtrace_t *trace, const char *msg, ...)
{
    char buf[256];
    va_list va;
    va_start(va, msg);
    vsnprintf(buf, sizeof(buf), msg, va);
    va_end(va);
    if (trace->err.err_num) {
        if (trace->uridata) {
            fprintf(stderr, "%s(%s): %s\n", buf, trace->uridata,
                    trace->err.problem);
        } else {
            fprintf(stderr, "%s: %s\n", buf, trace->err.problem);
        }
    } else {
        if (trace->uridata) {
            fprintf(stderr, "%s(%s): No error\n", buf, trace->uridata);
        } else {
            fprintf(stderr, "%s: No error\n", buf);
        }
    }
    trace->err.err_num = 0; /* "OK" */
    trace->err.problem[0] = '\0';
}

DLLEXPORT libtrace_err_t trace_get_err_output(libtrace_out_t *trace)
{
    libtrace_err_t err = trace->err;
    trace->err.err_num = TRACE_ERR_NOERROR; /* "OK" */
    trace->err.problem[0] = '\0';
    return err;
}

DLLEXPORT bool trace_is_err_output(libtrace_out_t *trace)
{
    return trace->err.err_num != 0;
}

/* Prints the output error status to standard error and clears the error state
 */
DLLEXPORT void trace_perror_output(libtrace_out_t *trace, const char *msg, ...)
{
    char buf[256];
    va_list va;
    va_start(va, msg);
    vsnprintf(buf, sizeof(buf), msg, va);
    va_end(va);
    if (trace->err.err_num) {
        fprintf(stderr, "%s(%s): %s\n", buf,
                trace->uridata ? trace->uridata : "no uri", trace->err.problem);
    } else {
        fprintf(stderr, "%s(%s): No error\n", buf, trace->uridata);
    }
    trace->err.err_num = TRACE_ERR_NOERROR; /* "OK" */
    trace->err.problem[0] = '\0';
}

DLLEXPORT int trace_seek_erf_timestamp(libtrace_t *trace, uint64_t ts)
{
    if (trace->format->seek_erf) {
        return trace->format->seek_erf(trace, ts);
    } else {
        if (trace->format->seek_timeval) {
            struct timeval tv;
#if __BYTE_ORDER == __BIG_ENDIAN
            tv.tv_sec = ts & 0xFFFFFFFF;
            tv.tv_usec = ((ts >> 32) * 1000000) & 0xFFFFFFFF;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
            tv.tv_sec = ts >> 32;
            tv.tv_usec = ((ts & 0xFFFFFFFF) * 1000000) >> 32;
#else
#    error "What on earth are you running this on?"
#endif
            if (tv.tv_usec >= 1000000) {
                tv.tv_usec -= 1000000;
                tv.tv_sec += 1;
            }
            return trace->format->seek_timeval(trace, tv);
        }
        if (trace->format->seek_seconds) {
            double seconds = (ts >> 32) + ((ts & UINT_MAX) * 1.0 / UINT_MAX);
            return trace->format->seek_seconds(trace, seconds);
        }
        trace_set_err(trace, TRACE_ERR_OPTION_UNAVAIL, "Feature unimplemented");
        return -1;
    }
}

DLLEXPORT int trace_seek_seconds(libtrace_t *trace, double seconds)
{
    if (trace->format->seek_seconds) {
        return trace->format->seek_seconds(trace, seconds);
    } else {
        if (trace->format->seek_timeval) {
            struct timeval tv;
            tv.tv_sec = (uint32_t)seconds;
            tv.tv_usec =
                (uint32_t)(((seconds - tv.tv_sec) * 1000000) / UINT_MAX);
            return trace->format->seek_timeval(trace, tv);
        }
        if (trace->format->seek_erf) {
            uint64_t timestamp =
                ((uint64_t)((uint32_t)seconds) << 32) +
                (uint64_t)((seconds - (uint32_t)seconds) * UINT_MAX);
            return trace->format->seek_erf(trace, timestamp);
        }
        trace_set_err(trace, TRACE_ERR_OPTION_UNAVAIL, "Feature unimplemented");
        return -1;
    }
}

DLLEXPORT int trace_seek_timeval(libtrace_t *trace, struct timeval tv)
{
    if (trace->format->seek_timeval) {
        return trace->format->seek_timeval(trace, tv);
    } else {
        if (trace->format->seek_erf) {
            uint64_t timestamp =
                ((((uint64_t)tv.tv_sec) << 32) +
                 (((uint64_t)tv.tv_usec * UINT_MAX) / 1000000));
            return trace->format->seek_erf(trace, timestamp);
        }
        if (trace->format->seek_seconds) {
            double seconds = tv.tv_sec + ((tv.tv_usec * 1.0) / 1000000);
            return trace->format->seek_seconds(trace, seconds);
        }
        trace_set_err(trace, TRACE_ERR_OPTION_UNAVAIL, "Feature unimplemented");
        return -1;
    }
}

/* Converts a binary ethernet MAC address into a printable string */
DLLEXPORT char *trace_ether_ntoa(const uint8_t *addr, char *buf)
{
    static char staticbuf[18] = {
        0,
    };
    if (!buf)
        buf = staticbuf;
    snprintf(buf, (size_t)18, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1],
             addr[2], addr[3], addr[4], addr[5]);
    return buf;
}

/* Converts a printable ethernet MAC address into a binary format */
DLLEXPORT uint8_t *trace_ether_aton(const char *buf, uint8_t *addr)
{
    uint8_t *buf2 = addr;
    unsigned int tmp[6];
    static uint8_t staticaddr[6];
    if (!buf2)
        buf2 = staticaddr;
    sscanf(buf, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2], &tmp[3],
           &tmp[4], &tmp[5]);
    buf2[0] = tmp[0];
    buf2[1] = tmp[1];
    buf2[2] = tmp[2];
    buf2[3] = tmp[3];
    buf2[4] = tmp[4];
    buf2[5] = tmp[5];
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
                            libtrace_linktype_t linktype, const void *data,
                            uint16_t len)
{

    if (!packet) {
        fprintf(stderr, "NULL packet passed into trace_contruct_packet()\n");
        return;
    }
    /* Check a valid linktype was supplied */
    if (linktype == TRACE_TYPE_UNKNOWN ||
        linktype == TRACE_TYPE_CONTENT_INVALID) {
        fprintf(stderr, "Unknown or invalid linktype passed into "
                        "trace_construct_packet()\n");
        return;
    }

    size_t size;
    static libtrace_t *deadtrace = NULL;
    libtrace_pcapfile_pkt_hdr_t hdr;
#ifdef WIN32
    struct _timeb tstruct;
#else
    struct timeval tv;
#endif

    /* We need a trace to attach the constructed packet to (and it needs
     * to be PCAP) */
    if (NULL == deadtrace)
        deadtrace = trace_create_dead("pcapfile");

        /* Fill in the new PCAP header */
#ifdef WIN32
    _ftime(&tstruct);
    hdr.ts_sec = tstruct.time;
    hdr.ts_usec = tstruct.millitm * 1000;
#else
    gettimeofday(&tv, NULL);
    hdr.ts_sec = tv.tv_sec;
    hdr.ts_usec = tv.tv_usec;
#endif

    hdr.caplen = len;
    hdr.wirelen = len;

    /* Now fill in the libtrace packet itself */
    if (!deadtrace) {
        fprintf(stderr, "Unable to create dummy trace for use within "
                        "trace_construct_packet()\n");
        return;
    }
    packet->trace = deadtrace;
    size = len + sizeof(hdr);
    if (size < LIBTRACE_PACKET_BUFSIZE)
        size = LIBTRACE_PACKET_BUFSIZE;
    if (packet->buf_control == TRACE_CTRL_PACKET) {
        packet->buffer = realloc(packet->buffer, size);
    } else {
        packet->buffer = malloc(size);
    }
    packet->buf_control = TRACE_CTRL_PACKET;
    packet->header = packet->buffer;
    packet->payload = (void *)((char *)packet->buffer + sizeof(hdr));

    /* Ugh, memmove - sadly necessary, also beware that we might be
     * moving data around within this packet, so ordering is important.
     */
    if (data != NULL) {
        memmove(packet->payload, data, (size_t)len);
    } else {
        packet->payload = NULL;
    }
    memmove(packet->header, &hdr, sizeof(hdr));
    packet->type = pcap_linktype_to_rt(libtrace_to_pcap_linktype(linktype));

    trace_clear_cache(packet);
}

uint64_t trace_get_received_packets(libtrace_t *trace)
{
    uint64_t ret;

    if (!trace) {
        fprintf(stderr, "NULL trace passed to trace_get_received_packets()\n");
        /* When the number of received packets is not known we return
         * UINT64_MAX */
        return UINT64_MAX;
    }

    if (trace->format->get_received_packets) {
        if ((ret = trace->format->get_received_packets(trace)) != UINT64_MAX)
            return ret;
    } else if (trace->format->get_statistics) {
        struct libtrace_stat_t stat;
        stat.magic = LIBTRACE_STAT_MAGIC;
        trace_get_statistics(trace, &stat);
        if (stat.received_valid)
            return stat.received;
    }

    // Read the cached value taken before the trace was paused/closed
    if (trace->stats && trace->stats->received_valid)
        return trace->stats->received;
    else
        return UINT64_MAX;
}

uint64_t trace_get_filtered_packets(libtrace_t *trace)
{
    if (!trace) {
        fprintf(stderr, "NULL trace passed to trace_get_filtered_packets()\n");
        return UINT64_MAX;
    }
    int i = 0;
    uint64_t lib_filtered = trace->filtered_packets;
    for (i = 0; i < trace->perpkt_thread_count; i++) {
        lib_filtered += trace->perpkt_threads[i].filtered_packets;
    }
    if (trace->format->get_filtered_packets) {
        uint64_t trace_filtered = trace->format->get_filtered_packets(trace);
        if (trace_filtered == UINT64_MAX)
            return UINT64_MAX;
        else
            return trace_filtered + lib_filtered;
    } else if (trace->format->get_statistics) {
        struct libtrace_stat_t stat;
        stat.magic = LIBTRACE_STAT_MAGIC;
        trace_get_statistics(trace, &stat);
        if (stat.filtered_valid)
            return lib_filtered + stat.filtered;
        else
            return UINT64_MAX;
    }

    // Read the cached value taken before the trace was paused/closed
    if (trace->stats && trace->stats->filtered_valid)
        return trace->stats->filtered + lib_filtered;
    else
        return lib_filtered;
}

uint64_t trace_get_dropped_packets(libtrace_t *trace)
{
    if (!trace) {
        fprintf(stderr, "NULL trace passed into trace_get_dropped_packets()\n");
        return UINT64_MAX;
    }
    uint64_t ret;

    if (trace->format->get_dropped_packets) {
        if ((ret = trace->format->get_dropped_packets(trace)) != UINT64_MAX)
            return ret;
    } else if (trace->format->get_statistics) {
        struct libtrace_stat_t stat;
        stat.magic = LIBTRACE_STAT_MAGIC;
        trace_get_statistics(trace, &stat);
        if (stat.dropped_valid)
            return stat.dropped;
    }

    // Read the cached value taken before the trace was paused/closed
    if (trace->stats && trace->stats->dropped_valid)
        return trace->stats->dropped;
    else
        return UINT64_MAX;
}

uint64_t trace_get_accepted_packets(libtrace_t *trace)
{
    if (!trace) {
        fprintf(stderr,
                "NULL trace passed into trace_get_accepted_packets()\n");
        return UINT64_MAX;
    }
    int i = 0;
    uint64_t ret = 0;
    /* We always add to a thread's accepted count before dispatching the
     * packet to the user. However if the underlying trace is single
     * threaded it will also be increasing the global count. So if we
     * find perpkt ignore the global count.
     */
    for (i = 0; i < trace->perpkt_thread_count; i++) {
        ret += trace->perpkt_threads[i].accepted_packets;
    }
    return ret ? ret : trace->accepted_packets;
}

libtrace_stat_t *trace_get_statistics(libtrace_t *trace, libtrace_stat_t *stat)
{
    uint64_t ret = 0;
    int i;
    if (!trace) {
        fprintf(stderr, "NULL trace passed into trace_get_statistics()\n");
        return NULL;
    }
    if (stat == NULL) {
        if (trace->stats == NULL)
            trace->stats = trace_create_statistics();
        stat = trace->stats;
    }
    if (stat->magic != LIBTRACE_STAT_MAGIC) {
        trace_set_err(trace, TRACE_ERR_STAT,
                      "Use trace_create_statistics() to allocate "
                      "statistics prior to calling trace_get_statistics()");
        return NULL;
    }

    /* If the trace has paused or finished get the cached results */
    if (trace->state == STATE_PAUSED || trace->state == STATE_FINISHED ||
        trace->state == STATE_FINISHING || trace->state == STATE_JOINED) {
        if (trace->stats && trace->stats != stat)
            *stat = *trace->stats;
        return stat;
    }

    stat->reserved1 = 0;
    stat->reserved2 = 0;
#define X(x) stat->x##_valid = 0;
    LIBTRACE_STAT_FIELDS;
#undef X
    /* Both accepted and filtered are stored against in the library */

    /* We always add to a thread's accepted count before dispatching the
     * packet to the user. However if the underlying trace is single
     * threaded it will also be increasing the global count. So if we
     * find perpkt ignore the global count.
     */
    for (i = 0; i < trace->perpkt_thread_count; i++) {
        ret += trace->perpkt_threads[i].accepted_packets;
    }

    stat->accepted_valid = 1;
    stat->accepted = ret ? ret : trace->accepted_packets;

    stat->filtered_valid = 1;
    stat->filtered = trace->filtered_packets;
    for (i = 0; i < trace->perpkt_thread_count; i++) {
        stat->filtered += trace->perpkt_threads[i].filtered_packets;
    }

    if (trace->format->get_statistics) {
        trace->format->get_statistics(trace, stat);
    }
    return stat;
}

void trace_get_thread_statistics(libtrace_t *trace, libtrace_thread_t *t,
                                 libtrace_stat_t *stat)
{
    if (!trace) {
        fprintf(stderr,
                "NULL trace passed into trace_get_thread_statistics()\n");
        return;
    }
    if (!stat) {
        trace_set_err(trace, TRACE_ERR_STAT,
                      "NULL statistics structure passed into "
                      "trace_get_thread_statistics()");
        return;
    }
    if (stat->magic != LIBTRACE_STAT_MAGIC) {
        trace_set_err(trace, TRACE_ERR_STAT,
                      "Use trace_create_statistics() to "
                      "allocate statistics prior to calling "
                      "trace_get_thread_statistics()");
        return;
    }
    stat->reserved1 = 0;
    stat->reserved2 = 0;
#define X(x) stat->x##_valid = 0;
    LIBTRACE_STAT_FIELDS;
#undef X
    stat->accepted_valid = 1;
    stat->accepted = t->accepted_packets;
    stat->filtered_valid = 1;
    stat->filtered = t->filtered_packets;
    if (!trace_has_dedicated_hasher(trace) &&
        trace->format->get_thread_statistics) {
        trace->format->get_thread_statistics(trace, t, stat);
    }
}

libtrace_stat_t *trace_create_statistics(void)
{
    libtrace_stat_t *ret;
    ret = malloc(sizeof(libtrace_stat_t));
    if (ret) {
        memset(ret, 0, sizeof(libtrace_stat_t));
        ret->magic = LIBTRACE_STAT_MAGIC;
    }
    return ret;
}

void trace_clear_statistics(libtrace_stat_t *s)
{
    memset(s, 0, sizeof(libtrace_stat_t));
    s->magic = LIBTRACE_STAT_MAGIC;
}

void trace_subtract_statistics(const libtrace_stat_t *a,
                               const libtrace_stat_t *b, libtrace_stat_t *c)
{

    if (a->magic != LIBTRACE_STAT_MAGIC || b->magic != LIBTRACE_STAT_MAGIC ||
        c->magic != LIBTRACE_STAT_MAGIC) {
        fprintf(stderr, "Use trace_create_statistics() to allocate "
                        "statistics prior to "
                        "calling trace_subtract_statistics()\n");
        return;
    }

#define X(x)                                                                   \
    if (a->x##_valid && b->x##_valid) {                                        \
        c->x##_valid = 1;                                                      \
        c->x = a->x - b->x;                                                    \
    } else {                                                                   \
        c->x##_valid = 0;                                                      \
    }
    LIBTRACE_STAT_FIELDS
#undef X
}

void trace_add_statistics(const libtrace_stat_t *a, const libtrace_stat_t *b,
                          libtrace_stat_t *c)
{
    if (a->magic != LIBTRACE_STAT_MAGIC || b->magic != LIBTRACE_STAT_MAGIC ||
        c->magic != LIBTRACE_STAT_MAGIC) {
        fprintf(stderr, "Use trace_create_statistics() to allocate "
                        "statistics prior to "
                        "calling trace_add_statistics()\n");
        return;
    }

#define X(x)                                                                   \
    if (a->x##_valid && b->x##_valid) {                                        \
        c->x##_valid = 1;                                                      \
        c->x = a->x + b->x;                                                    \
    } else {                                                                   \
        c->x##_valid = 0;                                                      \
    }
    LIBTRACE_STAT_FIELDS
#undef X
}

int trace_print_statistics(const libtrace_stat_t *s, FILE *f,
                           const char *format)
{
    if (s->magic != LIBTRACE_STAT_MAGIC) {
        fprintf(stderr, "Use trace_create_statistics() to allocate "
                        "statistics prior to "
                        "calling trace_print_statistics\n");
        return TRACE_ERR_STAT;
    }
    if (format == NULL)
        format = "%s: %" PRIu64 "\n";
#define xstr(s) str(s)
#define str(s) #s
#define X(x)                                                                   \
    if (s->x##_valid) {                                                        \
        if (fprintf(f, format, xstr(x), s->x) < 0)                             \
            return -1;                                                         \
    }
    LIBTRACE_STAT_FIELDS
#undef X
    return 0;
}

inline void trace_clear_cache(libtrace_packet_t *packet)
{

    packet->cached = clearcache;
}

void trace_interrupt(void) { libtrace_halt = 1; }

void register_format(struct libtrace_format_t *f)
{
    if (f->next != NULL) {
        fprintf(stderr,
                "You cannot register a format twice in register_format()");
        return;
    }
    f->next = formats_list;
    formats_list = f;

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
#    define REQUIRE(x)                                                         \
        if (!f->x)                                                             \
        fprintf(stderr, "%s: Input format should provide " #x "\n", f->name)
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
#    undef REQUIRE
	}
	else {
#    define REQUIRE(x)                                                         \
        if (f->x)                                                              \
        fprintf(stderr, "%s: Non Input format shouldn't need " #x "\n", f->name)
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
#    undef REQUIRE
	}
	if (f->init_output) {
#    define REQUIRE(x)                                                         \
        if (!f->x)                                                             \
        fprintf(stderr, "%s: Output format should provide " #x "\n", f->name)
		REQUIRE(write_packet);
		REQUIRE(start_output);
		REQUIRE(config_output);
		REQUIRE(fin_output);
#    undef REQUIRE
	}
	else {
#    define REQUIRE(x)                                                         \
        if (f->x)                                                              \
        fprintf(stderr, "%s: Non Output format shouldn't need " #x "\n",       \
                f->name)
		REQUIRE(write_packet);
		REQUIRE(start_output);
		REQUIRE(config_output);
		REQUIRE(fin_output);
#    undef REQUIRE
	}
#endif
}
