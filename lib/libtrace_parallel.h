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


/** @file
 *
 * @brief Header file containing definitions for structures and functions
 * related to the parallel framework
 *
 * @author Richard Sanger
 *
 * @version 4.0.0
 *
 * The parallel libtrace framework is a replacement to the libtrace framework
 * that allows packet processing workload to be spread over multiple threads.
 * It can also take advantage of native parallelism in the packet capture
 * source.
 */

#ifndef LIBTRACE_PARALLEL_H
#define LIBTRACE_PARALLEL_H

#include "libtrace.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct libtrace_result_t libtrace_result_t;

/**
 * A collection of types for convenience used in place of a
 * simple void* to allow any type of data to be stored and passed
 * around easily.
 *
 * This is expected to be 8 bytes in length.
 */
typedef union {
	/* Pointers */
	void *ptr;
	libtrace_packet_t *pkt;
	libtrace_result_t *res;

	/* C99 Integer types */
	/* NOTE: Standard doesn't require 64-bit
	 * but x32 and x64 gcc does */
	int64_t sint64;
	uint64_t uint64;

	uint32_t uint32s[2];
	int32_t sint32s[2];
	uint32_t uint32;
	int32_t sint32;

	uint16_t uint16s[4];
	int16_t sint16s[4];
	uint16_t uint16;
	int16_t sint16;

	uint8_t uint8s[8];
	int8_t sint8s[8];
	uint8_t uint8;
	int8_t sint8;

	size_t size;

	/* C basic types - we cannot be certain of the size */
	int sint;
	unsigned int uint;

	signed char schars[8];
	unsigned char uchars[8];
	signed char schar;
	unsigned char uchar;

	/* Real numbers */
	float rfloat;
	double rdouble;
} libtrace_generic_t;
ct_assert(sizeof(libtrace_generic_t) == 8);

/**
 * Structure describing a message that can be sent to a libtrace thread.
 */
typedef struct libtrace_message_t {
	int code; /**< The message code, as defined in enum libtrace_messages */
	libtrace_generic_t data; /**< Additional data related to the message */
	libtrace_thread_t *sender; /**< The thread that sent the message */
} libtrace_message_t;

/** Structure holding information about a result */
struct libtrace_result_t {
	uint64_t key;   /**< The unique key for the result */
	libtrace_generic_t value;  /**< The result value itself */
	int type; /**< Describes the type of result, see enum result_types */
};

/** The libtrace_messages enum
 * All libtrace messages are defined and documented here.
 *
 * Some messages can be sent to control the internal behaviour of the library
 * while others are used to trigger the user-defined callback functions.
 * If a user wishes to send their own custom messages, they should use
 * numbers greater than MESSAGE_USER (1000).
 *
 * @note Some messages are for internal use only
 */
enum libtrace_messages {
	/** A libtrace packet is ready, this will trigger the packet callback
         *  for the processing threads.
	 */
	MESSAGE_PACKET,

	/** A libtrace meta packet is ready, this will trigger the meta packet
         *  callback for the processing threads.
         */
	MESSAGE_META_PACKET,

        /** A libtrace result is ready, this will trigger the result callback
         *  for the reporter thread.
	 */
	MESSAGE_RESULT,

	/** This message is sent to each thread when it first starts and will
         *  trigger the starting callback for the processing and reporter
         *  threads. A starting message is sent when trace_pstart is called
         *  for the first time on a trace.
	 */
	MESSAGE_STARTING,

	/** This message is sent to each thread when the thread ends and will
         *  trigger the stopping callback for the processing and reporter
         *  threads.
	 */
	MESSAGE_STOPPING,

        /** This message is sent to each thread when the thread transitions
         *  from a paused state to a running state. It will trigger the
         *  resuming callback for the processing and reporter threads.
         *
         *  A resuming message is sent whenever trace_pstart is called on a
         *  trace (including the first time the trace is started).
         */
	MESSAGE_RESUMING,

        /** This message is sent to each thread when the thread transitions
         *  into a paused state from a running state. It will trigger the
         *  pausing callback for the processing and reporter threads.
         *
         *  A pausing message is sent whenever trace_ppause is called on a
         *  trace. It will also be sent when a trace is stopped, as all traces
         *  are implicitly paused before they stop.
         */
	MESSAGE_PAUSING,

	/** An internal message for forcing another thread to pause. Do not
         *  use this in user-defined callbacks!
         */
	MESSAGE_DO_PAUSE,

	/** An internal message for forcing another thread to stop. Do not
         *  use this in user-defined callbacks!
         */
	MESSAGE_DO_STOP,

        /** This message is sent to each processing thread as soon as the first
         *  packet has been seen by any of the processing threads. This will
         *  trigger the first_packet callback for the processing threads,
         *  allowing the threads to perform any initialisation required based
         *  on the properties of the first packet (e.g. the timestamp).
         *
         *  Threads should use trace_get_first_packet() to access the packet
         *  that triggered this message.
         *
         *  @note Upon pausing and restarting a trace, this message will be
         *  sent again when the first new packet is encountered.
         */
	MESSAGE_FIRST_PACKET,

        /** An internal message for notifying the reporter thread that more
         *  results are available.
         *
         *  Do not use this in user-defined callbacks -- call
         *  trace_post_reporter() instead.
	 */
	MESSAGE_POST_REPORTER,

	/** Sent to per-packet threads periodically after the configured time
	 * interval has passed.
	 *
	 * This is sent out-of-band with respect to packets and as a result
	 * can appear after a packet with an later time-stamp, or before one
	 * with an earlier time-stamp.
	 *
	 * @param data data.uint64 holds the system time-stamp in the
	 * erf format
	 * @param sender should be ignored
	 */

        /** This message is sent to the processing threads periodically, after
         *  the configured time interval has passed. This message will
         *  trigger the tick_interval callback function for the processing
         *  threads.
         *
         *  This message is sent out-of-band relative to packet messages and
         *  therefore can appear after a packet with a later timestamp or
         *  before a packet with an earlier timestamp.
         */
	MESSAGE_TICK_INTERVAL,

	/** Sent to per-packet threads once the configured number of packets
	 * are read from a trace.
	 *
	 * This are sent in-band with respect to packets such that all
	 * threads will see it between the same packets.
	 *
	 * @param data data.uint64 holds the number of packets seen so far across all threads
	 * @param sender Set to the current per-packet thread
	 */
        /** This message is sent to the processing threads periodically, after
         *  the configured number of packets have been read from the input
         *  trace. This message will trigger the tick_count callback function
         *  for the processing threads.
         *
         *  This message is sent in-band relative to packet messages and
         *  will always appear in the right place relative to the other packets
         *  observed by the thread.
         */
	MESSAGE_TICK_COUNT,

	/** All message codes at or above this value represent custom
         *  user-defined messages and will trigger the usermessage callback
         *  for the processing threads.
         */
	MESSAGE_USER = 1000
};

/** The hasher types that are available to libtrace applications.
 *  These can be selected using trace_set_hasher().
 */
enum hasher_types {
	/** Balance load across per-packet threads as best as possible, i.e
         *  the program does not care which thread sees a given packet. This
	 *  will be implemented using a hash or round robin, depending on the
         *  format and libtrace configuration.
	 */
	HASHER_BALANCE,

	/** Use a hash which is bi-directional for TCP and UDP flows, such that
	 * packets with the same 5-tuple are sent to the same processing thread.
	 * All non TCP/UDP packets will be sent to the same thread.
	 *
	 * @note it is possible that UDP packets may not be spread across
	 * processing threads, depending upon the format support. In this case
	 * they would be directed to a single thread.
	 */
	HASHER_BIDIRECTIONAL,

	/** Use a hash which is uni-directional across TCP and UDP flows, such
	 * that the opposing directions of the same 5-tuple may end up on
	 * different processing threads.
	 * Otherwise this is identical to HASHER_BIDIRECTIONAL.
	 */
	HASHER_UNIDIRECTIONAL,

	/**
	 * This value indicates that the hasher is a custom user-defined
         * function. 
	 */
	HASHER_CUSTOM
};

typedef struct libtrace_info_t {
	/**
	 * True if a live format (i.e. packets have to be trace-time).
	 * Otherwise false, indicating packets can be read as fast
	 * as possible from the format.
	 */
	bool live;

	/**
	 * The maximum number of threads supported by a parallel trace. 1
	 * if parallel support is not native (in this case libtrace will 
         * simulate an unlimited number of threads), -1 means unlimited and 0
         * unknown.
	 */
	int max_threads;

	/* TODO hash fn supported list */

	/* TODO consider time/clock details?? */
} libtrace_info_t;

typedef struct libtrace_combine libtrace_combine_t;
/**
 * The methods we use to combine the results from multiple processing
 * threads into a single output. Users can write their own combiners, but
 * we strongly recommend that you use one of the provided combiners.
 *
 */
struct libtrace_combine {

	/**
	 * Called at the start of the trace to allow data-structures
	 * to be initialised and allow functions to be swapped if appropriate.
	 *
	 * Also factors such as whether the trace is live or not can
	 * be used to determine the functions used.
	 * @return 0 if successful, -1 if an error occurs
	 */
	int (*initialise)(libtrace_t *,libtrace_combine_t *);

	/**
	 * Called when the trace ends, clean up any memory allocated
	 * by the initialise function.
	 */
	void (*destroy)(libtrace_t *, libtrace_combine_t *);

	/**
         * Receive a result from a processing thread. Most implementations
         * of this function will push the result into an appropriate
         * queue. If this is NULL, the result will automatically be pushed
         * to the reporter thread.
	 */
	void (*publish)(libtrace_t *, int thread_id, libtrace_combine_t *, libtrace_result_t *);

	/**
	 * Read as many results as possible from the trace. Each result
         * that is read should cause a MESSAGE_RESULT to be sent to the
         * reporter thread.
	 *
	 * THIS SHOULD BE NON-BLOCKING AND READ AS MANY AS POSSIBLE!
	 * If publish is NULL, this probably should be NULL as it will not be
         * called in that case.
	 */
	void (*read)(libtrace_t *, libtrace_combine_t *);

	/**
	 * Called when the trace is finished to flush the final
	 * results to the reporter thread. Any leftover results should
         * cause a MESSAGE_RESULT to be sent to the reporter thread.
	 *
	 * There may be no results, in which case this function should
	 * just return.
	 *
	 * Libtrace state:
	 * This function will be called from the reporter thread.
	 * No processing threads will be running, i.e. you can assume that
         * publish will not be called again.
	 *
	 * If publish is NULL, this probably should be NULL as it will not be
         * called in that case.
	 */
	void (*read_final)(libtrace_t *, libtrace_combine_t *);

	/**
	 * Pause must make sure any queued results that contain packets are
         * safe. See libtrace_make_result_safe() for more details on what it
         * means for a result to be safe.
	 * This function should be NULL if publish is NULL.
	 */
	void (*pause)(libtrace_t *, libtrace_combine_t *);

	/**
	 * Data storage for all the combiner threads
	 */
	void *queues;

        /** The last counter tick that we saw, so we can avoid duplicating
         *  any ticks that are published.
         */
        uint64_t last_count_tick;

        /** The last timestamp tick that we saw, so we can avoid duplicating
         *  any ticks that are published.
         */
        uint64_t last_ts_tick;

	/**
	 * Configuration options, what this does is up to the combiner
	 * chosen.
	 */
	libtrace_generic_t configuration;
};

/**
 * The definition for a hasher function, allowing matching packets to be
 * directed to the correct thread for processing.
 *
 * @param packet The packet to be hashed.
 * @param data A void pointer which can contain additional information,
 * such as configuration for the hasher function.
 *
 * @return The id of the thread that should receive this packet.
 */
typedef uint64_t (*fn_hasher)(const libtrace_packet_t* packet, void *data);


/** Start or restart an input trace in the parallel libtrace framework.
 *
 * @param libtrace The input trace to start
 * @param global_blob Global data related to this trace. This may be NULL if
 *    no global data is required.
 * @param per_packet_cbs A set of user supplied functions to be called in
 *   response to messages that are observed by the processing threads.
 * @param reporter_cbs A set of user supplied functions to be called in
 *   response to messages being seen by the reporter thread.
 * Optional if NULL, the reporter thread will not be started.
 * @return 0 on success, otherwise -1 to indicate an error has occurred
 *
 * This can also be used to restart an existing parallel trace,
 * that has previously been paused using trace_ppause().
 * In this case global_blob, per_packet_cbs and reporter_cbs will only be
 * updated if they are non-null. Otherwise their previous values will be
 * maintained.
 *
 */
DLLEXPORT int trace_pstart(libtrace_t *libtrace, void* global_blob,
                           libtrace_callback_set_t *per_packet_cbs,
                           libtrace_callback_set_t *reporter_cbs);

/**
 * The starting callback for a processing or reporting thread. Use this
 * callback to allocate and initialise any thread-local storage that you
 * would like to be available in other callbacks.
 *
 * @param libtrace The parallel trace.
 * @param t The thread that has just started.
 * @param global The global storage for the trace.
 *
 * @return The returned value is stored against the thread's local storage.
 *         This is typically passed as the 'tls' argument to other callbacks.
 */
typedef void* (*fn_cb_starting)(libtrace_t *libtrace,
                                     libtrace_thread_t *t,
                                     void *global);

/**
 * A callback function for any message that does not require any specific
 * data, e.g. stopping, pausing, or resuming callbacks.
 *
 * @param libtrace The parallel trace.
 * @param t The thread that is running.
 * @param global The global storage.
 * @param tls The thread local storage.
 */
typedef void (*fn_cb_dataless)(libtrace_t *libtrace,
                                    libtrace_thread_t *t,
                                    void *global,
                                    void *tls);

/**
 * A callback function for a first packet message seen by a processing thread.
 * @param libtrace The parallel trace.
 * @param t The thread that is running.
 * @param global The global storage.
 * @param tls The thread local storage.
 * @param sender The thread that saw the first packet.
 */
typedef void (*fn_cb_first_packet)(libtrace_t *libtrace,
                                   libtrace_thread_t *t,
                                   void *global,
                                   void *tls,
                                   libtrace_thread_t *sender);

/**
 * A callback function for handling a tick message within a processing thread.
 *
 * @param libtrace The parallel trace.
 * @param t The thread that is running.
 * @param global The global storage.
 * @param tls The thread local storage.
 * @param uint64_t The value of the tick; either a timestamp or packet count
 *    depending on the type of tick.
 */
typedef void (*fn_cb_tick)(libtrace_t *libtrace,
                           libtrace_thread_t *t,
                           void *global,
                           void *tls,
                           uint64_t order);

/**
 * A callback function triggered when a processing thread receives a packet.
 *
 * @param libtrace The parallel trace.
 * @param t The thread that is running
 * @param global The global storage.
 * @param tls The thread local storage.
 * @param packet The packet to be processed.
 *
 * @return either the packet itself if it is not being published as a result
 *   or NULL otherwise. If returning NULL, it is the user's responsibility
 *   to ensure the packet is freed when the reporter thread is finished with it.
 */
typedef libtrace_packet_t* (*fn_cb_packet)(libtrace_t *libtrace,
                                           libtrace_thread_t *t,
                                           void *global,
                                           void *tls,
                                           libtrace_packet_t *packet);

/**
 * A callback function triggered when a processing thread receives a meta packet.
 *
 * @param libtrace The parallel trace.
 * @param t The thread that is running
 * @param global The global storage.
 * @param tls The thread local storage.
 * @param packet The packet to be processed.
 *
 * @return either the packet itself if it is not being published as a result
 *   or NULL otherwise. If returning NULL, it is the user's responsibility
 *   to ensure the packet is freed when the reporter thread is finished with it.
 */
typedef libtrace_packet_t* (*fn_cb_meta_packet)(libtrace_t *libtrace,
                                           libtrace_thread_t *t,
                                           void *global,
                                           void *tls,
                                           libtrace_packet_t *packet);

/**
 * Callback for handling a result message. Should only be required by the
 * reporter thread.
 *
 * @param libtrace The parallel trace.
 * @param sender The thread that generated this result.
 * @param global The global storage.
 * @param tls The thread local storage.
 * @param result The result associated with the message.
 *
 */
typedef void (*fn_cb_result)(libtrace_t *libtrace, libtrace_thread_t *sender,
                void *global, void *tls, libtrace_result_t *result);


/**
 * Callback for handling any user-defined message types. This will handle
 * any messages with a type >= MESSAGE_USER.
 *
 * @param libtrace The parallel trace.
 * @param t The thread.
 * @param global The global storage.
 * @param tls The thread local storage.
 * @param mesg The code identifying the message type.
 * @param data The data associated with the message.
 *
 */
typedef void (*fn_cb_usermessage) (libtrace_t *libtrace, libtrace_thread_t *t,
                void *global, void *tls, int mesg, libtrace_generic_t data,
                libtrace_thread_t *sender);


/**
 * Registers a starting callback against a callback set.
 *
 * @param cbset The callback set.
 * @param handler The starting callback function.
 * @return 0 if successful, -1 otherwise.
 */
DLLEXPORT int trace_set_starting_cb(libtrace_callback_set_t *cbset,
                fn_cb_starting handler);

/**
 * Registers a stopping callback against a callback set.
 *
 * @param cbset The callback set.
 * @param handler The stopping callback function.
 * @return 0 if successful, -1 otherwise.
 */
DLLEXPORT int trace_set_stopping_cb(libtrace_callback_set_t *cbset,
                fn_cb_dataless handler);

/**
 * Registers a resuming callback against a callback set.
 *
 * @param cbset The callback set.
 * @param handler The resuming callback function.
 * @return 0 if successful, -1 otherwise.
 */
DLLEXPORT int trace_set_resuming_cb(libtrace_callback_set_t *cbset,
                fn_cb_dataless handler);

/**
 * Registers a pausing callback against a callback set.
 *
 * @param cbset The callback set.
 * @param handler The pausing callback function.
 * @return 0 if successful, -1 otherwise.
 */
DLLEXPORT int trace_set_pausing_cb(libtrace_callback_set_t *cbset,
                fn_cb_dataless handler);

/**
 * Registers a packet callback against a callback set.
 *
 * @param cbset The callback set.
 * @param handler The packet callback function.
 * @return 0 if successful, -1 otherwise.
 */
DLLEXPORT int trace_set_packet_cb(libtrace_callback_set_t *cbset,
                fn_cb_packet handler);

/**
 * Registers a meta packet callback against a callback set.
 *
 * @param cbset The callback set.
 * @param handler The meta packet callback funtion.
 * @return 0 if successful, -1 otherwise.
 */
DLLEXPORT int trace_set_meta_packet_cb(libtrace_callback_set_t *cbset,
                fn_cb_meta_packet handler);

/**
 * Registers a first packet callback against a callback set.
 *
 * @param cbset The callback set.
 * @param handler The first packet callback function.
 * @return 0 if successful, -1 otherwise.
 */
DLLEXPORT int trace_set_first_packet_cb(libtrace_callback_set_t *cbset,
                fn_cb_first_packet handler);

/**
 * Registers a result callback against a callback set.
 *
 * @param cbset The callback set.
 * @param handler The result callback function.
 * @return 0 if successful, -1 otherwise.
 */
DLLEXPORT int trace_set_result_cb(libtrace_callback_set_t *cbset,
                fn_cb_result handler);

/**
 * Registers a tick counter callback against a callback set.
 *
 * @param cbset The callback set.
 * @param handler The tick callback function.
 * @return 0 if successful, -1 otherwise.
 */
DLLEXPORT int trace_set_tick_count_cb(libtrace_callback_set_t *cbset,
                fn_cb_tick handler);

/**
 * Registers a tick interval callback against a callback set.
 *
 * @param cbset The callback set.
 * @param handler The tick callback function.
 * @return 0 if successful, -1 otherwise.
 */
DLLEXPORT int trace_set_tick_interval_cb(libtrace_callback_set_t *cbset,
                fn_cb_tick handler);

/**
 * Registers a callback for custom user messages against a callback set.
 *
 * @param cbset The callback set.
 * @param handler The user message callback function.
 * @return 0 if successful, -1 otherwise.
 */
DLLEXPORT int trace_set_user_message_cb(libtrace_callback_set_t *cbset,
                fn_cb_usermessage handler);

/** Create a callback set that can be used to define callbacks for parallel
  * libtrace threads.
  *
  * @return A pointer to a freshly allocated callback set.
  */
DLLEXPORT libtrace_callback_set_t *trace_create_callback_set(void);

/** Destroys a callback set, freeing up any resources it was using.
 *
 * @param cbset         The callback set to be destroyed.
 */
DLLEXPORT void trace_destroy_callback_set(libtrace_callback_set_t *cbset);


/** Pauses a trace previously started with trace_pstart()
 *
 * @param libtrace The parallel trace to be paused
 * @return 0 on success, otherwise -1 to indicate an error has occurred
 *
 */
DLLEXPORT int trace_ppause(libtrace_t *libtrace);

/** Stops a parallel trace, causing all threads to exit as if an EOF
 * has occurred. This replaces trace_interrupt(), allowing
 * a specified trace to be stopped.
 *
 * @param libtrace The parallel trace to be stopped
 * @return 0 on success, otherwise -1 to indicate an error has occurred
 *
 * Ideally, this should only be called by the main thread (i.e. from a signal
 * handler) but it can be called from within a reporter thread reasonably
 * safely.
 *
 */
DLLEXPORT int trace_pstop(libtrace_t *libtrace);

/** Waits for a trace to finish and all threads to join.
 *
 * @param trace The parallel trace
 *
 * Waits for a trace to finish, whether this be due to
 * an error occurring, an EOF or trace_pstop.
 *
 */
DLLEXPORT void trace_join(libtrace_t * trace);


/**
 * @name Parallel Configuration
 *
 * These methods provide a way to configure the parallel libtrace library.
 *
 * Many of these options are typically unneeded by most applications as they
 * control tuning aspects of the library and are more useful to the
 * end user.
 *
 * To allow the end user to change this configuration libtrace will search for
 * three environment variables and apply them to the configuration in the
 * following order. Such that the first has the lowest priority.
 *
 * 1. LIBTRACE_CONF, The global environment configuration
 * 2. LIBTRACE_CONF_<FORMAT>, Applied to a given format
 * 3. LIBTRACE_CONF_<FORMAT_URI>, Applied the specified trace
 *
 * E.g.
 * - int:eth0 would match LIBTRACE_CONF, LIBTRACE_CONF_INT,
 *       LIBTRACE_CONF_INT_ETH0
 * - dag:/dev/dag0,0 would match LIBTRACE_CONF, LIBTRACE_CONF_DAG,
 *       LIBTRACE_CONF_DAG__DEV_DAG0_0
 * - test.erf would match LIBTRACE_CONF, LIBTRACE_CONF_ERF,
 *       LIBTRACE_CONF_ERF_TEST_ERF
 *
 * @note All environment variables names MUST only contain
 * [A-Z], [0-9] and [_] (underscore). Any characters
 * outside of this range should be capitalised if possible or replaced with an
 * underscore.
 * @{
 */

/** Set the maximum number of perpkt threads to use in a trace.
 *
 * Only valid on a new trace, that has not be started. Once started
 * the number of threads cannot be changed without destroying the trace.
 *
 * @param[in] trace The parallel input trace
 * @param[in] nb The number of threads to use. If set to 0, libtrace will
 *    try to auto-detect how many threads it can use.
 * @return 0 if successful otherwise -1
 */
DLLEXPORT int trace_set_perpkt_threads(libtrace_t *trace, int nb);

/** Set the interval between tick messages in milliseconds.
 *
 * @param[in] trace The parallel input trace
 * @param[in] millisec The interval in milliseconds. If 0 this is disabled
 *     [default].
 * @return 0 if successful, otherwise -1.
 *
 * When enabled, MESSAGE_TICK_INTERVAL will be sent every tick interval to all
 * processing threads. This allows results to be published even in cases where
 * new packets are not being directed to a processing thread, while still
 * maintaining order etc.
 *
 * @see MESSAGE_TICK_INTERVAL, trace_set_tick_count()
 */
DLLEXPORT int trace_set_tick_interval(libtrace_t *trace, size_t millisec);

/** Set the number of packets to be read between tick messages.
 *
 * @param[in] trace The parallel input trace
 * @param[in] count The tick count.  If 0 this is disabled [default].
 * @return 0 if successful otherwise -1
 *
 * When enabled, MESSAGE_TICK_COUNT will be sent to all processing threads
 * after every 'count' packets have been read from the trace. This allows
 * results to be published even in cases where new packets are not being
 * directed to a processing thread, while still maintaining order etc.
 *
 * @see MESSAGE_TICK_COUNT, trace_set_tick_interval()
 */
DLLEXPORT int trace_set_tick_count(libtrace_t *trace, size_t count);

/**
 * Delays packets so they are played back in trace-time rather than as fast
 * as possible (real-time).
 *
 * @param trace A parallel input trace
 * @param tracetime If true packets are released with time spacing that matches
 * the original trace. Otherwise packets are read as fast as possible.
 * @return 0 if successful otherwise -1
 */
DLLEXPORT int trace_set_tracetime(libtrace_t *trace, bool tracetime);

/** Sets the maximum size of the freelist used to store empty packets
 * and their memory buffers.
 *
 * @param trace A parallel input trace
 * @param size The number of empty packets to cache in memory. Set to the
 * default, 0, to autoconfigure this value.
 * @return 0 if successful otherwise -1
 *
 * Internally libtrace maintains a buffer of packet structures which
 * includes a cache per thread and a shared main pool. This option configures
 * the size of the main pool. If an application is not passing packets
 * through to the reporter thread, i.e. the packet callback always returns
 * the packet, then the main pool is not used.
 *
 * @note Setting this too low could cause performance issues or a deadlock. An
 * unblockable warning will be printed.
 *
 * @see trace_set_thread_cache_size(), trace_set_fixed_count()
 */
DLLEXPORT int trace_set_cache_size(libtrace_t *trace, size_t size);

/** This sets the maximum size of the freelist cache owned by each thread
 * used to provide faster access to empty packets than the main shared pool.
 *
 * @param trace A parallel input trace
 * @param size The number of empty packets to cache in memory. Set to the
 * default, 0, to autoconfigure this value.
 * @return 0 if successful otherwise -1
 *
 * @see trace_set_cache_size(), trace_set_fixed_count()
 */
DLLEXPORT int trace_set_thread_cache_size(libtrace_t *trace, size_t size);

/** Determines whether a trace is allowed to create additional packets
 *  beyond the cache size.
 *
 *  If set to true, libtrace will cease reading packets once the cache is used
 *  up until the other threads release some packets back to the cache.
 *
 *  If set to false (the default), libtrace will use malloc and free to create
 *  additional packets when the cache is exhausted. This will be slower than
 *  getting a packet from the cache and will eventually run the machine out
 *  of memory if packets are allocated faster than they are released.
 *
 * @param trace A parallel input trace
 * @param fixed If true the total number of packets is limited, otherwise
 * it is not. Defaults to false.
 * @return 0 if successful otherwise -1
 *
 * @see trace_set_thread_cache_size(), trace_set_cache_size()
 */
DLLEXPORT int trace_set_fixed_count(libtrace_t *trace, bool fixed);

/** The number of packets to batch together for processing internally
 * by libtrace.
 *
 * @param trace A parallel input trace
 * @param size The total number of packets to batch together. Set to the
 * default, 0, to autoconfigure this value.
 * @return 0 if successful otherwise -1
 *
 * Internally libtrace will attempt to read up to this number of packets from
 * a format at a time. Typically, values of 10 will get good performance and
 * increasing beyond that will should little difference.
 *
 * @note We still pass a single packet at a time to the packet callback
 * function.
 */
DLLEXPORT int trace_set_burst_size(libtrace_t *trace, size_t size);

/**
 * Sets the maximum size of the buffer used between the single hasher thread
 * and the packet processing thread.
 *
 * Setting this to less than recommend could cause a deadlock for an input
 * trace that manages its own packets.
 * A unblockable warning message will be printed to stderr in this case.
 */
DLLEXPORT int trace_set_hasher_queue_size(libtrace_t *trace, size_t size);

/**
 * Enables or disables polling of the hasher queue.
 *
 * If enabled, the processing threads will poll on the hasher queue, yielding
 * if no data is available.
 *
 * If disabled, the processing threads will block on a condition variable
 * if there is no data available from the hasher.
 *
 * @param trace A parallel input trace
 * @param polling If true the hasher will poll waiting for data, otherwise
 * it will use a condition variable. Defaults to false.
 *
 * We note polling is likely to waste many CPU cycles and could even decrease
 * performance.
 *
 * @return 0 if successful otherwise -1
 */
DLLEXPORT int trace_set_hasher_polling(libtrace_t *trace, bool polling);

/**
 * Enables or disables polling of the reporter result queue.
 *
 * If enabled, the reporter thread will continuously poll for results.
 * If disabled, the reporter will only check for results if it receives a
 * MESSAGE_POST_REPORTER.
 *
 * @param trace A parallel input trace
 * @param polling If true the reporter will poll waiting for data, otherwise
 * it will wait for a MESSAGE_POST_REPORTER. Defaults to false.
 * @return 0 if successful otherwise -1
 *
 * We note polling is likely to waste many CPU cycles and could even decrease
 * performance.
 *
 * @note This setting could be ignored by some reporters.
 */
DLLEXPORT int trace_set_reporter_polling(libtrace_t *trace, bool polling);

/**
 * Set the number of results that are required in the result queue before
 * a MESSAGE_POST_REPORTER is sent to the reporter so that it can read the
 * results.
 *
 * Set this to 1 to ensure if you require your results to reach the reporter
 * as soon as possible.
 *
 * @param trace A parallel input trace
 * @param thold The threshold on the number of results to enqueue before
 * notifying the reporter thread to read them.
 * @return 0 if successful otherwise -1
 *
 *
 * @note This setting is generally ignored if the reporter is polling. However,
 * some combiner functions might ignore the polling behaviour and still
 * require this to be set.
 * @see trace_publish_result(), trace_post_reporter()
 */
DLLEXPORT int trace_set_reporter_thold(libtrace_t *trace, size_t thold);

/**
 * Enable or disable debug output for parallel libtrace.

 * If enabled, libtrace will print a line to standard error for every
 * state change observed by both the trace as a whole and by each thread.
 *
 * You really shouldn't need to enable this....
 *
 * @param trace A parallel input trace
 * @param debug_state If true debug is printed. Defaults false.
 * @return 0 if successful otherwise -1.
 *
 */
DLLEXPORT int trace_set_debug_state(libtrace_t *trace, bool debug_state);

/** Set the hasher function for a parallel trace.
 *
 * @param[in] trace The parallel trace to apply the hasher to
 * @param[in] type The type of hashing to apply, see enum hasher_types
 * @param[in] hasher A hasher function to use [Optional]
 * @param[in] data Data passed to the hasher function [Optional]
 *
 * @return 0 if successful otherwise -1 on error
 *
 * The hasher function in a parallel trace can be used to control which
 * processing thread will receive each packet.
 *
 * See hasher_types for a list of hashers supported natively by libtrace.
 *
 * HASHER_BALANCE is the default and will dispatch packets as fast as possible
 * to all threads arbitrarily.
 *
 * HASHER_CUSTOM will force the libtrace to use the user defined function. In
 * this case, the hasher parameter must be supplied.
 *
 * With other defined hasher types libtrace will try to push the hashing into
 * the capture format wherever possible. In this case, the hasher parameter is
 * optional; if a hasher is provided then it will be preferred over the
 * libtrace implementation.
 *
 * @note When supplying a hasher function it should be thread-safe so it can
 * be run in parallel by libtrace. Ideally this should rely upon no state, other
 * than some form of seed value supplied in data.
 */
DLLEXPORT int trace_set_hasher(libtrace_t *trace, enum hasher_types type,
                               fn_hasher hasher, void *data);

/// @}


/** Types of results.
 *
 * Custom result types users should be defined as RESULT_USER(1000) or greater.
 *
 */
enum result_types {
	/**
	 * The result contains a pointer to a libtrace_packet_t. This
         * packet should be freed using trace_free_packet() once the result
         * is processed by the reporter thread.
         *
         * The key for a RESULT_PACKET is the packet order (see
         * trace_get_packet_order() for more about ordering).
	 *
	 */
	RESULT_PACKET,

	/**
         * The result is a tick timestamp. The key is an ERF timestamp.
	 */
	RESULT_TICK_INTERVAL,

	/**
         * The result is a tick counter. The key is the sequence number of
         * the tick, relative to the packets read so far.
	 */
	RESULT_TICK_COUNT,

	/**
         * Any user-defined result codes should be at or above this value.
	 */
	RESULT_USER = 1000

};

/** Publish a result to the reporter thread (via the combiner)
 *
 * @param[in] libtrace The parallel input trace
 * @param[in] t The current per-packet thread
 * @param[in] key The key of the result (used for sorting by the combiner)
 * @param[in] value The value of the result
 * @param[in] type The type of result (see result_types)
 */
DLLEXPORT void trace_publish_result(libtrace_t *libtrace,
                                    libtrace_thread_t *t,
                                    uint64_t key,
                                    libtrace_generic_t value,
                                    int type);

/** Check if a dedicated hasher thread is being used.
 *
 * @param[in] libtrace The parallel input trace
 * @return true if the trace has dedicated hasher thread otherwise false.
 *
 * This should only be called after the trace has been started with
 * trace_pstart().
 */
DLLEXPORT bool trace_has_dedicated_hasher(libtrace_t * libtrace);

/** Checks if a trace is using a reporter thread.
 *
 * @param[in] libtrace The parallel input trace
 * @return True if the trace is using a reporter otherwise false
 */
DLLEXPORT bool trace_has_reporter(libtrace_t * libtrace);

/** Post a message to the reporter thread requesting that it check for more
 * results.
 *
 * @param[in] The parallel input trace
 * @return -1 upon error indicating the message has not been sent otherwise a
 * backlog indicator (the number of messages the reporter has not yet read).
 */
DLLEXPORT int trace_post_reporter(libtrace_t *libtrace);

/** Check the number of messages waiting in a thread's message queue
 *
 * @param[in] libtrace The input trace
 * @param[in] t The thread to check; if NULL the current thread will be used.
 *
 * @return packets in the queue otherwise -1 upon error.
 *
 * @note For best performance it is recommended to supply the thread argument
 * even if it is the current thread.
 */
DLLEXPORT int libtrace_thread_get_message_count(libtrace_t * libtrace,
                                                libtrace_thread_t *t);

/** Read a message from a thread in a blocking fashion.
 *
 * @param[in] libtrace The input trace
 * @param[in] t The thread to check, if NULL the current thread will be used.
 * @param[out] message A pointer to a libtrace_message_t structure which will
 * be filled with the retrieved message.
 *
 * @return The number of messages remaining otherwise -1 upon error.
 *
 * @note For best performance it is recommended to supply the thread argument
 * even if it is the current thread.
 */
DLLEXPORT int libtrace_thread_get_message(libtrace_t * libtrace,
                                          libtrace_thread_t *t,
                                          libtrace_message_t * message);

/** Read a message from a thread in a non-blocking fashion.
 *
 * @param[in] libtrace The input trace
 * @param[in] t The thread to check, if NULL the current thread will be used.
 * @param[out] message A pointer to a libtrace_message_t structure which will
 * be filled with the retrieved message.
 *
 * @return 0 if successful otherwise -1 upon error or if no message were
 * available.
 *
 * @note For best performance it is recommended to supply the thread argument
 * even if it is the current thread.
 */
DLLEXPORT int libtrace_thread_try_get_message(libtrace_t * libtrace,
                                              libtrace_thread_t *t,
                                              libtrace_message_t * message);

/** Send a message to the reporter thread.
 *
 * @param[in] libtrace The parallel trace
 * @param[in] message The message to be sent. If the sender field is NULL,
 * libtrace will attempt to fill this in. It is faster to assign this if it is
 * known.
 *
 * @return -1 upon error indicating the message has not been sent. Otherwise,
 * will return the number of messages the reporter has not yet read.
 */
DLLEXPORT int trace_message_reporter(libtrace_t * libtrace,
                                     libtrace_message_t * message);

/** Send a message to all processing threads.
 *
 * @param[in] libtrace The parallel trace
 * @param[in] message The message to be sent. If the sender field is NULL,
 * libtrace will attempt to fill this in. It is faster to assign this if it is
 * known.
 *
 * @return 0 if successful. Otherwise, a negative number is returned that
 * indicates the number of processing threads that the message was not sent
 * to (i.e. -1 means one thread could not be sent the message).
 */
DLLEXPORT int trace_message_perpkts(libtrace_t * libtrace,
                                    libtrace_message_t * message);

/** Send a message to a specific thread.
 *
 * @param[in] libtrace The parallel trace
 * @param[in] t The thread to message
 * @param[in] message The message to be sent. If the sender field is NULL,
 * libtrace will attempt to fill this in. It is faster to assign this if it is
 * known.
 *
 * @return -1 upon error indicating the message has not been sent. Otherwise,
 * will return the number of messages the recipient has not yet read.
 */
DLLEXPORT int trace_message_thread(libtrace_t * libtrace,
                                   libtrace_thread_t *t,
                                   libtrace_message_t * message);

/** Checks if a parallel trace has finished reading packets.
 *
 * @return true if the trace has finished reading packets (even if all results
 * have not yet been processed). Otherwise false.
 *
 * @note This returns true even if all results have not yet been processed by
 * the reporter thread.
 */
DLLEXPORT bool trace_has_finished(libtrace_t * libtrace);


/** Check if libtrace is directly reading from multiple queues
 * from within the capture format (such as a NICs hardware queues).
 *
 * A trace is considered to be parallel if the input format for the trace
 * allows the packets to be read in a natively parallel fashion, i.e. packets
 * can be read using multiple pipelines. If this function returns false, the
 * packets are instead being read from a single input source and then
 * distributed amongst the processing threads.
 *
 * Factors that may cause this function to return false despite the format
 * normally supporting native parallel reads include: the choice of hasher
 * function, the number of threads choosen (such as 1 or more than the trace
 * supports) or another error when trying to start the parallel format.
 *
 * If called before the trace is started, i.e. before trace_pstart(), this
 * function returns an indication whether the trace has the possiblity to
 * support native parallel reads. After trace_pstart() is called this should be
 * checked again to confirm that this has happened.
 *
 * @return true if the trace is parallel or false if the library is splitting
 * the trace into multiple threads.
 */
DLLEXPORT bool trace_is_parallel(libtrace_t * libtrace);

/** Returns either the sequence number or erf timestamp of a packet.
 *
 * @param[in] packet
 * @return A 64bit sequence number or erf timestamp.
 *
 * The returned value can be used to compare the relative ordering of packets.
 * Formats that are not natively parallel will typically return a sequence
 * number. Natively parallel formats will return a timestamp.
 */
DLLEXPORT uint64_t trace_packet_get_order(libtrace_packet_t * packet);

/** Returns the hash of a packet.
 *
 * @param[in] packet
 * @return A 64-bit hash
 *
 * @note This function will only work in situations where
 * a custom hash is being used. You can use trace_has_dedicated_hasher()
 * to check if this is the case.
 */
DLLEXPORT uint64_t trace_packet_get_hash(libtrace_packet_t * packet);

/** Sets the order of a packet.
 *
 * @param[in] packet
 * @param[in] order the new order of a packet
 *
 * @note Many combiners rely on this value, so please ensure that changing this
 * conforms to the expectations of the combiner.
 *
 * Generally speaking, you probably shouldn't be changing the order of packets!
 */
DLLEXPORT void trace_packet_set_order(libtrace_packet_t * packet, uint64_t order);

/** Sets the hash of a packet.
 *
 * @param[in] packet
 * @param[in] hash the new hash
 *
 * Once a packet reaches the processing thread, the libtrace library has
 * little use for this field and as such this can essentially be used for any
 * storage that the user requires.
 */
DLLEXPORT void trace_packet_set_hash(libtrace_packet_t * packet, uint64_t hash);


/** Returns the first packet read by a processing thread since the source
 * trace was last started or restarted.
 *
 * @param[in] libtrace the parallel input trace.
 * @param[in] t Either a per packet thread or NULL to retrieve the earliest
 * packet across all per packet threads.
 * @param[out] packet A pointer to the requested packet. [Optional]
 * @param[out] tv The system time-stamp when the packet was received. [Optional]
 * @return 1 if we are confident this is the first packet. Otherwise 0 if this
 * is a best guess (this is only possible int the case t=NULL) in which case
 * we recommend trying again at a later time.
 * -1 is returned if an error occurs, such as when this function is supplied
 * an invalid thread.
 *
 * The packet and timeval returned by this function is shared by all threads
 * and remain valid until MESSAGE_PAUSING is received.
 */
DLLEXPORT int trace_get_first_packet(libtrace_t *libtrace,
                                     libtrace_thread_t *t,
                                     const libtrace_packet_t **packet,
                                     const struct timeval **tv);

/** Makes a packet safe, preventing the packet from becoming invalid after a
 * pausing a trace.
 *
 * @param[in,out] pkt The packet to make safe
 *
 * This copies a packet in such a way that it will be able to survive a pause.
 * However this will not allow the packet to be used after the format is
 * destroyed.
 */
DLLEXPORT void libtrace_make_packet_safe(libtrace_packet_t *pkt);

/** Makes a result safe, preventing the result from becoming invalid after
 * pausing a trace.
 *
 * @param[in,out] res The result to make safe.
 *
 * This ensures the internal content of a result is safe to survive a pause.
 * Note that this is only an issue if the result contains a packet.
 * See libtrace_make_packet_safe().
 */
DLLEXPORT void libtrace_make_result_safe(libtrace_result_t *res);

/** In a parallel trace, free a packet back to libtrace.
 *
 * @param[in] libtrace A parallel input trace
 * @param[in] packet The packet to be released back to libtrace
 *
 * The packet should not be used after calling this function.
 *
 * @note Don't use this inside a packet callback function -- just return
 * the packet instead, as this will be faster.
 *
 * @note All packets should be free'd before a trace is destroyed.
 */
DLLEXPORT void trace_free_packet(libtrace_t * libtrace, libtrace_packet_t * packet);

/** Increments the internal reference counter for a packet.
 * @param packet        The packet opaque pointer
 *
 * You may wish to use this function (and its decrementing counterpart)
 * in situations where you are retaining multiple references to a packet
 * outside of the core packet processing function. This will ensure that
 * the packet is not released until there are no more outstanding references
 * to the packet anywhere in your program.
 */
DLLEXPORT void trace_increment_packet_refcount(libtrace_packet_t *packet);

/** Decrements the internal reference counter for a packet.
 * @param packet        The packet opaque pointer
 *
 * If the reference counter goes below one, trace_fin_packet() will be
 * called on the packet.
 *
 * You may wish to use this function (and its incrementing counterpart)
 * in situations where you are retaining multiple references to a packet
 * outside of the core packet processing function. This will ensure that
 * the packet is not released until there are no more outstanding references
 * to the packet anywhere in your program.
 */
DLLEXPORT void trace_decrement_packet_refcount(libtrace_packet_t *packet);


/** Provides some basic information about a trace based on its input format.
 *
 * @param libtrace  The trace that is being inquired about.
 * @return a libtrace_info_t structure that contains information about the
 * trace format, i.e. is it live or not, how many threads it supports.
 *
 * See trace_is_parallel(), trace_get_perpkt_threads().
 */
DLLEXPORT libtrace_info_t *trace_get_information(libtrace_t * libtrace);

/** Sets the configuration of a trace based upon a comma separated list of
 * key value pairs.
 *
 * @param trace A parallel trace which is not running or destroyed.
 * @param str A comma separated list of key=value pairs:
 *   e.g. \em "burst_size=20,perpkt_threads=2,fixed_count=true"
 * @return 0 if successful otherwise -1. If bad options are passed we will
 * print the error to stderr but still return successful.
 *
 * List of keys:
 * * \b cache_size,\b cs see trace_set_cache_size() [size_t]
 * * \b thread_cache_size,\b tcs see trace_set_thread_cache_size() [size_t]
 * * \b fixed_count,\b fc see trace_set_fixed_count() [bool]
 * * \b burst_size,\b bs see trace_set_burst_size() [size_t]
 * * \b tick_interval,\b ti see trace_set_tick_interval() [size_t]
 * * \b tick_count,\b tc see trace_set_tick_count() [size_t]
 * * \b perpkt_threads,\b pt see trace_set_perpkt_threads() [XXX TBA XXX]
 * * \b hasher_queue_size,\b hqs see trace_set_hasher_queue_size() [size_t]
 * * \b hasher_polling,\b hp see trace_set_hasher_polling() [bool]
 * * \b reporter_polling,\b rp see trace_set_reporter_polling() [bool]
 * * \b reporter_thold,\b rt see trace_set_reporter_thold() [size_t]
 * * \b debug_state,\b ds see trace_set_debug_state() [bool]
 *
 * Booleans can be set as 0/1 or false/true.
 *
 * @note a environment variable interface is provided by default to users via
 * LIBTRACE_CONF, see Parallel Configuration for more information.
 *
 * @note This interface is provided to allow a user to quickly configure an
 * application using a single API call. A nicer programatic method for
 * configuration would be to use the appropriate trace_set_*() function for
 * each option.
 */
DLLEXPORT int trace_set_configuration(libtrace_t *trace, const char * str);

/** Sets configuration from a file. This reads every line from the file and
 * interprets each line with trace_set_configuration().
 *
 * @param trace A parallel trace which is not running or destroyed
 * @param file A file pointer which we read each line from
 * @return 0 if successful otherwise -1. If bad options are passed we will
 * print the error to stderr but still return successful.
 *
 * @note We do not close the file pointer upon completion
 */
DLLEXPORT int trace_set_configuration_file(libtrace_t *trace, FILE *file);

/** Returns the number of processing threads that have been created for
 * a given trace.
 *
 * @param t A parallel trace.
 * @return The number of processing threads owned by that trace.
 */
DLLEXPORT int trace_get_perpkt_threads(libtrace_t* t); 

/** Returns the internal unique ID for a packet processing thread.
 *
 * @param thread The thread being queried.
 * @return The ID number of the thread or -1 if the thread is not a processing
 * thread or is otherwise invalid.
 */
DLLEXPORT int trace_get_perpkt_thread_id(libtrace_thread_t *thread);

/**
 * Sets a combiner function for an input trace.
 *
 * @param trace The input trace
 * @param combiner The combiner to use
 * @param config Configuration information. Dependent upon the combiner.
 *
 * Sets a combiner against a trace, this should only be called on a
 * non-started or paused trace.  By default, combiner_unordered
 * will be used if this function is not called before starting the trace.
 */
DLLEXPORT void trace_set_combiner(libtrace_t *trace, const libtrace_combine_t *combiner, libtrace_generic_t config);

/**
 * Takes unordered (or ordered) input and produces unordered output.
 * This is the fastest combiner but makes no attempt to ensure you get
 * results in a particular order.
 */
extern const libtrace_combine_t combiner_unordered;

/**
 * Takes ordered input and produces ordered output. Each processing thread
 * must produce results that are strictly ordered for this combiner to
 * work correctly.
 *
 * For example, a thread may publish a series of results with the keys
 * (in order) of 1,4,10,11,15,20 as the keys are all in order. It must not
 * publish the results in the order 1,4,11,10,15,20 -- 10 comes after 11,
 * which is out-of-order.
 */
extern const libtrace_combine_t combiner_ordered;

/**
 * Like classic Google Map/Reduce, the results are sorted
 * in ascending order based on their key. The sorting is only done when the
 * trace finishes and all results are stored internally until then.
 *
 * This only works with a very limited number of results, otherwise
 * libtrace will just run out of memory and crash. You should always
 * use combiner_ordered if you can.
 */
extern const libtrace_combine_t combiner_sorted;

#ifdef __cplusplus
}
#endif

#endif // LIBTRACE_PARALLEL_H
