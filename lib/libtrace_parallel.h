/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton,
 * New Zealand.
 *
 * Authors: Richard Sanger
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

/** @file
 *
 * @brief Header file containing definitions for structures and functions
 * related to the parallel framework
 *
 * @author Richard Sanger
 *
 * @version $Id$
 *
 * The parallel libtrace framework is a replacement to the libtrace framework. XXX TODO MAKE MORE DOCS HERE.
 */

#ifndef LIBTRACE_PARALLEL_H
#define LIBTRACE_PARALLEL_H

#include "libtrace.h"
#include <stdio.h>

typedef struct libtrace_result_t libtrace_result_t;

/**
 * A collection of types for convenience used in place of a
 * simple void* to allow a any type of data to be stored.
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

typedef struct libtrace_message_t {
	int code; /**< The message code see enum libtrace_messages */
	libtrace_generic_t data; /**< Additional data related to the message */
	libtrace_thread_t *sender; /**< The thread that sent the message */
} libtrace_message_t;

/** Structure holding information about a result */
struct libtrace_result_t {
	uint64_t key;
	libtrace_generic_t value;
	int type;
};

/** The libtrace_messages enum
 * All libtrace messages are defined and documented here.
 *
 * Some messages can be sent to control the library while others
 * are received by the per-packet and reporter functions to inform the libtrace
 * application.
 *
 * If a user wishes to send there own custom messages they should use
 * numbers greater than MESSAGE_USER (1000).
 *
 * @note Some messages are for internal use only
 */
enum libtrace_messages {
	/** A libtrace packet is ready, this will only be sent to per
	 * packet threads.
	 * @param data Holds the packet in data.pkt. The packet belongs to
	 * libtrace and should either be returned from the per-packet function
	 * if no longer needed or free'd at some later time using the XXX
	 * function.
	 * @param sender The sender will be set as the current thread
	 */
	MESSAGE_PACKET,
	/** A libtrace result is ready, this will only be sent to the reporter
	 * thread.
	 * @param data Holds the result in data.res. The memory holding the
	 * result is allocated by libtrace and should not be free'd. However
	 * note that any data stored within the result might need to be free'd.
	 * @param sender The sender will be set as the current thread
	 */
	MESSAGE_RESULT,

	/** A message sent to each thread when it starts. This is sent
	 * to both the reporter and per-packet threads. This will be sent once
	 * after trace_pstart() (assuming no errors occurs).
	 *
	 * This can be used to allocate resources required by each thread.
	 *
	 * These can be free'd when MESSAGE_STOPPING is received.
	 *
	 * @param data unused, do not use this
	 * @param sender The sender will be set as the current thread
	 * @return When using a function callback for starting, the returned
	 * value is stored against the thread tls. Otherwise the return is ignored.
	 */
	MESSAGE_STARTING,

	/** A message sent to each thread when it stops. This is sent
	 * to both the reporter and per-packet threads. This will be sent once
	 * after MESSAGE_STARTING.
	 *
	 * This can be used to free any resources allocated with
	 * MESSAGE_STARTING.
	 *
	 * @param data unused, do not use this
	 * @param sender The sender will be set as the current thread
	 */
	MESSAGE_STOPPING,

	/** A message sent to each thread when a thread transitions between a
	 * paused (or unstarted) state to running state. This is sent
	 * to both the reporter and per-packet threads. This will be sent after
	 * MESSAGE_STARTING when a trace is first started and when a trace
	 * is started (trace_pstart()) after a pause (trace_ppause()).
	 *
	 * This can be used to allocate resources.
	 *
	 * @param data unused, do not use this
	 * @param sender The sender will be set as the current thread
	 */
	MESSAGE_RESUMING,

	/** A message sent to each thread when a thread transitions between a
	 * paused (or unstarted) state to running state. This is sent
	 * to both the reporter and per-packet threads. This will be sent after
	 * MESSAGE_STARTING when a trace is first started and when a trace
	 * is started (trace_pstart()) after a pause (trace_ppause()).
	 *
	 * This can be used to allocate resources.
	 *
	 * @param data unused, do not use this
	 * @param sender The sender will be set as the current thread
	 */
	MESSAGE_PAUSING,

	/** An internal message do not use this */
	MESSAGE_DO_PAUSE,
	/** An internal message do not use this */
	MESSAGE_DO_STOP,

	/** Sent to all per-packet threads (including the sender) and the
	 * reducer when the first packet is seen for a thread.
	 *
	 * @param data The first packet is stored in data.pkt. This packet is
	 * shared by all threads receiving the message and is valid until
	 * MESSAGE_PAUSING is received.
	 * @param sender The per-packet thread which received the packet
	 *
	 * @note Upon pausing and restarting a trace this will be reset and
	 * sent once a new packet is encountered
	 *
	 * @see trace_get_first_packet()
	 */
	MESSAGE_FIRST_PACKET,

	/** Notify the reporter thread more data is available.
	 *
	 * Triggers the reporter to read as many results as possible.
	 *
	 * @param data unused
	 * @param sender the sending
	 *
	 * @note This message should not be sent directly instead call
	 * trace_post_reporter()
	 *
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
	MESSAGE_TICK_COUNT,

	/** For specific user defined messages use codes of MESSAGE_USER or above. */
	MESSAGE_USER = 1000
};

/** The hasher types available to libtrace application.
 * These can be selected using trace_set_hasher().
 */
enum hasher_types {
	/** Balance load across per-packet threads as best as possible, this is
	 * basically to say I do not care about where packets are sent. This
	 * might still might be implemented using a hash or round robin etc.
	 * depending on the format and libtrace configuration.
	 */
	HASHER_BALANCE,

	/** Use a hash which is bi-directional for TCP and UDP flows, that is
	 * packets with the same 5-tuple are sent to the same per-packet thread.
	 * All non TCP/UDP packets will be sent to the same thread.
	 *
	 * @note it is possible that UDP packets may not be spread across
	 * per-packet threads, depending upon the format support. In this case
	 * they would be directed to a single per-packet thread.
	 */
	HASHER_BIDIRECTIONAL,

	/** Use a hash which is uni-directional across TCP and UDP flows, this
	 * means the opposing directions of the same 5-tuple might end up on
	 * different per-packet threads.
	 * Otherwise this is identical to HASHER_BIDIRECTIONAL
	 */
	HASHER_UNIDIRECTIONAL,

	/**
	 * Always use the user supplied hasher, this disables native
	 * support in and is likely significantly slower.
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
	 * if parallel support is not native (in this case libtrace will simulate
	 * an unlimited number of threads), -1 means unlimited and 0 unknown.
	 */
	int max_threads;

	/* TODO hash fn supported list */

	/* TODO consider time/clock details?? */
} libtrace_info_t;

/**
 * The methods we use to combine multiple outputs into a single output
 * This is not considered a stable API however is public.
 * Where possible use built in combiners.
 *
 * @note this structure is duplicated per trace and as such can
 * have functions rewritten, and in fact should if possible.
 */
typedef struct libtrace_combine libtrace_combine_t;
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
	 * Called when the trace ends, clean up any memory here
	 * from libtrace_t * init.
	 */
	void (*destroy)(libtrace_t *, libtrace_combine_t *);

	/**
	 * Publish a result against it's a threads queue.
	 * If null publish directly, expected to be used
	 * as a single threaded optimisation and can be
	 * set to NULL by init if this case is detected.
	 *
	 * TODO this is old info
	 */
	void (*publish)(libtrace_t *, int thread_id, libtrace_combine_t *, libtrace_result_t *);

	/**
	 * Read as many results as possible from the trace.
	 * Directly calls the users code to handle results from here.
	 *
	 * THIS SHOULD BE NON-BLOCKING AND READ AS MANY AS POSSIBLE
	 * If publish is NULL, this probably should be NULL also otherwise
	 * it will not be called.
	 */
	void (*read)(libtrace_t *, libtrace_combine_t *);

	/**
	 * Called when the trace is finished to flush the final
	 * results to the reporter thread.
	 *
	 * There may be no results, in which case this should
	 * just return.
	 *
	 * Libtrace state:
	 * Called from reporter thread
	 * No perpkt threads will be running, i.e. publish will not be
	 * called again.
	 *
	 * If publish is NULL, this probably should be NULL also otherwise
	 * it will not be called.
	 */
	void (*read_final)(libtrace_t *, libtrace_combine_t *);

	/**
	 * Pause must make sure any results of the type packet are safe.
	 * That means trace_copy_packet() and destroy the original.
	 * This also should be NULL if publish is NULL.
	 */
	void (*pause)(libtrace_t *, libtrace_combine_t *);

	/**
	 * Data storage for all the combiner threads
	 */
	void *queues;

	/**
	 * Configuration options, what this does is up to the combiner
	 * chosen.
	 */
	libtrace_generic_t configuration;
};

/**
 * The definition for the main function that the user supplies to process
 * messages.
 *
 * @param trace The trace the packet is related to.
 * @param thread The thread identifier.
 * @param mesg_code The type of data ready, the most important being MESSAGE_PACKET.
 * In this case data.pkt contains the packet.
 * @param data A generic union of types that fit into 8 bytes, containing
 * information dependent upon the mesg_code.
 * @param sender The thread from which the message originated.
 * @return If the message type is MESSAGE_PACKET a packet can be returned back
 * to the library similar to trace_free_packet() otherwise this should be NULL.
 *
 * The values of data and sender depend upon the mesg_code. Please see the
 * documentation for the message as to what value these will contain.
 */
typedef void* (*fn_cb_msg)(libtrace_t* trace,
                           libtrace_thread_t *thread,
                           int mesg_code,
                           libtrace_generic_t data,
                           libtrace_thread_t *sender);

/**
 * The definition for the main function that the user supplies to process
 * results from trace_publish_result().
 *
 * @param trace The trace the packet is related to.
 * @param mesg_code The type of data ready, the most important being MESSAGE_RESULT.
 * In this case data.res contains the result.
 * @param data A generic union of types that fit into 8 bytes, containing
 * information dependent upon the mesg_code.
 * @param sender The thread from which the message originated.
 *
 * The values of data and sender depend upon the mesg_code. Please see the
 * documentation for the message as to what value these will contain.
 */
typedef void (*fn_reporter)(libtrace_t* trace,
                            int mesg_code,
                            libtrace_generic_t data,
                            libtrace_thread_t *sender);

/**
 * The definition for a hasher function, allowing matching packets to be
 * directed to the same per packet thread for processing.
 *
 * @param packet The packet to be hashed.
 * @param data A void pointer which can contain additional information,
 * such as configuration of the hasher function.
 */
typedef uint64_t (*fn_hasher)(const libtrace_packet_t* packet, void *data);


/** Start or restart an input trace in the parallel libtrace framework.
 *
 * @param libtrace The input trace to start
 * @param global_blob Global data related to this trace accessible using trace_get_global()
 * @param per_msg A user supplied function called when a message is ready
 * @param reporter A user supplied function called when a result is ready.
 * Optional if NULL the reporter thread will not be started.
 * @return 0 on success, otherwise -1 to indicate an error has occurred
 *
 * This can also be used to restart an existing parallel trace,
 * that has previously been paused using trace_ppause().
 * In this case global_blob,per_msg and reporter will only be updated
 * if they are non-null. Otherwise their previous values will be maintained.
 *
 */
DLLEXPORT int trace_pstart(libtrace_t *libtrace, void* global_blob,
                           fn_cb_msg per_msg, fn_reporter reporter);

/**
 *
 * @param libtrace The parallel trace
 * @param t The thread that is running
 * @param global The global storage
 * @return The returned value is stored against the threads tls.
 *         This is typically passed as tls argument to other messages.
 */
typedef void* (*fn_cb_starting)(libtrace_t *libtrace,
                                     libtrace_thread_t *t,
                                     void *global);

/**
 * @param libtrace The parallel trace
 * @param t The thread that is running
 * @param global The global storage
 * @param tls The thread local storage
 */
typedef void (*fn_cb_dataless)(libtrace_t *libtrace,
                                    libtrace_thread_t *t,
                                    void *global,
                                    void *tls);

/**
 * @param libtrace The parallel trace
 * @param t The thread that is running
 * @param global The global storage
 * @param tls The thread local storage
 */
typedef void (*fn_cb_first_packet)(libtrace_t *libtrace,
                                   libtrace_thread_t *t,
                                   void *global,
                                   void *tls,
                                   libtrace_packet_t *first_packet,
                                   libtrace_thread_t *sender);

/**
 * @param libtrace The parallel trace
 * @param t The thread that is running
 * @param global The global storage
 * @param tls The thread local storage
 * @param uint64_t Either the timestamp or packet count depending on message type
 */
typedef void (*fn_cb_tick)(libtrace_t *libtrace,
                           libtrace_thread_t *t,
                           void *global,
                           void *tls,
                           uint64_t order);

/**
 * @param libtrace The parallel trace
 * @param t The thread
 * @param packet The packet associated with the message
 * @param global The global storage
 * @param tls The thread local storage
 *
 * @return optionally a packet which is handed back to the library,
 *         typically this is the packet supplied. Otherwise NULL.
 */
typedef libtrace_packet_t* (*fn_cb_packet)(libtrace_t *libtrace,
                                           libtrace_thread_t *t,
                                           void *global,
                                           void *tls,
                                           libtrace_packet_t *packet);

/** Registers a built-in message with a handler.
 * Note we do not include the sending thread as an argument to the reporter.
 * If set to NULL, the message will be sent to default perpkt handler.
 *
 * @param libtrace The input trace to start
 * @param handler the handler to be called when the message is received
 * @return 0 if successful otherwise -1.
 */

DLLEXPORT int trace_cb_starting(libtrace_t *libtrace, fn_cb_starting handler);
DLLEXPORT int trace_cb_stopping(libtrace_t *libtrace, fn_cb_dataless handler);
DLLEXPORT int trace_cb_resuming(libtrace_t *libtrace, fn_cb_dataless handler);
DLLEXPORT int trace_cb_pausing(libtrace_t *libtrace, fn_cb_dataless handler);
DLLEXPORT int trace_cb_packet(libtrace_t *libtrace, fn_cb_packet handler);
DLLEXPORT int trace_cb_first_packet(libtrace_t *libtrace, fn_cb_first_packet handler);
DLLEXPORT int trace_cb_tick_count(libtrace_t *libtrace, fn_cb_tick handler);
DLLEXPORT int trace_cb_tick_interval(libtrace_t *libtrace, fn_cb_tick handler);

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
 * This should only be called by the main thread.
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
 * @name User Data Storage
 *
 * These method provide a way for users to store data against a trace or
 * a thread.
 *
 * Alternatively one could use global variables and thread local
 * storage (__thread), respectively, which in many cases could be simpler.
 *
 * @note We do not lock on reads, instead we rely on the
 * processor making any writes appear atomically.
 *
 * @{
 */

/** Returns the data stored against a trace.
 *
 * @param trace The parallel trace
 * @return The stored data.
 */
DLLEXPORT void * trace_get_local(libtrace_t *trace);

/** Store data against a trace so that all threads can access it
 * using trace_get_global().
 *
 * @param trace The parallel trace.
 * @param data The new value to save against the trace
 * @return The previously stored value
 *
 * The update to the previous value is atomic and thread-safe.
 *
 * @note Although this is thread-safe another thread may still be
 * using the previous data, as such further synchronisation is needed
 * if a thread wanted to free the existing value.
 */
DLLEXPORT void * trace_set_local(libtrace_t *trace, void * data);

/** Returns the users data stored against a thread.
 *
 * @param thread The thread
 * @return The stored data
 */
DLLEXPORT void * trace_get_tls(libtrace_thread_t *thread);

/** Store data against a thread.
 *
 * @param thread The thread
 * @param data The new value to save against the thread
 * @return The previously stored value
 *
 * This function is not thread-safe and is intended only to be
 * called on the currently running thread.
 */
DLLEXPORT void * trace_set_tls(libtrace_thread_t *thread, void * data);

/// @}


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
 * - int:eth0 would match LIBTRACE_CONF, LIBTRACE_CONF_INT, LIBTRACE_CONF_INT_ETH0
 * - dag:/dev/dag0,0 would match LIBTRACE_CONF, LIBTRACE_CONF_DAG, LIBTRACE_CONF_DAG__DEV_DAG0_0
 * - test.erf would match LIBTRACE_CONF, LIBTRACE_CONF_ERF, LIBTRACE_CONF_ERF_TEST_ERF
 *
 * @note All environment variables names MUST only contain
 * [A-Z], [0-9] and [_] (underscore). Any characters
 * outside of this range should be capitalised if possible or replaced with an
 * underscore.
 * @{
 */

/** Set the maximum number of perpkt threads to use in a trace.
 *
 * @param[in] trace The parallel input trace
 * @param[in] nb The number of threads to use. If 0 use default.
 * @return 0 if successful otherwise -1
 */
DLLEXPORT int trace_set_perpkt_threads(libtrace_t *trace, int nb);

/** Set the interval between tick messages in milliseconds.
 *
 * @param[in] trace The parallel input trace
 * @param[in] millisec The interval in milliseconds. If 0 this is disabled [default].
 * @return 0 if successful otherwise -1
 *
 * When a underlying parallel live trace is used MESSAGE_TICK_INTERVAL is sent
 * every tick interval to all per-packet threads to ensure data is received.
 * This allows results to be printed even in cases flows are not being directed
 * to a per-packet thread, while still maintaining order etc.
 *
 * @note Tick count is preferred over tick interval and will be used rather
 * than tick interval if possible.
 * @see MESSAGE_TICK_INTERVAL, trace_set_tick_count()
 */
DLLEXPORT int trace_set_tick_interval(libtrace_t *trace, size_t millisec);

/** Set the count between tick messages.
 *
 * @param[in] trace The parallel input trace
 * @param[in] count The tick count.  If 0 this is disabled [default].
 * @return 0 if successful otherwise -1
 *
 * When an underlying trace is accessed internally by libtrace in a
 * single-threaded manner MESSAGE_TICK_COUNT is sent to all per-packet threads
 * after every count packets have been seen in the trace. This allows results
 * to be printed even in cases flows are not being directed to a per-packet
 * thread, while still maintaining order etc.
 *
 * @see MESSAGE_TICK_COUNT, trace_set_tick_interval()
 */
DLLEXPORT int trace_set_tick_count(libtrace_t *trace, size_t count);

/**
 * Delays packets so they are played back in trace-time rather than as fast
 * as possible (real-time).
 *
 * @param trace A parallel input trace
 * @param tracetime If true packets are released with time intervals matching
 * the original trace. Otherwise packets are read as fast as possible.
 * @return 0 if successful otherwise -1
 */
DLLEXPORT int trace_set_tracetime(libtrace_t *trace, bool tracetime);

/** This sets the maximum size of the freelist used to store empty packets
 * and their memory buffers.
 *
 * @param trace A parallel input trace
 * @param size The number of empty packets to cache in memory. Set to the
 * default, 0, to autoconfigure this value.
 * @return 0 if successful otherwise -1
 *
 * Internally libtrace maintains a buffer of packet structures, this buffer
 * includes a cache per thread and a shared main pool. This configures
 * the size of the main pool. If an application is not passing packets
 * through to the reducer step --- that is to say returns packets from
 * the perpkt function --- this buffer will not need to be used.
 *
 * @note Setting this too low could cause performance issues or a deadlock. An
 * unblockable warning will be printed.
 *
 * @see trace_set_thread_cache_size(), trace_set_fixed_count()
 */
DLLEXPORT int trace_set_cache_size(libtrace_t *trace, size_t size);

/** This sets the maximum size of the freelist thread cache's used to provide
 * faster access than the main shared pool.
 *
 * @param trace A parallel input trace
 * @param size The number of empty packets to cache in memory. Set to the
 * default, 0, to autoconfigure this value.
 * @return 0 if successful otherwise -1
 *
 * @see trace_set_cache_size(), trace_set_fixed_count()
 */
DLLEXPORT int trace_set_thread_cache_size(libtrace_t *trace, size_t size);

/** If true the total number of packets that can be created by a trace is limited
 * to that set by trace_set_cache_size(), otherwise once exceeded malloc
 * and free will be used to create and free packets, this will be slower than
 * using the freelist and could run a machine out of memory.
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
 * a format typically values of 10 will get good performance and increasing
 * beyond that will should little difference.
 *
 * @note We still pass a single packet at a time to the perpkt function
 */
DLLEXPORT int trace_set_burst_size(libtrace_t *trace, size_t size);

/**
 * See diagrams, this sets the maximum size of buffers used between
 * the single hasher thread and the buffer.
 * NOTE setting this to less than recommend could cause deadlock a
 * trace that manages its own packets.
 * A unblockable warning message will be printed to stderr in this case.
 */
/** The number of packets that can queue per thread from hasher thread */
DLLEXPORT int trace_set_hasher_queue_size(libtrace_t *trace, size_t size);

/** If true use a polling hasher queue, that means that we will spin/or yield
 * when data is not available rather than blocking on a condition.
 *
 * @param trace A parallel input trace
 * @param polling If true the hasher will poll waiting for data, otherwise
 * it is not. Defaults to false.
 *
 * We note this is likely to waste many CPU cycles and could even decrease
 * performance.
 *
 * @return 0 if successful otherwise -1
 */
DLLEXPORT int trace_set_hasher_polling(libtrace_t *trace, bool polling);

/** If true the reporter thread will continuously poll waiting for results
 * if false they are only checked when a message is received, this message
 * is controlled by reporter_thold.
 *
 * @param trace A parallel input trace
 * @param polling If true the reporter will poll waiting for data, otherwise
 * it is not. Defaults to false.
 * @return 0 if successful otherwise -1
 *
 * We note this is likely to waste many CPU cycles and could even decrease
 * performance.
 *
 * @note This setting could be ignored by some reporters.
 */
DLLEXPORT int trace_set_reporter_polling(libtrace_t *trace, bool polling);

/** Set the perpkt thread result queue size before triggering the reporter
 * to read results.
 *
 * @param trace A parallel input trace
 * @param thold The threshold on the number of results to enqueue before
 * notifying the reporter thread to read them.
 * @return 0 if successful otherwise -1
 *
 *
 * @note This setting is generally ignored if trace_set_reporter_polling() is
 * set however some combiner functions might ignore trace_set_reporter_polling()
 * and still require this to be set.
 * @see trace_publish_result(), trace_post_reporter()
 */
DLLEXPORT int trace_set_reporter_thold(libtrace_t *trace, size_t thold);

/** Prints a line to standard error for every state change
 * for both the trace as a whole and for each thread.
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
 * per-packet thread a packets is processed by.
 *
 * HASHER_BALANCE is the default and will dispatch packets as fast as possible
 * to all threads arbitrarily. As such when called the hasher and
 * data parameters must be set to NULL.
 *
 * HASHER_CUSTOM will force the libtrace to use the user defined function. As
 * such the hasher parameter must be supplied.
 *
 * With other defined hasher types we will try to push the hashing into the format
 * by default. In this case the hasher parameter is optional and will be
 * preferred over the default supplied by libtrace.
 *
 * @note When supplying a hasher function it should be thread-safe so it can
 * be run in parallel by libtrace. Ideally this should rely upon no state, other
 * than some form of seed value supplied in data.
 */
DLLEXPORT int trace_set_hasher(libtrace_t *trace, enum hasher_types type,
                               fn_hasher hasher, void *data);

/// @}


/** Types of results.
 * Some result types require special handling by combiners
 * as such making use of built-in types is important.
 *
 * Custom result types users should be defined as RESULT_USER(1000) or greater.
 *
 */
enum result_types {
	/**
	 * The result is a packet in some circumstances special handling needs
	 * to be performed. As such packets should always be published as so.
	 *
	 * @param key (Typically) The packets order, see trace_packet_get_order()
	 */
	RESULT_PACKET,

	/** The result is a tick message
	 *
	 * @param key The erf time-stamp of the tick
	 */
	RESULT_TICK_INTERVAL,

	/** The result is a tick message
	 *
	 * @param key The sequence number of the tick message
	 */
	RESULT_TICK_COUNT,

	/** Any user specific codes should be above this.
	 *
	 */
	RESULT_USER = 1000

};

/** Publish a result for to the combiner destined for the reporter thread
 *
 * @param[in] libtrace The parallel input trace
 * @param[in] t The current per-packet thread
 * @param[in] key The key of the result (used for sorting by the combiner)
 * @param[in] value The value of the result
 * @param[in] type The type of result see the documentation for the result_types enum
 */
DLLEXPORT void trace_publish_result(libtrace_t *libtrace,
                                    libtrace_thread_t *t,
                                    uint64_t key,
                                    libtrace_generic_t value,
                                    int type);

/** Check if a dedicated hasher thread is being used.
 *
 * @param[in] libtrace The parallel input trace
 * @return True if the trace has dedicated hasher thread otherwise false.
 *
 * This is valid once the trace is running after calling trace_pstart().
 */
DLLEXPORT bool trace_has_dedicated_hasher(libtrace_t * libtrace);

/** Checks if a trace is using a reporter
 *
 * @param[in] libtrace The parallel input trace
 * @return True if the trace is using a reporter otherwise false
 */
DLLEXPORT bool trace_has_reporter(libtrace_t * libtrace);

/** Post a message to the reporter thread requesting it to check for more
 * results.
 *
 * @param[in] The parallel input trace
 * @return -1 upon error indicating the message has not been sent otherwise a
 * backlog indicator (the number of messages the reporter has not yet read).
 */
DLLEXPORT int trace_post_reporter(libtrace_t *libtrace);

/** Check the number of messages waiting in a queue
 *
 * @param[in] libtrace The input trace
 * @param[in] t The thread to check, if NULL the current thread will be used [Optional]
 *
 * @return packets in the queue otherwise -1 upon error.
 *
 * @note For best performance it is recommended to supply the thread argument
 * even if it is the current thread.
 */
DLLEXPORT int libtrace_thread_get_message_count(libtrace_t * libtrace,
                                                libtrace_thread_t *t);

/** Read a message from a thread in a blocking fashion
 *
 * @param[in] libtrace The input trace
 * @param[in] t The thread to check, if NULL the current thread will be used [Optional]
 * @param[out] message A pointer to libtrace_message_t structure which will be
 * filled with the retrieved message.
 *
 * @return The number of messages remaining otherwise -1 upon error.
 *
 *
 * @note For best performance it is recommended to supply the thread argument
 * even if it is the current thread.
 */
DLLEXPORT int libtrace_thread_get_message(libtrace_t * libtrace,
                                          libtrace_thread_t *t,
                                          libtrace_message_t * message);

/** Read a message from a thread in a blocking fashion
 *
 * @param[in] libtrace The input trace
 * @param[in] t The thread to check, if NULL the current thread will be used [Optional]
 * @param[out] message A pointer to libtrace_message_t structure which will be
 * filled with the retrieved message.
 *
 * @return 0 if successful otherwise -1 upon error or if no packets were available.
 *
 *
 * @note For best performance it is recommended to supply the thread argument
 * even if it is the current thread.
 */
DLLEXPORT int libtrace_thread_try_get_message(libtrace_t * libtrace,
                                              libtrace_thread_t *t,
                                              libtrace_message_t * message);

/** Send a message to the reporter thread
 *
 * @param[in] libtrace The parallel trace
 * @param[in] message The message to be sent, if sender is NULL libtrace will
 * attempt to fill this in. It is faster to assign this if it is known.
 *
 * @return -1 upon error indicating the message has not been sent otherwise a
 * backlog indicator (the number of messages the reporter has not yet read).
 */
DLLEXPORT int trace_message_reporter(libtrace_t * libtrace,
                                     libtrace_message_t * message);

/** Send a message to all per-packet threads
 *
 * @param[in] libtrace The parallel trace
 * @param[in] message The message to be sent, if sender is NULL libtrace will
 * attempt to fill this in. It is faster to assign this if it is known.
 *
 * @return 0 if successful otherwise a negative number indicating the number
 * of per-packet threads the message was not sent to (i.e. -1 means one thread
 * could not be sent the message).
 */
DLLEXPORT int trace_message_perpkts(libtrace_t * libtrace,
                                    libtrace_message_t * message);

/** Send a message to a thread
 *
 * @param[in] libtrace The parallel trace
 * @param[in] t The thread to message
 * @param[in] message The message to be sent, if sender is NULL libtrace will
 * attempt to fill this in. It is faster to assign this if it is known.
 *
 * @return -1 upon error indicating the message has not been sent otherwise a
 * backlog indicator (the number of messages the thread has not yet read).
 */
DLLEXPORT int trace_message_thread(libtrace_t * libtrace,
                                   libtrace_thread_t *t,
                                   libtrace_message_t * message);

/** Check if a parallel trace has finished reading packets
 *
 * @return True if the trace has finished reading packets (even if all results
 * have not yet been processed). Otherwise false.
 *
 * @note This returns true even if all results have not yet been processed.
 */
DLLEXPORT bool trace_has_finished(libtrace_t * libtrace);


/** Check if libtrace is directly reading from multiple queues
 * from the format (such as a NICs hardware queues).
 *
 * When a parallel trace is running, or if checked after its completion
 * this returns true if a trace was able to run natively parallel
 * from the format. Otherwise false is returned, meaning libtrace is
 * distibuting packets across multiple threads from a single source.
 *
 * Factors that may stop this happening despite the format supporting
 * native parallel reads include: the choice of hasher function,
 * the number of threads choosen (such as 1 or more than the trace supports)
 * or another error when trying to start the parallel format.
 *
 * If this is called before the trace is started. I.e. before pstart
 * this returns an indication that the trace has the possiblity to support
 * native parallel reads. After trace pstart is called this should be
 * checked again to confirm this has happened.
 *
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
 * The returned value can be used to compare if packets come before or after
 * others.
 */
DLLEXPORT uint64_t trace_packet_get_order(libtrace_packet_t * packet);

/** Returns the hash of a packet.
 *
 * @param[in] packet
 * @return A 64-bit hash
 *
 * @note In many cases this might not be filled in, only in cases where
 * a custom hash is being used. You can use trace_has_dedicated_hasher()
 * to check if this will be valid.
 */
DLLEXPORT uint64_t trace_packet_get_hash(libtrace_packet_t * packet);

/** Sets the order of a packet.
 *
 * @param[in] packet
 * @param[in] order the new order of a packet
 *
 * @note many combiners rely on this value, ensure changing this conforms to
 * the combiners requirements.
 */
DLLEXPORT void trace_packet_set_order(libtrace_packet_t * packet, uint64_t order);

/** Sets the hash of a packet.
 *
 * @param[in] packet
 * @param[in] hash the new hash
 *
 * Once handed to the user the libtrace library has little use for this field
 * and as such this can essentially be used for any storage the user requires.
 */
DLLEXPORT void trace_packet_set_hash(libtrace_packet_t * packet, uint64_t hash);

/** TODO WHAT TO DO WITH THIS ? */
DLLEXPORT uint64_t tv_to_usec(const struct timeval *tv);


/** Returns the first packet of a parallel trace since it was started or
 * restarted.
 *
 * @param[in] libtrace the parallel input trace
 * @param[in] t Either a per packet thread or NULL to retrieve the first packet
 * of across all per packet threads.
 * @param[out] packet A pointer to the first packet in the trace. [Optional]
 * @param[out] tv The system time-stamp when this packet was received. [Optional]
 * @return 1 if we are confident this is the first packet. Otherwise 0 if this
 * is a best guess (this is only possible int the case t=NULL)
 * in which case we recommend calling this at a later time.
 * -1 is returned if an error occurs, such as supplied a invalid thread.
 *
 * The packet and timeval returned by this function is shared by all threads
 * and remain valid until MESSAGE_PAUSING is received.
 */
DLLEXPORT int trace_get_first_packet(libtrace_t *libtrace,
                                     libtrace_thread_t *t,
                                     const libtrace_packet_t **packet,
                                     const struct timeval **tv);

/** Makes a packet safe, a packet will become invalid after a
 * pausing a trace.
 *
 * @param[in,out] pkt The packet to make safe
 *
 * This copies a packet in such a way that it will be able to survive a pause.
 * However this will not allow the packet to be used after
 * the format is destroyed.
 */
DLLEXPORT void libtrace_make_packet_safe(libtrace_packet_t *pkt);

/** Makes a result safe if a result contains a packet.
 *
 * @param[in,out] res The result to make safe.
 *
 * This ensures the internal content of a result is safe to survive a pause.
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
 * @note All packets should be free'd before a trace is destroyed.
 */
DLLEXPORT void trace_free_packet(libtrace_t * libtrace, libtrace_packet_t * packet);


DLLEXPORT libtrace_info_t *trace_get_information(libtrace_t * libtrace);

/** Sets the configuration of a trace based upon a comma separated list of
 * key value pairs.
 *
 * @param trace A parallel trace which is not running or destroyed
 * @param str A comma separated list of key=value pairs.
 * E.g. \em "burst_size=20,perpkt_threads=2,fixed_count=true"
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
 * @note this interface is provided to allow a user to configure an application
 * if a libtrace applicate wishes to configure a setting it should use a
 * trace_set_*() function with the same name.
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

DLLEXPORT int libtrace_get_perpkt_count(libtrace_t* t); // TODO MATCH WITH THE SET_PERPKT

/**
 * Sets a combiner function against the trace.
 *
 * @param trace The input trace
 * @combiner The combiner to use
 * @config config Configuration information. Dependent upon the combiner in use
 *
 * Sets a combiner against a trace, this should only be called on a
 * non-started or paused trace.  By default combiner_unordered
 * will be used.
 */
DLLEXPORT void trace_set_combiner(libtrace_t *trace, const libtrace_combine_t *combiner, libtrace_generic_t config);

/**
 * Takes unordered (or ordered) input and produces unordered output.
 * Basically you get the result quickly but in no particular order.
 */
extern const libtrace_combine_t combiner_unordered;

/**
 * Takes ordered input and produces ordered output. Perpkt threads
 * the output results must be ordered for this to work correctly!!
 */
extern const libtrace_combine_t combiner_ordered;

/**
 * Like classic Google Map/Reduce, the results are sorted
 * in ascending order, this is only done when the trace finishes.
 *
 * This only works with a limited number of results, otherwise
 * we will just run out of memory and crash!! You should always
 * use combiner_ordered if you can.
 */
extern const libtrace_combine_t combiner_sorted;

#endif // LIBTRACE_PARALLEL_H
