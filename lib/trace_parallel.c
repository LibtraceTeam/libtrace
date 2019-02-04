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
#include "libtrace_parallel.h"

#ifdef HAVE_NET_BPF_H
#  include <net/bpf.h>
#else
#  ifdef HAVE_PCAP_BPF_H
#    include <pcap-bpf.h>
#  endif
#endif


#include "libtrace_int.h"
#include "format_helper.h"
#include "rt_protocol.h"
#include "hash_toeplitz.h"

#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>

static inline int delay_tracetime(libtrace_t *libtrace, libtrace_packet_t *packet, libtrace_thread_t *t);
extern int libtrace_parallel;

struct mem_stats {
	struct memfail {
	   uint64_t cache_hit;
	   uint64_t ring_hit;
	   uint64_t miss;
	   uint64_t recycled;
	} readbulk, read, write, writebulk;
};


#ifdef ENABLE_MEM_STATS
// Grrr gcc wants this spelt out
__thread struct mem_stats mem_hits = {{0},{0},{0},{0}};


static void print_memory_stats() {
	uint64_t total;
#if defined(HAVE_PTHREAD_SETNAME_NP) && defined(__linux__)
	char t_name[50];
	pthread_getname_np(pthread_self(), t_name, sizeof(t_name));

	fprintf(stderr, "Thread ID#%d - %s\n", (int) pthread_self(), t_name);
#else
	fprintf(stderr, "Thread ID#%d\n", (int) pthread_self());
#endif

	total = mem_hits.read.cache_hit + mem_hits.read.ring_hit + mem_hits.read.miss;
	if (total) {
		fprintf(stderr, "\tRead:\n\t---CHits=%"PRIu64"\n\t---RHits=%"PRIu64"\n\t---Misses=%"PRIu64"\n\t---Recycled=%"PRIu64"\n",
				mem_hits.read.cache_hit, mem_hits.read.ring_hit, mem_hits.read.miss, mem_hits.read.recycled);
		fprintf(stderr, "\t---Total=%"PRIu64"\n\t---Miss %%=%f\n",
				total, (double) mem_hits.read.miss / (double) total * 100.0);
	}

	total = mem_hits.readbulk.cache_hit + mem_hits.readbulk.ring_hit + mem_hits.readbulk.miss;
	if (total) {
		fprintf(stderr, "\tReadbulk:\n\t---CHits=%"PRIu64"\n\t---RHits=%"PRIu64"\n\t---Misses=%"PRIu64"\n\t---Recycled=%"PRIu64"\n",
				mem_hits.readbulk.cache_hit, mem_hits.readbulk.ring_hit, mem_hits.readbulk.miss, mem_hits.readbulk.recycled);


		fprintf(stderr, "\t---Total=%"PRIu64"\n\t---Miss %%=%f\n",
				total, (double) mem_hits.readbulk.miss / (double) total * 100.0);
	}

	total = mem_hits.write.cache_hit + mem_hits.write.ring_hit + mem_hits.write.miss;
	if (total) {
		fprintf(stderr, "\tWrite:\n\t---CHits=%"PRIu64"\n\t---RHits=%"PRIu64"\n\t---Misses=%"PRIu64"\n\t---Recycled=%"PRIu64"\n",
				mem_hits.write.cache_hit, mem_hits.write.ring_hit, mem_hits.write.miss, mem_hits.write.recycled);

		fprintf(stderr, "\t---Total=%"PRIu64"\n\t---Miss %%=%f\n",
				total, (double) mem_hits.write.miss / (double) total * 100.0);
	}

	total = mem_hits.writebulk.cache_hit + mem_hits.writebulk.ring_hit + mem_hits.writebulk.miss;
	if (total) {
		fprintf(stderr, "\tWritebulk:\n\t---CHits=%"PRIu64"\n\t---RHits=%"PRIu64"\n\t---Misses=%"PRIu64"\n\t---Recycled=%"PRIu64"\n",
				mem_hits.writebulk.cache_hit, mem_hits.writebulk.ring_hit, mem_hits.writebulk.miss, mem_hits.writebulk.recycled);

		fprintf(stderr, "\t---Total=%"PRIu64"\n\t---Miss %%=%f\n",
				total, (double) mem_hits.writebulk.miss / (double) total * 100.0);
	}
}
#else
static void print_memory_stats() {}
#endif

static const libtrace_generic_t gen_zero = {0};

/* This should optimise away the switch to nothing in the explict cases */
inline void send_message(libtrace_t *trace, libtrace_thread_t *thread,
                const enum libtrace_messages type,
		libtrace_generic_t data, libtrace_thread_t *sender) {

	fn_cb_dataless fn = NULL;
        enum libtrace_messages switchtype;
        libtrace_callback_set_t *cbs = NULL;

        if (thread == &trace->reporter_thread) {
                cbs = trace->reporter_cbs;
        } else {
                cbs = trace->perpkt_cbs;
        }

        if (cbs == NULL)
                return;

        if (type >= MESSAGE_USER)
                switchtype = MESSAGE_USER;
        else
                switchtype = (enum libtrace_messages) type;

	switch (switchtype) {
	case MESSAGE_STARTING:
		if (cbs->message_starting)
			thread->user_data = (*cbs->message_starting)(trace,
                                        thread, trace->global_blob);
		return;
	case MESSAGE_FIRST_PACKET:
		if (cbs->message_first_packet)
			        (*cbs->message_first_packet)(trace, thread,
                                trace->global_blob, thread->user_data,
                                sender);
		return;
	case MESSAGE_TICK_COUNT:
		if (cbs->message_tick_count)
			(*cbs->message_tick_count)(trace, thread,
                                        trace->global_blob, thread->user_data,
                                        data.uint64);
		return;
	case MESSAGE_TICK_INTERVAL:
		if (cbs->message_tick_interval)
			(*cbs->message_tick_interval)(trace, thread,
                                        trace->global_blob, thread->user_data,
                                        data.uint64);
		return;
	case MESSAGE_STOPPING:
		fn = cbs->message_stopping;
		break;
	case MESSAGE_RESUMING:
		fn = cbs->message_resuming;
		break;
	case MESSAGE_PAUSING:
		fn = cbs->message_pausing;
		break;
	case MESSAGE_USER:
		if (cbs->message_user)
			(*cbs->message_user)(trace, thread, trace->global_blob,
                                        thread->user_data, type, data, sender);
		return;
	case MESSAGE_RESULT:
                if (cbs->message_result)
                        (*cbs->message_result)(trace, thread,
                                        trace->global_blob, thread->user_data,
                                        data.res);
                return;

	/* These should be unused */
	case MESSAGE_DO_PAUSE:
	case MESSAGE_DO_STOP:
	case MESSAGE_POST_REPORTER:
	case MESSAGE_PACKET:
		return;
	}

	if (fn)
		(*fn)(trace, thread, trace->global_blob, thread->user_data);
}

DLLEXPORT void trace_destroy_callback_set(libtrace_callback_set_t *cbset) {
        free(cbset);
}

DLLEXPORT libtrace_callback_set_t *trace_create_callback_set() {
        libtrace_callback_set_t *cbset;

        cbset = (libtrace_callback_set_t *)malloc(sizeof(libtrace_callback_set_t));
        memset(cbset, 0, sizeof(libtrace_callback_set_t));
        return cbset;
}

/*
 * This can be used once the hasher thread has been started and internally after
 * verify_configuration.
 */
DLLEXPORT bool trace_has_dedicated_hasher(libtrace_t * libtrace)
{
	return libtrace->hasher_thread.type == THREAD_HASHER;
}

DLLEXPORT bool trace_has_reporter(libtrace_t * libtrace)
{
	if (!(libtrace->state != STATE_NEW)) {
		trace_set_err(libtrace, TRACE_ERR_BAD_STATE, "Cannot check reporter for the current state in trace_has_reporter()");
		return false;
	}
	return libtrace->reporter_thread.type == THREAD_REPORTER && libtrace->reporter_cbs;
}

/**
 * When running the number of perpkt threads in use.
 * TODO what if the trace is not running yet, or has finished??
 *
 * @brief libtrace_perpkt_thread_nb
 * @param t The trace
 * @return
 */
DLLEXPORT int trace_get_perpkt_threads(libtrace_t * t) {
	return t->perpkt_thread_count;
}

DLLEXPORT int trace_get_perpkt_thread_id(libtrace_thread_t *thread) {
        return thread->perpkt_num;
}

/**
 * Changes the overall traces state and signals the condition.
 *
 * @param trace A pointer to the trace
 * @param new_state The new state of the trace
 * @param need_lock Set to true if libtrace_lock is not held, otherwise
 *        false in the case the lock is currently held by this thread.
 */
static inline void libtrace_change_state(libtrace_t *trace,
	const enum trace_state new_state, const bool need_lock)
{
	UNUSED enum trace_state prev_state;
	if (need_lock)
		pthread_mutex_lock(&trace->libtrace_lock);
	prev_state = trace->state;
	trace->state = new_state;

	if (trace->config.debug_state)
		fprintf(stderr, "Trace(%s) state changed from %s to %s\n",
			trace->uridata, get_trace_state_name(prev_state),
			get_trace_state_name(trace->state));

	pthread_cond_broadcast(&trace->perpkt_cond);
	if (need_lock)
		pthread_mutex_unlock(&trace->libtrace_lock);
}

/**
 * Changes a thread's state and broadcasts the condition variable. This
 * should always be done when the lock is held.
 *
 * Additionally for perpkt threads the state counts are updated.
 *
 * @param trace A pointer to the trace
 * @param t A pointer to the thread to modify
 * @param new_state The new state of the thread
 * @param need_lock Set to true if libtrace_lock is not held, otherwise
 *        false in the case the lock is currently held by this thread.
 */
static inline void thread_change_state(libtrace_t *trace, libtrace_thread_t *t,
	const enum thread_states new_state, const bool need_lock)
{
	enum thread_states prev_state;
	if (need_lock)
		pthread_mutex_lock(&trace->libtrace_lock);
	prev_state = t->state;
	t->state = new_state;
	if (t->type == THREAD_PERPKT) {
		--trace->perpkt_thread_states[prev_state];
		++trace->perpkt_thread_states[new_state];
	}

	if (trace->config.debug_state)
		fprintf(stderr, "Thread %d state changed from %d to %d\n",
		        (int) t->tid, prev_state, t->state);

	if (trace->perpkt_thread_states[THREAD_FINISHED] == trace->perpkt_thread_count) {
                /* Make sure we save our final stats in case someone wants
                 * them at the end of their program.
                 */

                trace_get_statistics(trace, NULL);
		libtrace_change_state(trace, STATE_FINISHED, false);
        }

	pthread_cond_broadcast(&trace->perpkt_cond);
	if (need_lock)
		pthread_mutex_unlock(&trace->libtrace_lock);
}

/**
 * This is valid once a trace is initialised
 *
 * @return True if the format supports parallel threads.
 */
static inline bool trace_supports_parallel(libtrace_t *trace)
{
	if (!trace) {
		fprintf(stderr, "NULL trace passed into trace_supports_parallel()\n");
		return false;
	}
	if (!trace->format) {
		trace_set_err(trace, TRACE_ERR_BAD_FORMAT,
			"NULL capture format associated with trace in trace_supports_parallel()");
		return false;
	}
	if (trace->format->pstart_input)
		return true;
	else
		return false;
}

void libtrace_zero_thread(libtrace_thread_t * t) {
	t->accepted_packets = 0;
	t->filtered_packets = 0;
	t->recorded_first = false;
	t->tracetime_offset_usec = 0;
	t->user_data = 0;
	t->format_data = 0;
	libtrace_zero_ringbuffer(&t->rbuffer);
	t->trace = NULL;
	t->ret = NULL;
	t->type = THREAD_EMPTY;
	t->perpkt_num = -1;
}

// Ints are aligned int is atomic so safe to read and write at same time
// However write must be locked, read doesn't (We never try read before written to table)
libtrace_thread_t * get_thread_table(libtrace_t *libtrace) {
	int i = 0;
	pthread_t tid = pthread_self();

	for (;i<libtrace->perpkt_thread_count ;++i) {
		if (pthread_equal(tid, libtrace->perpkt_threads[i].tid))
			return &libtrace->perpkt_threads[i];
	}
	return NULL;
}

static libtrace_thread_t * get_thread_descriptor(libtrace_t *libtrace) {
	libtrace_thread_t *ret;
	if (!(ret = get_thread_table(libtrace))) {
		pthread_t tid = pthread_self();
		// Check if we are reporter or something else
		if (libtrace->hasher_thread.type == THREAD_REPORTER &&
				pthread_equal(tid, libtrace->reporter_thread.tid))
			ret = &libtrace->reporter_thread;
		else if (libtrace->hasher_thread.type == THREAD_HASHER &&
		         pthread_equal(tid, libtrace->hasher_thread.tid))
			ret = &libtrace->hasher_thread;
		else
			ret = NULL;
	}
	return ret;
}

DLLEXPORT void libtrace_make_packet_safe(libtrace_packet_t *pkt) {
	// Duplicate the packet in standard malloc'd memory and free the
	// original, This is a 1:1 exchange so the ocache count remains unchanged.
	if (pkt->buf_control != TRACE_CTRL_PACKET) {
		libtrace_packet_t *dup;
		dup = trace_copy_packet(pkt);
		/* Release the external buffer */
		trace_fin_packet(pkt);
		/* Copy the duplicated packet over the existing */
		memcpy(pkt, dup, sizeof(libtrace_packet_t));
		/* Free the packet structure */
		free(dup);
	}
}

/**
 * Makes a libtrace_result_t safe, used when pausing a trace.
 * This will call libtrace_make_packet_safe if the result is
 * a packet.
 */
DLLEXPORT void libtrace_make_result_safe(libtrace_result_t *res) {
	if (res->type == RESULT_PACKET) {
		libtrace_make_packet_safe(res->value.pkt);
	}
}

/**
 * Holds threads in a paused state, until released by broadcasting
 * the condition mutex.
 */
static void trace_thread_pause(libtrace_t *trace, libtrace_thread_t *t) {
	ASSERT_RET(pthread_mutex_lock(&trace->libtrace_lock), == 0);
	thread_change_state(trace, t, THREAD_PAUSED, false);
	while (trace->state == STATE_PAUSED || trace->state == STATE_PAUSING) {
		ASSERT_RET(pthread_cond_wait(&trace->perpkt_cond, &trace->libtrace_lock), == 0);
	}
	thread_change_state(trace, t, THREAD_RUNNING, false);
	ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
}

/**
 * Sends a packet to the user, expects either a valid packet or a TICK packet.
 *
 * @param trace The trace
 * @param t The current thread
 * @param packet A pointer to the packet storage, which may be set to null upon
 *               return, or a packet to be finished.
 * @param tracetime If true packets are delayed to match with tracetime
 * @return 0 is successful, otherwise if playing back in tracetime
 *         READ_MESSAGE(-2) can be returned in which case the packet is not sent.
 *
 * @note READ_MESSAGE will only be returned if tracetime is true.
 */
static inline int dispatch_packet(libtrace_t *trace,
                                  libtrace_thread_t *t,
                                  libtrace_packet_t **packet,
                                  bool tracetime) {

	if ((*packet)->error > 0) {
		if (tracetime) {
			if (delay_tracetime(trace, packet[0], t) == READ_MESSAGE)
				return READ_MESSAGE;
		}
                if (!IS_LIBTRACE_META_PACKET((*packet))) {
        		t->accepted_packets++;
                }
		if (trace->perpkt_cbs->message_packet)
			*packet = (*trace->perpkt_cbs->message_packet)(trace, t, trace->global_blob, t->user_data, *packet);
		trace_fin_packet(*packet);
	} else {
		if ((*packet)->error != READ_TICK) {
			trace_set_err(trace, TRACE_ERR_BAD_STATE,
				"dispatch_packet() called with invalid 'packet'");
			return -1;
		}
		libtrace_generic_t data = {.uint64 = trace_packet_get_order(*packet)};
		send_message(trace, t, MESSAGE_TICK_COUNT, data, t);
	}
	return 0;
}

/**
 * Sends a batch of packets to the user, expects either a valid packet or a
 * TICK packet.
 *
 * @param trace The trace
 * @param t The current thread
 * @param packets [in,out] An array of packets, these may be null upon return
 * @param nb_packets The total number of packets in the list
 * @param empty [in,out] A pointer to an integer storing the first empty slot,
 * upon return this is updated
 * @param offset [in,out] The offset into the array, upon return this is updated
 * @param tracetime If true packets are delayed to match with tracetime
 * @return 0 is successful, otherwise if playing back in tracetime
 *         READ_MESSAGE(-2) can be returned in which case the packet is not sent.
 *
 * @note READ_MESSAGE will only be returned if tracetime is true.
 */
static inline int dispatch_packets(libtrace_t *trace,
                                  libtrace_thread_t *t,
                                  libtrace_packet_t *packets[],
                                  int nb_packets, int *empty, int *offset,
                                  bool tracetime) {
	for (;*offset < nb_packets; ++*offset) {
		int ret;
		ret = dispatch_packet(trace, t, &packets[*offset], tracetime);
		if (ret == 0) {
			/* Move full slots to front as we go */
			if (packets[*offset]) {
				if (*empty != *offset) {
					packets[*empty] = packets[*offset];
					packets[*offset] = NULL;
				}
				++*empty;
			}
		} else {
			/* Break early */
			if (ret != READ_MESSAGE) {
				trace_set_err(trace, TRACE_ERR_UNKNOWN_OPTION,
					"dispatch_packets() called with at least one invalid packet");
				return -1;
			}
			return READ_MESSAGE;
		}
	}

	return 0;
}

/**
 * Pauses a per packet thread, messages will not be processed when the thread
 * is paused.
 *
 * This process involves reading packets if a hasher thread is used. As such
 * this function can fail to pause due to errors when reading in which case
 * the thread should be stopped instead.
 *
 *
 * @brief trace_perpkt_thread_pause
 * @return READ_ERROR(-1) or READ_EOF(0) or 1 if successfull
 */
static int trace_perpkt_thread_pause(libtrace_t *trace, libtrace_thread_t *t,
                                     libtrace_packet_t *packets[],
                                     int nb_packets, int *empty, int *offset) {
	libtrace_packet_t * packet = NULL;

	/* Let the user thread know we are going to pause */
	send_message(trace, t, MESSAGE_PAUSING, gen_zero, t);

	/* Send through any remaining packets (or messages) without delay */

	/* First send those packets already read, as fast as possible
	 * This should never fail or check for messages etc. */
	ASSERT_RET(dispatch_packets(trace, t, packets, nb_packets, empty,
	                            offset, false), == 0);

	libtrace_ocache_alloc(&trace->packet_freelist, (void **) &packet, 1, 1);
	/* If a hasher thread is running, empty input queues so we don't lose data */
	if (trace_has_dedicated_hasher(trace)) {
		// The hasher has stopped by this point, so the queue shouldn't be filling
		while(!libtrace_ringbuffer_is_empty(&t->rbuffer) || t->format_data) {
			int ret = trace->pread(trace, t, &packet, 1);
			if (ret == 1) {
				if (packet->error > 0) {
					store_first_packet(trace, packet, t);
				}
				ASSERT_RET(dispatch_packet(trace, t, &packet, false), == 0);
				if (packet == NULL)
					libtrace_ocache_alloc(&trace->packet_freelist, (void **) &packet, 1, 1);
			} else if (ret != READ_MESSAGE) {
				/* Ignore messages we pick these up next loop */
				if (!(ret == READ_EOF || ret == READ_ERROR)) {
					trace_set_err(trace, TRACE_ERR_PAUSE_PTHREAD,
						"Error pausing processing thread in trace_perpkt_thread_pause()");
					return -1;
				}
				/* Verify no packets are remaining */
				/* TODO refactor this sanity check out!! */
				while (!libtrace_ringbuffer_is_empty(&t->rbuffer)) {
					ASSERT_RET(trace->pread(trace, t, &packet, 1), <= 0);
					// No packets after this should have any data in them
					if (packet->error > 0) {
						trace_set_err(trace, TRACE_ERR_BAD_PACKET, "Bogus data in "
							"libtrace ring buffer after pausing perpkt thread");
						return -1;
					}
				}
				libtrace_ocache_free(&trace->packet_freelist, (void **) &packet, 1, 1);
				return -1;
			}
		}
	}
	libtrace_ocache_free(&trace->packet_freelist, (void **) &packet, 1, 1);

	/* Now we do the actual pause, this returns when we resumed */
	trace_thread_pause(trace, t);
	send_message(trace, t, MESSAGE_RESUMING, gen_zero, t);
	return 1;
}

/**
 * The is the entry point for our packet processing threads.
 */
static void* perpkt_threads_entry(void *data) {
	libtrace_t *trace = (libtrace_t *)data;
	libtrace_thread_t *t;
	libtrace_message_t message = {0, {.uint64=0}, NULL};
	libtrace_packet_t *packets[trace->config.burst_size];
	size_t i;
	//int ret;
	/* The current reading position into the packets */
	int offset = 0;
	/* The number of packets last read */
	int nb_packets = 0;
	/* The offset to the first NULL packet upto offset */
	int empty = 0;
        int j;

	/* Wait until trace_pstart has been completed */
	ASSERT_RET(pthread_mutex_lock(&trace->libtrace_lock), == 0);
	t = get_thread_table(trace);
	if (!t) {
		trace_set_err(trace, TRACE_ERR_THREAD, "Unable to get thread table in perpkt_threads_entry()");
		ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
		pthread_exit(NULL);
	}
	if (trace->state == STATE_ERROR) {
		thread_change_state(trace, t, THREAD_FINISHED, false);
		ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
		pthread_exit(NULL);
	}
	ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);

	if (trace->format->pregister_thread) {
		if (trace->format->pregister_thread(trace, t, 
				trace_is_parallel(trace)) < 0) {
			thread_change_state(trace, t, THREAD_FINISHED, false);
			pthread_exit(NULL);
		}
	}

	/* Fill our buffer with empty packets */
	memset(&packets, 0, sizeof(void*) * trace->config.burst_size);
	libtrace_ocache_alloc(&trace->packet_freelist, (void **) packets,
	                      trace->config.burst_size,
	                      trace->config.burst_size);

	/* ~~~~~~~~~~~ Setup complete now we loop ~~~~~~~~~~~~~~~ */

	/* Let the per_packet function know we have started */
	send_message(trace, t, MESSAGE_STARTING, gen_zero, t);
	send_message(trace, t, MESSAGE_RESUMING, gen_zero, t);

	for (;;) {

		if (libtrace_message_queue_try_get(&t->messages, &message) != LIBTRACE_MQ_FAILED) {
			int ret;
			switch (message.code) {
				case MESSAGE_DO_PAUSE: // This is internal
					ret = trace_perpkt_thread_pause(trace, t,
					      packets, nb_packets, &empty, &offset);
					if (ret == READ_EOF) {
						goto eof;
					} else if (ret == READ_ERROR) {
						goto error;
					}
					if (ret != 1) {
						fprintf(stderr, "Unknown error pausing thread in perpkt_threads_entry()\n");
						pthread_exit(NULL);
					}
					continue;
				case MESSAGE_DO_STOP: // This is internal
					goto eof;
			}
                        send_message(trace, t, message.code, message.data, 
                                        message.sender);
			/* Continue and the empty messages out before packets */
			continue;
		}


		/* Do we need to read a new set of packets MOST LIKELY we do */
		if (offset == nb_packets) {
			/* Refill the packet buffer */
			if (empty != nb_packets) {
				// Refill the empty packets
				libtrace_ocache_alloc(&trace->packet_freelist,
						      (void **) &packets[empty],
						      nb_packets - empty,
						      nb_packets - empty);
			}
			if (!trace->pread) {
				if (!packets[0]) {
					fprintf(stderr, "Unable to read into NULL packet structure\n");
					pthread_exit(NULL);
				}
				nb_packets = trace_read_packet(trace, packets[0]);
				packets[0]->error = nb_packets;
				if (nb_packets > 0)
					nb_packets = 1;
			} else {
				nb_packets = trace->pread(trace, t, packets, trace->config.burst_size);
			}
			offset = 0;
			empty = 0;
		}

		/* Handle error/message cases */
		if (nb_packets > 0) {
			/* Store the first non-meta packet */
                        for (j = 0; j < nb_packets; j++) {
                                if (t->recorded_first)
                                        break;
			        if (packets[j]->error > 0) {
        				store_first_packet(trace, packets[j], t);
                                }
			}
			dispatch_packets(trace, t, packets, nb_packets, &empty,
			                 &offset, trace->tracetime);
		} else {
			switch (nb_packets) {
			case READ_EOF:
				goto eof;
			case READ_ERROR:
				goto error;
			case READ_MESSAGE:
				nb_packets = 0;
				continue;
			default:
				fprintf(stderr, "Unexpected error %d!!\n", nb_packets);
				goto error;
			}
		}

	}

error:
	message.code = MESSAGE_DO_STOP;
	message.sender = t;
	message.data.uint64 = 0;
	trace_message_perpkts(trace, &message);
eof:
	/* ~~~~~~~~~~~~~~ Trace is finished do tear down ~~~~~~~~~~~~~~~~~~~~~ */

	// Let the per_packet function know we have stopped
	send_message(trace, t, MESSAGE_PAUSING, gen_zero, t);
	send_message(trace, t, MESSAGE_STOPPING, gen_zero, t);

	// Free any remaining packets
	for (i = 0; i < trace->config.burst_size; i++) {
		if (packets[i]) {
			libtrace_ocache_free(&trace->packet_freelist, (void **) &packets[i], 1, 1);
			packets[i] = NULL;
		}
	}

	thread_change_state(trace, t, THREAD_FINISHED, true);

	/* Make sure the reporter sees we have finished */
	if (trace_has_reporter(trace))
		trace_post_reporter(trace);

	// Release all ocache memory before unregistering with the format
	// because this might(it does in DPDK) unlink the formats mempool
	// causing destroy/finish packet to fail.
	libtrace_ocache_unregister_thread(&trace->packet_freelist);
	if (trace->format->punregister_thread) {
		trace->format->punregister_thread(trace, t);
	}
	print_memory_stats();

	pthread_exit(NULL);
}

/**
 * The start point for our single threaded hasher thread, this will read
 * and hash a packet from a data source and queue it against the correct
 * core to process it.
 */
static void* hasher_entry(void *data) {
	libtrace_t *trace = (libtrace_t *)data;
	libtrace_thread_t * t;
	int i;
	libtrace_packet_t * packet;
	libtrace_message_t message = {0, {.uint64=0}, NULL};
	int pkt_skipped = 0;

	if (!trace_has_dedicated_hasher(trace)) {
		fprintf(stderr, "Trace does not have hasher associated with it in hasher_entry()\n");
		pthread_exit(NULL);
	}
	/* Wait until all threads are started and objects are initialised (ring buffers) */
	ASSERT_RET(pthread_mutex_lock(&trace->libtrace_lock), == 0);
	t = &trace->hasher_thread;
	if (!(t->type == THREAD_HASHER && pthread_equal(pthread_self(), t->tid))) {
		fprintf(stderr, "Incorrect thread type or non matching thread IDs in hasher_entry()\n");
		pthread_exit(NULL);
	}

	if (trace->state == STATE_ERROR) {
		thread_change_state(trace, t, THREAD_FINISHED, false);
		ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
		pthread_exit(NULL);
	}
	ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);

	/* We are reading but it is not the parallel API */
	if (trace->format->pregister_thread) {
		trace->format->pregister_thread(trace, t, true);
	}

	/* Read all packets in then hash and queue against the correct thread */
	while (1) {
		int thread;
		if (!pkt_skipped)
			libtrace_ocache_alloc(&trace->packet_freelist, (void **) &packet, 1, 1);
		if (!packet) {
			fprintf(stderr, "Hasher thread was unable to get a fresh packet from the "
				"object cache\n");
			pthread_exit(NULL);
		}

		// Check for messages that we expect MESSAGE_DO_PAUSE, (internal messages only)
		if (libtrace_message_queue_try_get(&t->messages, &message) != LIBTRACE_MQ_FAILED) {
			switch(message.code) {
				case MESSAGE_DO_PAUSE:
					ASSERT_RET(pthread_mutex_lock(&trace->libtrace_lock), == 0);
					thread_change_state(trace, t, THREAD_PAUSED, false);
					pthread_cond_broadcast(&trace->perpkt_cond);
					while (trace->state == STATE_PAUSED || trace->state == STATE_PAUSING) {
						ASSERT_RET(pthread_cond_wait(&trace->perpkt_cond, &trace->libtrace_lock), == 0);
					}
					thread_change_state(trace, t, THREAD_RUNNING, false);
					pthread_cond_broadcast(&trace->perpkt_cond);
					ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
					break;
				case MESSAGE_DO_STOP:
					/* Either FINISHED or FINISHING */
					if (!(trace->started == false)) {
						fprintf(stderr, "STOP message received by hasher, but "
							"trace is still active\n");
						pthread_exit(NULL);
					}
					/* Mark the current packet as EOF */
					packet->error = 0;
					goto hasher_eof;
				default:
					fprintf(stderr, "Hasher thread didn't expect message code=%d\n", message.code);
			}
			pkt_skipped = 1;
			continue;
		}

		if ((packet->error = trace_read_packet(trace, packet)) <1) {
			if (packet->error == READ_MESSAGE) {
				pkt_skipped = 1;
				continue;
			} else {
				break; /* We are EOF or error'd either way we stop  */
			}
		}

		/* We are guaranteed to have a hash function i.e. != NULL */
		trace_packet_set_hash(packet, (*trace->hasher)(packet, trace->hasher_data));
		thread = trace_packet_get_hash(packet) % trace->perpkt_thread_count;
		/* Blocking write to the correct queue - I'm the only writer */
		if (trace->perpkt_threads[thread].state != THREAD_FINISHED) {
			uint64_t order = trace_packet_get_order(packet);
			libtrace_ringbuffer_write(&trace->perpkt_threads[thread].rbuffer, packet);
			if (trace->config.tick_count && order % trace->config.tick_count == 0) {
				// Write ticks to everyone else
				libtrace_packet_t * pkts[trace->perpkt_thread_count];
				memset(pkts, 0, sizeof(void *) * trace->perpkt_thread_count);
				libtrace_ocache_alloc(&trace->packet_freelist, (void **) pkts, trace->perpkt_thread_count, trace->perpkt_thread_count);
				for (i = 0; i < trace->perpkt_thread_count; i++) {
					pkts[i]->error = READ_TICK;
					trace_packet_set_order(pkts[i], order);
					libtrace_ringbuffer_write(&trace->perpkt_threads[i].rbuffer, pkts[i]);
				}
			}
			pkt_skipped = 0;
		}
	}
hasher_eof:
	/* Broadcast our last failed read to all threads */
	for (i = 0; i < trace->perpkt_thread_count; i++) {
		libtrace_packet_t * bcast;
		if (i == trace->perpkt_thread_count - 1) {
			bcast = packet;
		} else {
			libtrace_ocache_alloc(&trace->packet_freelist, (void **) &bcast, 1, 1);
			bcast->error = packet->error;
		}
		ASSERT_RET(pthread_mutex_lock(&trace->libtrace_lock), == 0);
		if (trace->perpkt_threads[i].state != THREAD_FINISHED) {
			libtrace_ringbuffer_write(&trace->perpkt_threads[i].rbuffer, bcast);
		} else {
			libtrace_ocache_free(&trace->packet_freelist, (void **) &bcast, 1, 1);
		}
		ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
	}

	// We don't need to free the packet
	thread_change_state(trace, t, THREAD_FINISHED, true);

	libtrace_ocache_unregister_thread(&trace->packet_freelist);
	if (trace->format->punregister_thread) {
		trace->format->punregister_thread(trace, t);
	}
	print_memory_stats();

	// TODO remove from TTABLE t sometime
	pthread_exit(NULL);
}

/* Our simplest case when a thread becomes ready it can obtain an exclusive
 * lock to read packets from the underlying trace.
 */
static int trace_pread_packet_first_in_first_served(libtrace_t *libtrace,
                                                    libtrace_thread_t *t,
                                                    libtrace_packet_t *packets[],
                                                    size_t nb_packets) {
	size_t i = 0;
	//bool tick_hit = false;

	ASSERT_RET(pthread_mutex_lock(&libtrace->read_packet_lock), == 0);
	/* Read nb_packets */
	for (i = 0; i < nb_packets; ++i) {
		if (libtrace_message_queue_count(&t->messages) > 0) {
			if ( i==0 ) {
				ASSERT_RET(pthread_mutex_unlock(&libtrace->read_packet_lock), == 0);
				return READ_MESSAGE;
			} else {
				break;
			}
		}
		packets[i]->error = trace_read_packet(libtrace, packets[i]);

		if (packets[i]->error <= 0) {
			/* We'll catch this next time if we have already got packets */
			if ( i==0 ) {
				ASSERT_RET(pthread_mutex_unlock(&libtrace->read_packet_lock), == 0);
				return packets[i]->error;
			} else {
				break;
			}
		}
		/*
		if (libtrace->config.tick_count && trace_packet_get_order(packets[i]) % libtrace->config.tick_count == 0) {
			tick_hit = true;
		}*/

	        // Doing this inside the lock ensures the first packet is
                // always recorded first
                if (!t->recorded_first && packets[0]->error > 0) {
		        store_first_packet(libtrace, packets[0], t);
                }
	}
	ASSERT_RET(pthread_mutex_unlock(&libtrace->read_packet_lock), == 0);
	/* XXX TODO this needs to be inband with packets, or we don't bother in this case
	if (tick_hit) {
		libtrace_message_t tick;
		tick.additional.uint64 = trace_packet_get_order(packets[i]);
		tick.code = MESSAGE_TICK;
		trace_send_message_to_perpkts(libtrace, &tick);
	} */
	return i;
}

/**
 * For the case that we have a dedicated hasher thread
 * 1. We read a packet from our buffer
 * 2. Move that into the packet provided (packet)
 */
inline static int trace_pread_packet_hasher_thread(libtrace_t *libtrace,
                                                   libtrace_thread_t *t,
                                                   libtrace_packet_t *packets[],
                                                   size_t nb_packets) {
	size_t i;

	/* We store the last error message here */
	if (t->format_data) {
		return ((libtrace_packet_t *)t->format_data)->error;
	}

	// Always grab at least one
	if (packets[0]) // Recycle the old get the new
		libtrace_ocache_free(&libtrace->packet_freelist, (void **) packets, 1, 1);
	packets[0] = libtrace_ringbuffer_read(&t->rbuffer);

	if (packets[0]->error <= 0 && packets[0]->error != READ_TICK) {
		return packets[0]->error;
	}

	for (i = 1; i < nb_packets; i++) {
		if (packets[i]) // Recycle the old get the new
			libtrace_ocache_free(&libtrace->packet_freelist, (void **) &packets[i], 1, 1);
		if (!libtrace_ringbuffer_try_read(&t->rbuffer, (void **) &packets[i])) {
			packets[i] = NULL;
			break;
		}

		/* We will return an error or EOF the next time around */
		if (packets[i]->error <= 0 && packets[0]->error != READ_TICK) {
			/* The message case will be checked automatically -
			   However other cases like EOF and error will only be
			   sent once*/
			if (packets[i]->error != READ_MESSAGE) {
				t->format_data = packets[i];
			}
			break;
		}
	}

	return i;
}

/**
 * For the first packet of each queue we keep a copy and note the system
 * time it was received at.
 *
 * This is used for finding the first packet when playing back a trace
 * in trace time. And can be used by real time applications to print
 * results out every XXX seconds.
 */
void store_first_packet(libtrace_t *libtrace, libtrace_packet_t *packet, libtrace_thread_t *t)
{

        libtrace_message_t mesg = {0, {.uint64=0}, NULL};
        struct timeval tv;
        libtrace_packet_t * dup;

        if (t->recorded_first) {
                return;
        }

        if (IS_LIBTRACE_META_PACKET(packet)) {
                return;
        }

        /* We mark system time against a copy of the packet */
        gettimeofday(&tv, NULL);
        dup = trace_copy_packet(packet);

        ASSERT_RET(pthread_spin_lock(&libtrace->first_packets.lock), == 0);
        libtrace->first_packets.packets[t->perpkt_num].packet = dup;
        memcpy(&libtrace->first_packets.packets[t->perpkt_num].tv, &tv, sizeof(tv));
        libtrace->first_packets.count++;

        /* Now update the first */
        if (libtrace->first_packets.count == 1) {
                /* We the first entry hence also the first known packet */
                libtrace->first_packets.first = t->perpkt_num;
        } else {
                /* Check if we are newer than the previous 'first' packet */
                size_t first = libtrace->first_packets.first;
                struct timeval cur_ts = trace_get_timeval(dup);
                struct timeval first_ts = trace_get_timeval(libtrace->first_packets.packets[first].packet);
                if (timercmp(&cur_ts, &first_ts, <))
                        libtrace->first_packets.first = t->perpkt_num;
        }
        ASSERT_RET(pthread_spin_unlock(&libtrace->first_packets.lock), == 0);

        memset(&mesg, 0, sizeof(libtrace_message_t));
        mesg.code = MESSAGE_FIRST_PACKET;
        trace_message_reporter(libtrace, &mesg);
        trace_message_perpkts(libtrace, &mesg);
        t->recorded_first = true;
}

DLLEXPORT int trace_get_first_packet(libtrace_t *libtrace,
                                     libtrace_thread_t *t,
                                     const libtrace_packet_t **packet,
                                     const struct timeval **tv)
{
	void * tmp;
	int ret = 0;

	if (t) {
		if (t->type != THREAD_PERPKT || t->trace != libtrace)
			return -1;
	}

	/* Throw away these which we don't use */
	if (!packet)
		packet = (const libtrace_packet_t **) &tmp;
	if (!tv)
		tv = (const struct timeval **) &tmp;

	ASSERT_RET(pthread_spin_lock(&libtrace->first_packets.lock), == 0);
	if (t) {
		/* Get the requested thread */
		*packet = libtrace->first_packets.packets[t->perpkt_num].packet;
		*tv = &libtrace->first_packets.packets[t->perpkt_num].tv;
	} else if (libtrace->first_packets.count) {
		/* Get the first packet across all threads */
		*packet = libtrace->first_packets.packets[libtrace->first_packets.first].packet;
		*tv = &libtrace->first_packets.packets[libtrace->first_packets.first].tv;
		if (libtrace->first_packets.count == (size_t) libtrace->perpkt_thread_count) {
			ret = 1;
		} else {
			struct timeval curr_tv;
			// If a second has passed since the first entry we will assume this is the very first packet
			gettimeofday(&curr_tv, NULL);
			if (curr_tv.tv_sec > (*tv)->tv_sec) {
				if(curr_tv.tv_usec > (*tv)->tv_usec || curr_tv.tv_sec - (*tv)->tv_sec > 1) {
					ret = 1;
				}
			}
		}
	} else {
		*packet = NULL;
		*tv = NULL;
	}
	ASSERT_RET(pthread_spin_unlock(&libtrace->first_packets.lock), == 0);
	return ret;
}


DLLEXPORT uint64_t tv_to_usec(const struct timeval *tv)
{
	return (uint64_t) tv->tv_sec*1000000ull + (uint64_t) tv->tv_usec;
}

inline static struct timeval usec_to_tv(uint64_t usec)
{
	struct timeval tv;
	tv.tv_sec = usec / 1000000;
	tv.tv_usec = usec % 1000000;
	return tv;
}

/** Similar to delay_tracetime but send messages to all threads periodically */
static void* reporter_entry(void *data) {
	libtrace_message_t message = {0, {.uint64=0}, NULL};
	libtrace_t *trace = (libtrace_t *)data;
	libtrace_thread_t *t = &trace->reporter_thread;

	/* Wait until all threads are started */
	ASSERT_RET(pthread_mutex_lock(&trace->libtrace_lock), == 0);
	if (trace->state == STATE_ERROR) {
		thread_change_state(trace, t, THREAD_FINISHED, false);
		ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
		pthread_exit(NULL);
	}
	ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);

	if (trace->format->pregister_thread) {
		trace->format->pregister_thread(trace, t, false);
	}

	send_message(trace, t, MESSAGE_STARTING, (libtrace_generic_t){0}, t);
	send_message(trace, t, MESSAGE_RESUMING, (libtrace_generic_t){0}, t);

	while (!trace_has_finished(trace)) {
		if (trace->config.reporter_polling) {
			if (libtrace_message_queue_try_get(&t->messages, &message) == LIBTRACE_MQ_FAILED)
				message.code = MESSAGE_POST_REPORTER;
		} else {
			libtrace_message_queue_get(&t->messages, &message);
		}
		switch (message.code) {
			// Check for results
			case MESSAGE_POST_REPORTER:
				trace->combiner.read(trace, &trace->combiner);
				break;
			case MESSAGE_DO_PAUSE:
				if(trace->combiner.pause) {
					trace->combiner.pause(trace, &trace->combiner);
				}
				send_message(trace, t, MESSAGE_PAUSING,
                                                (libtrace_generic_t) {0}, t);
				trace_thread_pause(trace, t);
				send_message(trace, t, MESSAGE_RESUMING,
                                                (libtrace_generic_t) {0}, t);
				break;
		default:
                        send_message(trace, t, message.code, message.data,
                                        message.sender);
		}
	}

	// Flush out whats left now all our threads have finished
	trace->combiner.read_final(trace, &trace->combiner);

	// GOODBYE
        send_message(trace, t, MESSAGE_PAUSING,(libtrace_generic_t) {0}, t);
        send_message(trace, t, MESSAGE_STOPPING,(libtrace_generic_t) {0}, t);

	thread_change_state(trace, &trace->reporter_thread, THREAD_FINISHED, true);
	print_memory_stats();
	pthread_exit(NULL);
}

/** Similar to delay_tracetime but send messages to all threads periodically */
static void* keepalive_entry(void *data) {
	struct timeval prev, next;
	libtrace_message_t message = {0, {.uint64=0}, NULL};
	libtrace_t *trace = (libtrace_t *)data;
	uint64_t next_release;
	libtrace_thread_t *t = &trace->keepalive_thread;

	/* Wait until all threads are started */
	ASSERT_RET(pthread_mutex_lock(&trace->libtrace_lock), == 0);
	if (trace->state == STATE_ERROR) {
		thread_change_state(trace, t, THREAD_FINISHED, false);
		ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
		pthread_exit(NULL);
	}
	ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);

	gettimeofday(&prev, NULL);
        memset(&message, 0, sizeof(libtrace_message_t));
	message.code = MESSAGE_TICK_INTERVAL;

	while (trace->state != STATE_FINISHED) {
		fd_set rfds;
		next_release = tv_to_usec(&prev) + (trace->config.tick_interval * 1000);
		gettimeofday(&next, NULL);
		if (next_release > tv_to_usec(&next)) {
			next = usec_to_tv(next_release - tv_to_usec(&next));
			// Wait for timeout or a message
			FD_ZERO(&rfds);
			FD_SET(libtrace_message_queue_get_fd(&t->messages), &rfds);
			if (select(libtrace_message_queue_get_fd(&t->messages)+1, &rfds, NULL, NULL, &next) == 1) {
				libtrace_message_t msg;
				libtrace_message_queue_get(&t->messages, &msg);
				if (msg.code != MESSAGE_DO_STOP) {
					fprintf(stderr, "Unexpected message code in keepalive_entry()\n");
					pthread_exit(NULL);
				}
				goto done;
			}
		}
		prev = usec_to_tv(next_release);
		if (trace->state == STATE_RUNNING) {
			message.data.uint64 = ((((uint64_t)prev.tv_sec) << 32) +
			                       (((uint64_t)prev.tv_usec << 32)/1000000));
			trace_message_perpkts(trace, &message);
		}
	}
done:

	thread_change_state(trace, t, THREAD_FINISHED, true);
	pthread_exit(NULL);
}

/**
 * Delays a packets playback so the playback will be in trace time.
 * This may break early if a message becomes available.
 *
 * Requires the first packet for this thread to be received.
 * @param libtrace  The trace
 * @param packet    The packet to delay
 * @param t         The current thread
 * @return Either READ_MESSAGE(-2) or 0 is successful
 */
static inline int delay_tracetime(libtrace_t *libtrace, libtrace_packet_t *packet, libtrace_thread_t *t) {
	struct timeval curr_tv, pkt_tv;
	uint64_t next_release = t->tracetime_offset_usec;
	uint64_t curr_usec;

	if (!t->tracetime_offset_usec) {
		const libtrace_packet_t *first_pkt;
		const struct timeval *sys_tv;
		int64_t initial_offset;
		int stable = trace_get_first_packet(libtrace, NULL, &first_pkt, &sys_tv);
                if (!first_pkt)
                        return 0;
		pkt_tv = trace_get_timeval(first_pkt);
		initial_offset = (int64_t)tv_to_usec(sys_tv) - (int64_t)tv_to_usec(&pkt_tv);
		/* In the unlikely case offset is 0, change it to 1 */
		if (stable)
			t->tracetime_offset_usec = initial_offset ? initial_offset: 1;
		next_release = initial_offset;
	}
	/* next_release == offset */
	pkt_tv = trace_get_timeval(packet);
	next_release += tv_to_usec(&pkt_tv);
	gettimeofday(&curr_tv, NULL);
	curr_usec = tv_to_usec(&curr_tv);
	if (next_release > curr_usec) {
		int ret, mesg_fd = libtrace_message_queue_get_fd(&t->messages);
		struct timeval delay_tv = usec_to_tv(next_release-curr_usec);
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(mesg_fd, &rfds);
		// We need to wait
		ret = select(mesg_fd+1, &rfds, NULL, NULL, &delay_tv);
		if (ret == 0) {
			return 0;
		} else if (ret > 0) {
			return READ_MESSAGE;
		} else {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Unexpected return from select in delay_tracetime()");
			return -1;
		}
	}
	return 0;
}

/* Discards packets that don't match the filter.
 * Discarded packets are emptied and then moved to the end of the packet list.
 *
 * @param trace       The trace format, containing the filter
 * @param packets     An array of packets
 * @param nb_packets  The number of valid items in packets
 *
 * @return The number of packets that passed the filter, which are moved to
 *          the start of the packets array
 */
static inline size_t filter_packets(libtrace_t *trace,
                                    libtrace_packet_t **packets,
                                    size_t nb_packets) {
	size_t offset = 0;
	size_t i;

	for (i = 0; i < nb_packets; ++i) {
		// The filter needs the trace attached to receive the link type
		packets[i]->trace = trace;
		if (trace_apply_filter(trace->filter, packets[i])) {
			libtrace_packet_t *tmp;
			tmp = packets[offset];
			packets[offset++] = packets[i];
			packets[i] = tmp;
		} else {
			trace_fin_packet(packets[i]);
		}
	}

	return offset;
}

/* Read a batch of packets from the trace into a buffer.
 * Note that this function will block until a packet is read (or EOF is reached)
 *
 * @param libtrace    The trace
 * @param t           The thread
 * @param packets     An array of packets
 * @param nb_packets  The number of empty packets in packets
 * @return The number of packets read, 0 on EOF (or an error/message -1,-2).
 */
static int trace_pread_packet_wrapper(libtrace_t *libtrace,
                                      libtrace_thread_t *t,
                                      libtrace_packet_t *packets[],
                                      size_t nb_packets) {
	int i;
	if (!libtrace) {
		fprintf(stderr, "NULL trace passed into trace_read_packet()\n");
		return TRACE_ERR_NULL_TRACE;
	}
	if (nb_packets <= 0) {
		trace_set_err(libtrace, TRACE_ERR_NULL,
			"nb_packets must be greater than zero in trace_pread_packet_wrapper()");
		return -1;
	}
	if (trace_is_err(libtrace))
		return -1;
	if (!libtrace->started) {
		trace_set_err(libtrace, TRACE_ERR_BAD_STATE,
		              "You must call libtrace_start() before trace_read_packet()\n");
		return -1;
	}

	if (libtrace->format->pread_packets) {
		int ret;
		for (i = 0; i < (int) nb_packets; ++i) {
			if (!i[packets]) {
				trace_set_err(libtrace, TRACE_ERR_BAD_STATE, "NULL packets in "
					"trace_pread_packet_wrapper()");
				return -1;
			}
			if (!(packets[i]->buf_control==TRACE_CTRL_PACKET ||
			      packets[i]->buf_control==TRACE_CTRL_EXTERNAL)) {
				trace_set_err(libtrace,TRACE_ERR_BAD_STATE,
				              "Packet passed to trace_read_packet() is invalid\n");
				return -1;
			}
                        packets[i]->which_trace_start = libtrace->startcount;
		}
		do {
			ret=libtrace->format->pread_packets(libtrace, t,
			                                    packets,
			                                    nb_packets);
			/* Error, EOF or message? */
			if (ret <= 0) {
				return ret;
			}

			if (libtrace->filter) {
				int remaining;
				remaining = filter_packets(libtrace,
				                           packets, ret);
				t->filtered_packets += ret - remaining;
				ret = remaining;
			}
			for (i = 0; i < ret; ++i) {
				/* We do not mark the packet against the trace,
				 * before hand or after. After breaks DAG meta
				 * packets and before is inefficient */
				//packets[i]->trace = libtrace;
				/* TODO IN FORMAT?? Like traditional libtrace */
				if (libtrace->snaplen>0)
					trace_set_capture_length(packets[i],
							libtrace->snaplen);
			}
		} while(ret == 0);
		return ret;
	}
	trace_set_err(libtrace, TRACE_ERR_UNSUPPORTED,
	              "This format does not support reading packets\n");
	return ~0U;
}

/* Restarts a parallel trace, this is called from trace_pstart.
 * The libtrace lock is held upon calling this function.
 * Typically with a parallel trace the threads are not
 * killed rather.
 */
static int trace_prestart(libtrace_t * libtrace, void *global_blob,
                          libtrace_callback_set_t *per_packet_cbs, 
                          libtrace_callback_set_t *reporter_cbs) {
	int i, err = 0;
	if (libtrace->state != STATE_PAUSED) {
		trace_set_err(libtrace, TRACE_ERR_BAD_STATE,
			"trace(%s) is not currently paused",
		              libtrace->uridata);
		return -1;
	}

	if (!libtrace_parallel) {
		trace_set_err(libtrace, TRACE_ERR_THREAD, "Trace_prestart() has been called on a "
			"non-parallel libtrace input?");
		return -1;
	}
	if (libtrace->perpkt_thread_states[THREAD_RUNNING]) {
		trace_set_err(libtrace, TRACE_ERR_THREAD, "Cannot restart a parallel libtrace input "
			"while it is still running");
		return -1;
	}

	/* Reset first packets */
	pthread_spin_lock(&libtrace->first_packets.lock);
	for (i = 0; i < libtrace->perpkt_thread_count; ++i) {
		if (libtrace->first_packets.packets[i].packet) {
			trace_destroy_packet(libtrace->first_packets.packets[i].packet);
			libtrace->first_packets.packets[i].packet = NULL;
			libtrace->first_packets.packets[i].tv.tv_sec = 0;
			libtrace->first_packets.packets[i].tv.tv_usec = 0;
			libtrace->first_packets.count--;
			libtrace->perpkt_threads[i].recorded_first = false;
		}
	}
	if (libtrace->first_packets.count != 0) {
		trace_set_err(libtrace, TRACE_ERR_THREAD, "Expected a first packets count of 0 in trace_pstart()");
		return -1;
	}
	libtrace->first_packets.first = 0;
	pthread_spin_unlock(&libtrace->first_packets.lock);

	/* Reset delay */
	for (i = 0; i < libtrace->perpkt_thread_count; ++i) {
		libtrace->perpkt_threads[i].tracetime_offset_usec = 0;
	}

	/* Reset statistics */
	for (i = 0; i < libtrace->perpkt_thread_count; ++i) {
		libtrace->perpkt_threads[i].accepted_packets = 0;
		libtrace->perpkt_threads[i].filtered_packets = 0;
	}
	libtrace->accepted_packets = 0;
	libtrace->filtered_packets = 0;

	/* Update functions if requested */
	if(global_blob)
		libtrace->global_blob = global_blob;

        if (per_packet_cbs) {
                if (libtrace->perpkt_cbs)
                        trace_destroy_callback_set(libtrace->perpkt_cbs);
                libtrace->perpkt_cbs = trace_create_callback_set();
                memcpy(libtrace->perpkt_cbs, per_packet_cbs, 
                                sizeof(libtrace_callback_set_t));
        }

        if (reporter_cbs) {
                if (libtrace->reporter_cbs)
                        trace_destroy_callback_set(libtrace->reporter_cbs);

                libtrace->reporter_cbs = trace_create_callback_set();
                memcpy(libtrace->reporter_cbs, reporter_cbs,
                                sizeof(libtrace_callback_set_t));
        }

	if (trace_is_parallel(libtrace)) {
		err = libtrace->format->pstart_input(libtrace);
	} else {
		if (libtrace->format->start_input) {
			err = libtrace->format->start_input(libtrace);
		}
	}

	if (err == 0) {
		libtrace->started = true;
                libtrace->startcount ++;
		libtrace_change_state(libtrace, STATE_RUNNING, false);
	}
	return err;
}

/**
 * @return the number of CPU cores on the machine. -1 if unknown.
 */
SIMPLE_FUNCTION static int get_nb_cores() {
	int numCPU;
#ifdef _SC_NPROCESSORS_ONLN
	/* Most systems do this now */
	numCPU = sysconf(_SC_NPROCESSORS_ONLN);

#else
	int mib[] = {CTL_HW, HW_AVAILCPU};
	size_t len = sizeof(numCPU);

	/* get the number of CPUs from the system */
	sysctl(mib, 2, &numCPU, &len, NULL, 0);
#endif
	return numCPU <= 0 ? 1 : numCPU;
}

/**
 * Verifies the configuration and sets default values for any values not
 * specified by the user.
 */
static void verify_configuration(libtrace_t *libtrace) {

	if (libtrace->config.hasher_queue_size <= 0)
		libtrace->config.hasher_queue_size = 1000;

	if (libtrace->config.perpkt_threads <= 0) {
		libtrace->perpkt_thread_count = get_nb_cores();
		if (libtrace->perpkt_thread_count <= 0)
			// Lets just use one
			libtrace->perpkt_thread_count = 1;
	} else {
		libtrace->perpkt_thread_count = libtrace->config.perpkt_threads;
	}

	if (libtrace->config.reporter_thold <= 0)
		libtrace->config.reporter_thold = 100;
	if (libtrace->config.burst_size <= 0)
		libtrace->config.burst_size = 32;
	if (libtrace->config.thread_cache_size <= 0)
		libtrace->config.thread_cache_size = 64;
	if (libtrace->config.cache_size <= 0)
		libtrace->config.cache_size = (libtrace->config.hasher_queue_size + 1) * libtrace->perpkt_thread_count;

	if (libtrace->config.cache_size <
		(libtrace->config.hasher_queue_size + 1) * libtrace->perpkt_thread_count)
		fprintf(stderr, "WARNING deadlocks may occur and extra memory allocating buffer sizes (packet_freelist_size) mismatched\n");

	if (libtrace->combiner.initialise == NULL && libtrace->combiner.publish == NULL)
		libtrace->combiner = combiner_unordered;

	/* Figure out if we are using a dedicated hasher thread? */
	if (libtrace->hasher && libtrace->perpkt_thread_count > 1) {
		libtrace->hasher_thread.type = THREAD_HASHER;
	}
}

/**
 * Starts a libtrace_thread, including allocating memory for messaging.
 * Threads are expected to wait until the libtrace look is released.
 * Hence why we don't init structures until later.
 *
 * @param trace The trace the thread is associated with
 * @param t The thread that is filled when the thread is started
 * @param type The type of thread
 * @param start_routine The entry location of the thread
 * @param perpkt_num The perpkt thread number (should be set -1 if not perpkt)
 * @param name For debugging purposes set the threads name (Optional)
 *
 * @return 0 on success or -1 upon error in which case the libtrace error is set.
 *         In this situation the thread structure is zeroed.
 */
static int trace_start_thread(libtrace_t *trace,
                       libtrace_thread_t *t,
                       enum thread_types type,
                       void *(*start_routine) (void *),
                       int perpkt_num,
                       const char *name) {
#ifdef __linux__
	cpu_set_t cpus;
	int i;
#endif
	int ret;
	if (t->type != THREAD_EMPTY) {
		trace_set_err(trace, TRACE_ERR_THREAD,
			"Expected thread type of THREAD_EMPTY in trace_start_thread()");
		return -1;
	}
	t->trace = trace;
	t->ret = NULL;
	t->user_data = NULL;
	t->type = type;
	t->state = THREAD_RUNNING;

	if (!name) {
		trace_set_err(trace, TRACE_ERR_THREAD, "NULL thread name in trace_start_thread()");
		return -1;
	}

#ifdef __linux__
	CPU_ZERO(&cpus);
	for (i = 0; i < get_nb_cores(); i++)
		CPU_SET(i, &cpus);

	ret = pthread_create(&t->tid, NULL, start_routine, (void *) trace);
	if( ret == 0 ) {
		ret = pthread_setaffinity_np(t->tid, sizeof(cpus), &cpus);
	}

#else
	ret = pthread_create(&t->tid, NULL, start_routine, (void *) trace);
#endif
	if (ret != 0) {
		libtrace_zero_thread(t);
		trace_set_err(trace, ret, "Failed to create a thread of type=%d\n", type);
		return -1;
	}
	libtrace_message_queue_init(&t->messages, sizeof(libtrace_message_t));
	if (trace_has_dedicated_hasher(trace) && type == THREAD_PERPKT) {
		libtrace_ringbuffer_init(&t->rbuffer,
		                         trace->config.hasher_queue_size,
		                         trace->config.hasher_polling?
		                                 LIBTRACE_RINGBUFFER_POLLING:
		                                 LIBTRACE_RINGBUFFER_BLOCKING);
	}
#if defined(HAVE_PTHREAD_SETNAME_NP) && defined(__linux__)
	if(name)
		pthread_setname_np(t->tid, name);
#endif
	t->perpkt_num = perpkt_num;
	return 0;
}

/** Parses the environment variable LIBTRACE_CONF into the supplied
 * configuration structure.
 *
 * @param[in,out] libtrace The trace from which we determine the URI and set
 * the configuration.
 *
 * We search for 3 environment variables and apply them to the config in the
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
 * @note All environment variables names MUST only contian
 * [A-Z], [0-9] and [_] (underscore) and not start with a number. Any characters
 * outside of this range should be captilised if possible or replaced with an
 * underscore.
 */
static void parse_env_config (libtrace_t *libtrace) {
	char env_name[1024] = "LIBTRACE_CONF_";
	size_t len = strlen(env_name);
	size_t mark = 0;
	size_t i;
	char * env;

	/* Make our compound string */
	strncpy(&env_name[len], libtrace->format->name, sizeof(env_name) - len);
	len += strlen(libtrace->format->name);
	strncpy(&env_name[len], ":", sizeof(env_name) - len);
	len += 1;
	strncpy(&env_name[len], libtrace->uridata, sizeof(env_name) - len);

	/* env names are allowed to be A-Z (CAPS) 0-9 and _ */
	for (i = 0; env_name[i] != 0; ++i) {
		env_name[i] = toupper(env_name[i]);
		if(env_name[i] == ':') {
			mark = i;
		}
		if (!( (env_name[i] >= 'A' && env_name[i] <= 'Z') ||
		       (env_name[i] >= '0' && env_name[i] <= '9') )) {
			env_name[i] = '_';
		}
	}

	/* First apply global env settings LIBTRACE_CONF */
	env = getenv("LIBTRACE_CONF");
	if (env)
	{
		printf("Got env %s", env);
		trace_set_configuration(libtrace, env);
	}

	/* Then format settings LIBTRACE_CONF_<FORMAT> */
	if (mark != 0) {
		env_name[mark] = 0;
		env = getenv(env_name);
		if (env) {
			trace_set_configuration(libtrace, env);
		}
		env_name[mark] = '_';
	}

	/* Finally this specific trace LIBTRACE_CONF_<FORMAT_URI> */
	env = getenv(env_name);
	if (env) {
		trace_set_configuration(libtrace, env);
	}
}

DLLEXPORT bool trace_is_parallel(libtrace_t * libtrace) {
	if (libtrace->state == STATE_NEW)
		return trace_supports_parallel(libtrace);
	return libtrace->pread == trace_pread_packet_wrapper;
}

DLLEXPORT int trace_pstart(libtrace_t *libtrace, void* global_blob,
                           libtrace_callback_set_t *per_packet_cbs,
                           libtrace_callback_set_t *reporter_cbs) {
	int i;
	int ret = -1;
	char name[24];
	sigset_t sig_before, sig_block_all;
	if (!libtrace) {
		fprintf(stderr, "NULL trace passed to trace_pstart()\n");
		return -1;
	}

	ASSERT_RET(pthread_mutex_lock(&libtrace->libtrace_lock), == 0);
	if (trace_is_err(libtrace)) {
		goto cleanup_none;
	}

	if (libtrace->state == STATE_PAUSED) {
		ret = trace_prestart(libtrace, global_blob, per_packet_cbs, 
                                reporter_cbs);
		ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);
		return ret;
	}

	if (libtrace->state != STATE_NEW) {
		trace_set_err(libtrace, TRACE_ERR_BAD_STATE, "trace_pstart "
		              "should be called on a NEW or PAUSED trace but "
		              "instead was called from %s",
		              get_trace_state_name(libtrace->state));
		goto cleanup_none;
	}

	/* Store the user defined things against the trace */
	libtrace->global_blob = global_blob;

        /* Save a copy of the callbacks in case the user tries to change them
         * on us later */
        if (!per_packet_cbs) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "trace_pstart "
                                "requires a non-NULL set of per packet "
                                "callbacks.");
                goto cleanup_none;
        }

        if (per_packet_cbs->message_packet == NULL) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "The per "
                                "packet callbacks must include a handler "
                                "for a packet. Please set this using "
                                "trace_set_packet_cb().");
                goto cleanup_none;
        }

        libtrace->perpkt_cbs = trace_create_callback_set();
        memcpy(libtrace->perpkt_cbs, per_packet_cbs, sizeof(libtrace_callback_set_t));
        
        if (reporter_cbs) {
                libtrace->reporter_cbs = trace_create_callback_set();
                memcpy(libtrace->reporter_cbs, reporter_cbs, sizeof(libtrace_callback_set_t));
        }

        


	/* And zero other fields */
	for (i = 0; i < THREAD_STATE_MAX; ++i) {
		libtrace->perpkt_thread_states[i] = 0;
	}
	libtrace->first_packets.first = 0;
	libtrace->first_packets.count = 0;
	libtrace->first_packets.packets = NULL;
	libtrace->perpkt_threads = NULL;
	/* Set a global which says we are using a parallel trace. This is
	 * for backwards compatibility due to changes when destroying packets */
	libtrace_parallel = 1;

	/* Parses configuration passed through environment variables */
	parse_env_config(libtrace);
	verify_configuration(libtrace);

	ret = -1;
	/* Try start the format - we prefer parallel over single threaded, as
	 * these formats should support messages better */

	if (trace_supports_parallel(libtrace) &&
	    !trace_has_dedicated_hasher(libtrace)) {
		ret = libtrace->format->pstart_input(libtrace);
		libtrace->pread = trace_pread_packet_wrapper;
	}
	if (ret != 0) {
		if (libtrace->format->start_input) {
			ret = libtrace->format->start_input(libtrace);
		}
		if (libtrace->perpkt_thread_count > 1) {
			libtrace->pread = trace_pread_packet_first_in_first_served;
			/* Don't wait for a burst of packets if the format is
			 * live as this could block ring based formats and
			 * introduces delay. */
			if (libtrace->format->info.live) {
				libtrace->config.burst_size = 1;
			}
		}
		else {
			/* Use standard read_packet */
			libtrace->pread = NULL;
		}
	}

	if (ret < 0) {
		goto cleanup_none;
	}

	/* --- Start all the threads we need --- */
	/* Disable signals because it is inherited by the threads we start */
	sigemptyset(&sig_block_all);
	ASSERT_RET(pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before), == 0);

	/* If we need a hasher thread start it
	 * Special Case: If single threaded we don't need a hasher
	 */
	if (trace_has_dedicated_hasher(libtrace)) {
		libtrace->hasher_thread.type = THREAD_EMPTY;
		ret = trace_start_thread(libtrace, &libtrace->hasher_thread,
		                   THREAD_HASHER, hasher_entry, -1,
		                   "hasher-thread");
		if (ret != 0)
			goto cleanup_started;
		libtrace->pread = trace_pread_packet_hasher_thread;
	} else {
		libtrace->hasher_thread.type = THREAD_EMPTY;
	}

	/* Start up our perpkt threads */
	libtrace->perpkt_threads = calloc(sizeof(libtrace_thread_t),
	                                  libtrace->perpkt_thread_count);
	if (!libtrace->perpkt_threads) {
		trace_set_err(libtrace, errno, "trace_pstart "
		              "failed to allocate memory.");
		goto cleanup_threads;
	}
	for (i = 0; i < libtrace->perpkt_thread_count; i++) {
		snprintf(name, sizeof(name), "perpkt-%d", i);
		libtrace_zero_thread(&libtrace->perpkt_threads[i]);
		ret = trace_start_thread(libtrace, &libtrace->perpkt_threads[i],
		                   THREAD_PERPKT, perpkt_threads_entry, i,
		                   name);
		if (ret != 0)
			goto cleanup_threads;
	}

	/* Start the reporter thread */
	if (reporter_cbs) {
		if (libtrace->combiner.initialise)
			libtrace->combiner.initialise(libtrace, &libtrace->combiner);
		ret = trace_start_thread(libtrace, &libtrace->reporter_thread,
		                   THREAD_REPORTER, reporter_entry, -1,
		                   "reporter_thread");
		if (ret != 0)
			goto cleanup_threads;
	}

	/* Start the keepalive thread */
	if (libtrace->config.tick_interval > 0) {
		ret = trace_start_thread(libtrace, &libtrace->keepalive_thread,
		                   THREAD_KEEPALIVE, keepalive_entry, -1,
		                   "keepalive_thread");
		if (ret != 0)
			goto cleanup_threads;
	}

	/* Init other data structures */
	libtrace->perpkt_thread_states[THREAD_RUNNING] = libtrace->perpkt_thread_count;
	ASSERT_RET(pthread_spin_init(&libtrace->first_packets.lock, 0), == 0);
	libtrace->first_packets.packets = calloc(libtrace->perpkt_thread_count,
	                                         sizeof(*libtrace->first_packets.packets));
	if (libtrace->first_packets.packets == NULL) {
		trace_set_err(libtrace, errno, "trace_pstart "
		              "failed to allocate memory.");
		goto cleanup_threads;
	}

	if (libtrace_ocache_init(&libtrace->packet_freelist,
	                     (void* (*)()) trace_create_packet,
	                     (void (*)(void *))trace_destroy_packet,
	                     libtrace->config.thread_cache_size,
	                     libtrace->config.cache_size * 4,
	                     libtrace->config.fixed_count) != 0) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "trace_pstart "
		              "failed to allocate ocache.");
		goto cleanup_threads;
	}

	/* Threads don't start */
	libtrace->started = true;
        libtrace->startcount ++;
	libtrace_change_state(libtrace, STATE_RUNNING, false);

	ret = 0;
	goto success;
cleanup_threads:
	if (libtrace->first_packets.packets) {
		free(libtrace->first_packets.packets);
		libtrace->first_packets.packets = NULL;
	}
	libtrace_change_state(libtrace, STATE_ERROR, false);
	ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);
	if (libtrace->hasher_thread.type == THREAD_HASHER) {
		pthread_join(libtrace->hasher_thread.tid, NULL);
		libtrace_zero_thread(&libtrace->hasher_thread);
	}

	if (libtrace->perpkt_threads) {
		for (i = 0; i < libtrace->perpkt_thread_count; i++) {
			if (libtrace->perpkt_threads[i].type == THREAD_PERPKT) {
				pthread_join(libtrace->perpkt_threads[i].tid, NULL);
				libtrace_zero_thread(&libtrace->perpkt_threads[i]);
			} else break;
		}
		free(libtrace->perpkt_threads);
		libtrace->perpkt_threads = NULL;
	}

	if (libtrace->reporter_thread.type == THREAD_REPORTER) {
		pthread_join(libtrace->reporter_thread.tid, NULL);
		libtrace_zero_thread(&libtrace->reporter_thread);
	}

	if (libtrace->keepalive_thread.type == THREAD_KEEPALIVE) {
		pthread_join(libtrace->keepalive_thread.tid, NULL);
		libtrace_zero_thread(&libtrace->keepalive_thread);
	}
	ASSERT_RET(pthread_mutex_lock(&libtrace->libtrace_lock), == 0);
	libtrace_change_state(libtrace, STATE_NEW, false);
	if (libtrace->perpkt_thread_states[THREAD_RUNNING] != 0) {
		trace_set_err(libtrace, TRACE_ERR_THREAD, "Expected 0 running threads in trace_pstart()");
		return -1;
	}
	libtrace->perpkt_thread_states[THREAD_FINISHED] = 0;
cleanup_started:
	if (libtrace->pread == trace_pread_packet_wrapper) {
		if (libtrace->format->ppause_input)
			libtrace->format->ppause_input(libtrace);
	} else {
		if (libtrace->format->pause_input)
			libtrace->format->pause_input(libtrace);
	}
	ret = -1;
success:
	ASSERT_RET(pthread_sigmask(SIG_SETMASK, &sig_before, NULL), == 0);
cleanup_none:
	ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);
	return ret;
}

DLLEXPORT int trace_set_starting_cb(libtrace_callback_set_t *cbset,
                fn_cb_starting handler) {
	cbset->message_starting = handler;
	return 0;
}

DLLEXPORT int trace_set_pausing_cb(libtrace_callback_set_t *cbset,
                fn_cb_dataless handler) {
	cbset->message_pausing = handler;
	return 0;
}

DLLEXPORT int trace_set_resuming_cb(libtrace_callback_set_t *cbset,
                fn_cb_dataless handler) {
	cbset->message_resuming = handler;
	return 0;
}

DLLEXPORT int trace_set_stopping_cb(libtrace_callback_set_t *cbset,
                fn_cb_dataless handler) {
	cbset->message_stopping = handler;
	return 0;
}

DLLEXPORT int trace_set_packet_cb(libtrace_callback_set_t *cbset,
                fn_cb_packet handler) {
	cbset->message_packet = handler;
	return 0;
}

DLLEXPORT int trace_set_first_packet_cb(libtrace_callback_set_t *cbset,
                fn_cb_first_packet handler) {
	cbset->message_first_packet = handler;
	return 0;
}

DLLEXPORT int trace_set_tick_count_cb(libtrace_callback_set_t *cbset,
                fn_cb_tick handler) {
	cbset->message_tick_count = handler;
	return 0;
}

DLLEXPORT int trace_set_tick_interval_cb(libtrace_callback_set_t *cbset,
                fn_cb_tick handler) {
	cbset->message_tick_interval = handler;
	return 0;
}

DLLEXPORT int trace_set_result_cb(libtrace_callback_set_t *cbset,
                fn_cb_result handler) {
	cbset->message_result = handler;
	return 0;
}

DLLEXPORT int trace_set_user_message_cb(libtrace_callback_set_t *cbset,
                fn_cb_usermessage handler) {
	cbset->message_user = handler;
	return 0;
}

/*
 * Pauses a trace, this should only be called by the main thread
 * 1. Set started = false
 * 2. All perpkt threads are paused waiting on a condition var
 * 3. Then call ppause on the underlying format if found
 * 4. The traces state is paused
 *
 * Once done you should be able to modify the trace setup and call pstart again
 * TODO add support to change the number of threads.
 */
DLLEXPORT int trace_ppause(libtrace_t *libtrace)
{
	libtrace_thread_t *t;
	int i;
	if (!libtrace) {
		fprintf(stderr, "NULL trace passed into trace_ppause()\n");
		return TRACE_ERR_NULL_TRACE;
	}

	t = get_thread_table(libtrace);
	// Check state from within the lock if we are going to change it
	ASSERT_RET(pthread_mutex_lock(&libtrace->libtrace_lock), == 0);

        /* If we are already paused, just treat this as a NOOP */
        if (libtrace->state == STATE_PAUSED) {
		ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);
                return 0;
        }
	if (!libtrace->started || libtrace->state != STATE_RUNNING) {
		ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);
		trace_set_err(libtrace,TRACE_ERR_BAD_STATE, "You must call trace_start() before calling trace_ppause()");
		return -1;
	}

	libtrace_change_state(libtrace, STATE_PAUSING, false);
	ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);

	// Special case handle the hasher thread case
	if (trace_has_dedicated_hasher(libtrace)) {
		if (libtrace->config.debug_state)
			fprintf(stderr, "Hasher thread is running, asking it to pause ...");
		libtrace_message_t message = {0, {.uint64=0}, NULL};
		message.code = MESSAGE_DO_PAUSE;
		trace_message_thread(libtrace, &libtrace->hasher_thread, &message);
		// Wait for it to pause
		ASSERT_RET(pthread_mutex_lock(&libtrace->libtrace_lock), == 0);
		while (libtrace->hasher_thread.state == THREAD_RUNNING) {
			ASSERT_RET(pthread_cond_wait(&libtrace->perpkt_cond, &libtrace->libtrace_lock), == 0);
		}
		ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);
		if (libtrace->config.debug_state)
			fprintf(stderr, " DONE\n");
	}

	if (libtrace->config.debug_state)
		fprintf(stderr, "Asking perpkt threads to pause ...");
	// Stop threads, skip this one if it's a perpkt
	for (i = 0; i < libtrace->perpkt_thread_count; i++) {
		if (&libtrace->perpkt_threads[i] != t) {
			libtrace_message_t message = {0, {.uint64=0}, NULL};
			message.code = MESSAGE_DO_PAUSE;
			ASSERT_RET(trace_message_thread(libtrace, &libtrace->perpkt_threads[i], &message), != -1);
			if(trace_has_dedicated_hasher(libtrace)) {
				// The hasher has stopped and other threads have messages waiting therefore
				// If the queues are empty the other threads would have no data
				// So send some message packets to simply ask the threads to check
				// We are the only writer since hasher has paused
				libtrace_packet_t *pkt;
				libtrace_ocache_alloc(&libtrace->packet_freelist, (void **) &pkt, 1, 1);
				pkt->error = READ_MESSAGE;
				libtrace_ringbuffer_write(&libtrace->perpkt_threads[i].rbuffer, pkt);
			}
		} else {
			fprintf(stderr, "Mapper threads should not be used to pause a trace this could cause any number of problems!!\n");
		}
	}

	if (t) {
		// A perpkt is doing the pausing, interesting, fake an extra thread paused
		// We rely on the user to *not* return before starting the trace again
		thread_change_state(libtrace, t, THREAD_PAUSED, true);
	}

	// Wait for all threads to pause
	ASSERT_RET(pthread_mutex_lock(&libtrace->libtrace_lock), == 0);
	while(libtrace->perpkt_thread_states[THREAD_RUNNING]) {
		ASSERT_RET(pthread_cond_wait(&libtrace->perpkt_cond, &libtrace->libtrace_lock), == 0);
	}
	ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);

	if (libtrace->config.debug_state)
		fprintf(stderr, " DONE\n");

	// Deal with the reporter
	if (trace_has_reporter(libtrace)) {
		if (libtrace->config.debug_state)
			fprintf(stderr, "Reporter thread is running, asking it to pause ...");
		if (pthread_equal(pthread_self(), libtrace->reporter_thread.tid)) {
                        libtrace->combiner.pause(libtrace, &libtrace->combiner);
                        thread_change_state(libtrace, &libtrace->reporter_thread, THREAD_PAUSED, true);
                
                } else {
			libtrace_message_t message = {0, {.uint64=0}, NULL};
                        message.code = MESSAGE_DO_PAUSE;
                        trace_message_thread(libtrace, &libtrace->reporter_thread, &message);
                        // Wait for it to pause
                        ASSERT_RET(pthread_mutex_lock(&libtrace->libtrace_lock), == 0);
                        while (libtrace->reporter_thread.state == THREAD_RUNNING) {
                                ASSERT_RET(pthread_cond_wait(&libtrace->perpkt_cond, &libtrace->libtrace_lock), == 0);
                        }
                        ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);
                }
		if (libtrace->config.debug_state)
			fprintf(stderr, " DONE\n");
	}

	/* Cache values before we pause */
	if (libtrace->stats == NULL)
		libtrace->stats = trace_create_statistics();
	// Save the statistics against the trace
	trace_get_statistics(libtrace, NULL);
	if (trace_is_parallel(libtrace)) {
		libtrace->started = false;
		if (libtrace->format->ppause_input)
			libtrace->format->ppause_input(libtrace);
		// TODO What happens if we don't have pause input??
	} else {
		int err;
		err = trace_pause(libtrace);
		// We should handle this a bit better
		if (err)
			return err;
	}

	// Only set as paused after the pause has been called on the trace
	libtrace_change_state(libtrace, STATE_PAUSED, true);
	return 0;
}

/**
 * Stop trace finish prematurely as though it meet an EOF
 * This should only be called by the main thread
 * 1. Calls ppause
 * 2. Sends a message asking for threads to finish
 * 3. Releases threads which will pause
 */
DLLEXPORT int trace_pstop(libtrace_t *libtrace)
{
	int i, err;
	libtrace_message_t message = {0, {.uint64=0}, NULL};
	if (!libtrace) {
		fprintf(stderr, "NULL trace passed into trace_pstop()\n");
		return TRACE_ERR_NULL_TRACE;
	}

	// Ensure all threads have paused and the underlying trace format has
	// been closed and all packets associated are cleaned up
	// Pause will do any state checks for us
	err = trace_ppause(libtrace);
	if (err)
		return err;

	// Now send a message asking the threads to stop
	// This will be retrieved before trying to read another packet
	message.code = MESSAGE_DO_STOP;
	trace_message_perpkts(libtrace, &message);
	if (trace_has_dedicated_hasher(libtrace))
		trace_message_thread(libtrace, &libtrace->hasher_thread, &message);

	for (i = 0; i < libtrace->perpkt_thread_count; i++) {
		trace_message_thread(libtrace, &libtrace->perpkt_threads[i], &message);
	}

	/* Now release the threads and let them stop - when the threads finish
	 * the state will be set to finished */
	libtrace_change_state(libtrace, STATE_FINISHING, true);
	return 0;
}

DLLEXPORT int trace_set_hasher(libtrace_t *trace, enum hasher_types type, fn_hasher hasher, void *data) {
	int ret = -1;
	if ((type == HASHER_CUSTOM && !hasher) || (type == HASHER_BALANCE && hasher)) {
		return -1;
	}

	// Save the requirements
	trace->hasher_type = type;
	if (hasher) {
                if (trace->hasher_owner == HASH_OWNED_LIBTRACE) {
                        if (trace->hasher_data) {
                                free(trace->hasher_data);
                        }
                }
		trace->hasher = hasher;
		trace->hasher_data = data;
                trace->hasher_owner = HASH_OWNED_EXTERNAL;
	} else {
		trace->hasher = NULL;
		trace->hasher_data = NULL;
                trace->hasher_owner = HASH_OWNED_LIBTRACE;
	}

	// Try push this to hardware - NOTE hardware could do custom if
	// there is a more efficient way to apply it, in this case
	// it will simply grab the function out of libtrace_t
	if (trace_supports_parallel(trace) && trace->format->config_input)
		ret = trace->format->config_input(trace, TRACE_OPTION_HASHER, &type);

	if (ret == -1) {
                libtrace_err_t err UNUSED;

		/* We have to deal with this ourself */
                /* If we succeed, clear any error state otherwise our caller
                 * might assume an error occurred, even though we've resolved
                 * the issue ourselves.
                 */
		if (!hasher) {
			switch (type)
			{
				case HASHER_CUSTOM:
				case HASHER_BALANCE:
                                        err = trace_get_err(trace);
					return 0;
				case HASHER_BIDIRECTIONAL:
					trace->hasher = (fn_hasher) toeplitz_hash_packet;
					trace->hasher_data = calloc(1, sizeof(toeplitz_conf_t));
					toeplitz_init_config(trace->hasher_data, 1);
                                        err = trace_get_err(trace);
					return 0;
				case HASHER_UNIDIRECTIONAL:
					trace->hasher = (fn_hasher) toeplitz_hash_packet;
					trace->hasher_data = calloc(1, sizeof(toeplitz_conf_t));
					toeplitz_init_config(trace->hasher_data, 0);
                                        err = trace_get_err(trace);
					return 0;
			}
			return -1;
		}
	} else {
		/* If the hasher is hardware we zero out the hasher and hasher
		 * data fields - only if we need a hasher do we do this */
		trace->hasher = NULL;
		trace->hasher_data = NULL;
	}

	return 0;
}

// Waits for all threads to finish
DLLEXPORT void trace_join(libtrace_t *libtrace) {
	int i;

	/* Firstly wait for the perpkt threads to finish, since these are
	 * user controlled */
	for (i=0; i< libtrace->perpkt_thread_count; i++) {
		ASSERT_RET(pthread_join(libtrace->perpkt_threads[i].tid, NULL), == 0);
		// So we must do our best effort to empty the queue - so
		// the producer (or any other threads) don't block.
		libtrace_packet_t * packet;
		if (libtrace->perpkt_threads[i].state != THREAD_FINISHED) {
			trace_set_err(libtrace, TRACE_ERR_THREAD_STATE,
				"Expected processing thread state to be THREAD_FINISHED in trace_join()");
			return;
		}
		while(libtrace_ringbuffer_try_read(&libtrace->perpkt_threads[i].rbuffer, (void **) &packet))
			if (packet) // This could be NULL iff the perpkt finishes early
				trace_destroy_packet(packet);
	}

	/* Now the hasher */
	if (trace_has_dedicated_hasher(libtrace)) {
		pthread_join(libtrace->hasher_thread.tid, NULL);
		if (libtrace->hasher_thread.state != THREAD_FINISHED) {
			trace_set_err(libtrace, TRACE_ERR_THREAD_STATE,
				"Expected hasher thread state to be THREAD_FINISHED in trace_join()");
			return;
		}
	}

	// Now that everything is finished nothing can be touching our
	// buffers so clean them up
	for (i = 0; i < libtrace->perpkt_thread_count; i++) {
		// Its possible 1 packet got added by the reporter (or 1 per any other thread) since we cleaned up
		// if they lost timeslice before-during a write
		libtrace_packet_t * packet;
		while(libtrace_ringbuffer_try_read(&libtrace->perpkt_threads[i].rbuffer, (void **) &packet))
			trace_destroy_packet(packet);
		if (trace_has_dedicated_hasher(libtrace)) {
			if (!libtrace_ringbuffer_is_empty(&libtrace->perpkt_threads[i].rbuffer)) {
				trace_set_err(libtrace, TRACE_ERR_THREAD,
					"Expected processing threads ring buffers to be empty in trace_join()");
				return;
			}
			libtrace_ringbuffer_destroy(&libtrace->perpkt_threads[i].rbuffer);
		}
		// Cannot destroy vector yet, this happens with trace_destroy
	}

	if (trace_has_reporter(libtrace)) {
		pthread_join(libtrace->reporter_thread.tid, NULL);
		if (libtrace->reporter_thread.state != THREAD_FINISHED) {
			trace_set_err(libtrace, TRACE_ERR_THREAD_STATE,
				"Expected reporting thread state to be THREAD_FINISHED in trace_join()");
			return;
		}
	}

	// Wait for the tick (keepalive) thread if it has been started
	if (libtrace->keepalive_thread.type == THREAD_KEEPALIVE) {
		libtrace_message_t msg = {0, {.uint64=0}, NULL};
		msg.code = MESSAGE_DO_STOP;
		trace_message_thread(libtrace, &libtrace->keepalive_thread, &msg);
		pthread_join(libtrace->keepalive_thread.tid, NULL);
	}

	libtrace_change_state(libtrace, STATE_JOINED, true);
	print_memory_stats();
}

DLLEXPORT int libtrace_thread_get_message_count(libtrace_t * libtrace,
                                                libtrace_thread_t *t)
{
	int ret;
	if (t == NULL)
		t = get_thread_descriptor(libtrace);
	if (t == NULL)
		return -1;
	ret = libtrace_message_queue_count(&t->messages);
	return ret < 0 ? 0 : ret;
}

DLLEXPORT int libtrace_thread_get_message(libtrace_t * libtrace,
                                          libtrace_thread_t *t,
                                          libtrace_message_t * message)
{
	int ret;
	if (t == NULL)
		t = get_thread_descriptor(libtrace);
	if (t == NULL)
		return -1;
	ret = libtrace_message_queue_get(&t->messages, message);
	return ret < 0 ? 0 : ret;
}

DLLEXPORT int libtrace_thread_try_get_message(libtrace_t * libtrace,
                                              libtrace_thread_t *t,
                                              libtrace_message_t * message)
{
	if (t == NULL)
		t = get_thread_descriptor(libtrace);
	if (t == NULL)
		return -1;
	if (libtrace_message_queue_try_get(&t->messages, message) != LIBTRACE_MQ_FAILED)
		return 0;
	else
		return -1;
}

DLLEXPORT int trace_message_thread(libtrace_t * libtrace, libtrace_thread_t *t, libtrace_message_t * message)
{
	int ret;
	if (!message->sender)
		message->sender = get_thread_descriptor(libtrace);

	ret = libtrace_message_queue_put(&t->messages, message);
	return ret < 0 ? 0 : ret;
}

DLLEXPORT int trace_message_reporter(libtrace_t * libtrace, libtrace_message_t * message)
{
	if (!trace_has_reporter(libtrace) ||
	    !(libtrace->reporter_thread.state == THREAD_RUNNING
	      || libtrace->reporter_thread.state == THREAD_PAUSED))
		return -1;

	return trace_message_thread(libtrace, &libtrace->reporter_thread, message);
}

DLLEXPORT int trace_post_reporter(libtrace_t *libtrace)
{
	libtrace_message_t message = {0, {.uint64=0}, NULL};
	message.code = MESSAGE_POST_REPORTER;
	return trace_message_reporter(libtrace, (void *) &message);
}

DLLEXPORT int trace_message_perpkts(libtrace_t * libtrace, libtrace_message_t * message)
{
	int i;
	int missed = 0;
	if (message->sender == NULL)
		message->sender = get_thread_descriptor(libtrace);
	for (i = 0; i < libtrace->perpkt_thread_count; i++) {
		if (libtrace->perpkt_threads[i].state == THREAD_RUNNING ||
		    libtrace->perpkt_threads[i].state == THREAD_PAUSED) {
			libtrace_message_queue_put(&libtrace->perpkt_threads[i].messages, message);
		} else {
			missed += 1;
		}
	}
	return -missed;
}

/**
 * Publishes a result to the reduce queue
 * Should only be called by a perpkt thread, i.e. from a perpkt handler
 */
DLLEXPORT void trace_publish_result(libtrace_t *libtrace, libtrace_thread_t *t, uint64_t key, libtrace_generic_t value, int type) {
	libtrace_result_t res;
	res.type = type;
	res.key = key;
	res.value = value;
	if (!libtrace->combiner.publish) {
		fprintf(stderr, "Combiner has no publish method -- can not publish results!\n");
		return;
	}
	libtrace->combiner.publish(libtrace, t->perpkt_num, &libtrace->combiner, &res);
	return;
}

DLLEXPORT void trace_set_combiner(libtrace_t *trace, const libtrace_combine_t *combiner, libtrace_generic_t config){
	if (combiner) {
		trace->combiner = *combiner;
		trace->combiner.configuration = config;
	} else {
		// No combiner, so don't try use it
		memset(&trace->combiner, 0, sizeof(trace->combiner));
	}
}

DLLEXPORT uint64_t trace_packet_get_order(libtrace_packet_t * packet) {
	return packet->order;
}

DLLEXPORT uint64_t trace_packet_get_hash(libtrace_packet_t * packet) {
	return packet->hash;
}

DLLEXPORT void trace_packet_set_order(libtrace_packet_t * packet, uint64_t order) {
	packet->order = order;
}

DLLEXPORT void trace_packet_set_hash(libtrace_packet_t * packet, uint64_t hash) {
	packet->hash = hash;
}

DLLEXPORT bool trace_has_finished(libtrace_t * libtrace) {
	return libtrace->state == STATE_FINISHED || libtrace->state == STATE_JOINED;
}

/**
 * @return True if the trace is not running such that it can be configured
 */
static inline bool trace_is_configurable(libtrace_t *trace) {
	return trace->state == STATE_NEW ||
	                trace->state == STATE_PAUSED;
}

DLLEXPORT int trace_set_perpkt_threads(libtrace_t *trace, int nb) {
	// Only supported on new traces not paused traces
	if (trace->state != STATE_NEW) return -1;

	/* TODO consider allowing an offset from the total number of cores i.e.
	 * -1 reserve 1 core */
	if (nb >= 0) {
		trace->config.perpkt_threads = nb;
		return 0;
	} else {
		return -1;
	}
}

DLLEXPORT int trace_set_tick_interval(libtrace_t *trace, size_t millisec) {
	if (!trace_is_configurable(trace)) return -1;

	trace->config.tick_interval = millisec;
	return 0;
}

DLLEXPORT int trace_set_tick_count(libtrace_t *trace, size_t count) {
	if (!trace_is_configurable(trace)) return -1;

	trace->config.tick_count = count;
	return 0;
}

DLLEXPORT int trace_set_tracetime(libtrace_t *trace, bool tracetime) {
	if (!trace_is_configurable(trace)) return -1;

	trace->tracetime = tracetime;
	return 0;
}

DLLEXPORT int trace_set_cache_size(libtrace_t *trace, size_t size) {
	if (!trace_is_configurable(trace)) return -1;

	trace->config.cache_size = size;
	return 0;
}

DLLEXPORT int trace_set_thread_cache_size(libtrace_t *trace, size_t size) {
	if (!trace_is_configurable(trace)) return -1;

	trace->config.thread_cache_size = size;
	return 0;
}

DLLEXPORT int trace_set_fixed_count(libtrace_t *trace, bool fixed) {
	if (!trace_is_configurable(trace)) return -1;

	trace->config.fixed_count = fixed;
	return 0;
}

DLLEXPORT int trace_set_burst_size(libtrace_t *trace, size_t size) {
	if (!trace_is_configurable(trace)) return -1;

	trace->config.burst_size = size;
	return 0;
}

DLLEXPORT int trace_set_hasher_queue_size(libtrace_t *trace, size_t size) {
	if (!trace_is_configurable(trace)) return -1;

	trace->config.hasher_queue_size = size;
	return 0;
}

DLLEXPORT int trace_set_hasher_polling(libtrace_t *trace, bool polling) {
	if (!trace_is_configurable(trace)) return -1;

	trace->config.hasher_polling = polling;
	return 0;
}

DLLEXPORT int trace_set_reporter_polling(libtrace_t *trace, bool polling) {
	if (!trace_is_configurable(trace)) return -1;

	trace->config.reporter_polling = polling;
	return 0;
}

DLLEXPORT int trace_set_reporter_thold(libtrace_t *trace, size_t thold) {
	if (!trace_is_configurable(trace)) return -1;

	trace->config.reporter_thold = thold;
	return 0;
}

DLLEXPORT int trace_set_debug_state(libtrace_t *trace, bool debug_state) {
	if (!trace_is_configurable(trace)) return -1;

	trace->config.debug_state = debug_state;
	return 0;
}

static bool config_bool_parse(char *value, size_t nvalue) {
	if (strncmp(value, "true", nvalue) == 0)
		return true;
	else if (strncmp(value, "false", nvalue) == 0)
		return false;
	else
		return strtoll(value, NULL, 10) != 0;
}

/* Note update documentation on trace_set_configuration */
static void config_string(struct user_configuration *uc, char *key, size_t nkey, char *value, size_t nvalue) {
	if (!key) {
		fprintf(stderr, "NULL key passed to config_string()\n");
		return;
	}
	if (!value) {
		fprintf(stderr, "NULL value passed to config_string()\n");
		return;
	}
	if (!uc) {
		fprintf(stderr, "NULL uc (user_configuration) passed to config_string()\n");
		return;
	}
	if (strncmp(key, "cache_size", nkey) == 0
	    || strncmp(key, "cs", nkey) == 0) {
		uc->cache_size = strtoll(value, NULL, 10);
	} else if (strncmp(key, "thread_cache_size", nkey) == 0
	           || strncmp(key, "tcs", nkey) == 0) {
		uc->thread_cache_size = strtoll(value, NULL, 10);
	} else if (strncmp(key, "fixed_count", nkey) == 0
	           || strncmp(key, "fc", nkey) == 0) {
		uc->fixed_count = config_bool_parse(value, nvalue);
	} else if (strncmp(key, "burst_size", nkey) == 0
	           || strncmp(key, "bs", nkey) == 0) {
		uc->burst_size = strtoll(value, NULL, 10);
	} else if (strncmp(key, "tick_interval", nkey) == 0
	           || strncmp(key, "ti", nkey) == 0) {
		uc->tick_interval = strtoll(value, NULL, 10);
	} else if (strncmp(key, "tick_count", nkey) == 0
	           || strncmp(key, "tc", nkey) == 0) {
		uc->tick_count = strtoll(value, NULL, 10);
	} else if (strncmp(key, "perpkt_threads", nkey) == 0
	           || strncmp(key, "pt", nkey) == 0) {
		uc->perpkt_threads = strtoll(value, NULL, 10);
	} else if (strncmp(key, "hasher_queue_size", nkey) == 0
	           || strncmp(key, "hqs", nkey) == 0) {
		uc->hasher_queue_size = strtoll(value, NULL, 10);
	} else if (strncmp(key, "hasher_polling", nkey) == 0
	           || strncmp(key, "hp", nkey) == 0) {
		uc->hasher_polling = config_bool_parse(value, nvalue);
	} else if (strncmp(key, "reporter_polling", nkey) == 0
	           || strncmp(key, "rp", nkey) == 0) {
		uc->reporter_polling = config_bool_parse(value, nvalue);
	} else if (strncmp(key, "reporter_thold", nkey) == 0
	           || strncmp(key, "rt", nkey) == 0) {
		uc->reporter_thold = strtoll(value, NULL, 10);
	} else if (strncmp(key, "debug_state", nkey) == 0
	           || strncmp(key, "ds", nkey) == 0) {
		uc->debug_state = config_bool_parse(value, nvalue);
	} else {
		fprintf(stderr, "No matching option %s(=%s), ignoring\n", key, value);
	}
}

DLLEXPORT int trace_set_configuration(libtrace_t *trace, const char *str) {
	char *pch;
	char key[100];
	char value[100];
	char *dup;
	if (!trace) {
		fprintf(stderr, "NULL trace passed into trace_set_configuration()\n");
		return TRACE_ERR_NULL_TRACE;
	}
	if (!str) {
		trace_set_err(trace, TRACE_ERR_CONFIG, "NULL configuration string passed to trace_set_configuration()");
		return -1;
	}

	if (!trace_is_configurable(trace)) return -1;

	dup = strdup(str);
	pch = strtok (dup," ,.-");
	while (pch != NULL)
	{
		if (sscanf(pch, "%99[^=]=%99s", key, value) == 2) {
			config_string(&trace->config, key, sizeof(key), value, sizeof(value));
		} else {
			fprintf(stderr, "Error: parsing option %s\n", pch);
		}
		pch = strtok (NULL," ,.-");
	}
	free(dup);

	return 0;
}

DLLEXPORT int trace_set_configuration_file(libtrace_t *trace, FILE *file) {
	char line[1024];
	if (!trace_is_configurable(trace)) return -1;

	while (fgets(line, sizeof(line), file) != NULL)
	{
		trace_set_configuration(trace, line);
	}

	if(ferror(file))
		return -1;
	else
		return 0;
}

DLLEXPORT void trace_free_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	if (!packet) {
		trace_set_err(libtrace, TRACE_ERR_NULL_PACKET,
			"NULL packet passed to trace_free_packet()");
		return;
	}
	/* Always release any resources this might be holding */
	trace_fin_packet(packet);
	libtrace_ocache_free(&libtrace->packet_freelist, (void **) &packet, 1, 1);
}

DLLEXPORT void trace_increment_packet_refcount(libtrace_packet_t *packet) {
        pthread_mutex_lock(&(packet->ref_lock));
        if (packet->refcount < 0) {
                packet->refcount = 1;
        } else {
                packet->refcount ++;
        }
        pthread_mutex_unlock(&(packet->ref_lock));
}

DLLEXPORT void trace_decrement_packet_refcount(libtrace_packet_t *packet) {
        pthread_mutex_lock(&(packet->ref_lock));
        packet->refcount --;

        if (packet->refcount <= 0) {
                trace_free_packet(packet->trace, packet);
        }
        pthread_mutex_unlock(&(packet->ref_lock));
}


DLLEXPORT libtrace_info_t *trace_get_information(libtrace_t * libtrace) {
	if (libtrace->format)
		return &libtrace->format->info;
	else
		pthread_exit(NULL);
}
