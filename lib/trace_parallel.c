/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton,
 * New Zealand.
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
#include "hash_toeplitz.h"
#include "combiners.h"

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

// Grrr gcc wants this spelt out
__thread struct mem_stats mem_hits = {{0},{0},{0},{0}};

static void print_memory_stats() {
#if 0
	char t_name[50];
	uint64_t total;
	pthread_getname_np(pthread_self(), t_name, sizeof(t_name));

	fprintf(stderr, "Thread ID#%d - %s\n", (int) pthread_self(), t_name);

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
#endif
}

/**
 * This can be used once the hasher thread has been started and internally after
 * verfiy_configuration.
 *
 * @return true if the trace has dedicated hasher thread otherwise false.
 */
inline bool trace_has_dedicated_hasher(libtrace_t * libtrace)
{
	return libtrace->hasher_thread.type == THREAD_HASHER;
}

/**
 * True if the trace has dedicated hasher thread otherwise false,
 * to be used after the trace is running
 */
static inline int trace_has_dedicated_reporter(libtrace_t * libtrace)
{
	assert(libtrace->state != STATE_NEW);
	return libtrace->reporter_thread.type == THREAD_REPORTER && libtrace->reporter;
}

/**
 * When running the number of perpkt threads in use.
 * TODO what if the trace is not running yet, or has finished??
 *
 * @brief libtrace_perpkt_thread_nb
 * @param t The trace
 * @return
 */
DLLEXPORT int libtrace_get_perpkt_count(libtrace_t * t) {
	return t->perpkt_thread_count;
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

	pthread_cond_broadcast(&trace->perpkt_cond);
	if (need_lock)
		pthread_mutex_unlock(&trace->libtrace_lock);
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
 * This is valid once a trace is initialised
 *
 * @return True if the format supports parallel threads.
 */
static inline bool trace_supports_parallel(libtrace_t *trace)
{
	assert(trace);
	assert(trace->format);
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

int get_thread_table_num(libtrace_t *libtrace) {
	int i = 0;
	pthread_t tid = pthread_self();
	for (;i<libtrace->perpkt_thread_count; ++i) {
		if (pthread_equal(tid, libtrace->perpkt_threads[i].tid))
			return i;
	}
	return -1;
}

static libtrace_thread_t * get_thread_descriptor(libtrace_t *libtrace) {
	libtrace_thread_t *ret;
	if (!(ret = get_thread_table(libtrace))) {
		pthread_t tid = pthread_self();
		// Check if we are reporter or something else
		if (pthread_equal(tid, libtrace->reporter_thread.tid))
			ret = &libtrace->reporter_thread;
		else if (pthread_equal(tid, libtrace->hasher_thread.tid))
			ret = &libtrace->hasher_thread;
		else
			ret = NULL;
	}
	return ret;
}

/** Makes a packet safe, a packet may become invaild after a
 * pause (or stop/destroy) of a trace. This copies a packet
 * in such a way that it will be able to survive a pause.
 *
 * However this will not allow the packet to be used after
 * the format is destroyed. Or while the trace is still paused.
 */
DLLEXPORT void libtrace_make_packet_safe(libtrace_packet_t *pkt) {
	// Duplicate the packet in standard malloc'd memory and free the
	// original, This is a 1:1 exchange so is ocache count remains unchanged.
	if (pkt->buf_control != TRACE_CTRL_PACKET) {
		libtrace_packet_t *dup;
		dup = trace_copy_packet(pkt);
		/* Release the external buffer */
		trace_fin_packet(pkt);
		/* Copy the duplicated packet over the existing */
		memcpy(pkt, dup, sizeof(libtrace_packet_t));
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
		t->accepted_packets++;
		libtrace_generic_t data = {.pkt = *packet};
		*packet = (*trace->per_pkt)(trace, t, MESSAGE_PACKET, data, t);
		trace_fin_packet(*packet);
	} else {
		assert((*packet)->error == READ_TICK);
		libtrace_generic_t data = {.uint64 = trace_packet_get_order(*packet)};
		(*trace->per_pkt)(trace, t, MESSAGE_TICK, data, t);
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
			assert(ret == READ_MESSAGE);
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
	(*trace->per_pkt)(trace, t, MESSAGE_PAUSING, (libtrace_generic_t){0}, t);

	/* Send through any remaining packets (or messages) without delay */

	/* First send those packets already read, as fast as possible
	 * This should never fail or check for messages etc. */
	ASSERT_RET(dispatch_packets(trace, t, packets, nb_packets, empty,
	                            offset, false), == 0);

	libtrace_ocache_alloc(&trace->packet_freelist, (void **) &packet, 1, 1);
	/* If a hasher thread is running, empty input queues so we don't lose data */
	if (trace_has_dedicated_hasher(trace)) {
		fprintf(stderr, "Trace is using a hasher thread emptying queues\n");
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
				assert (ret == READ_EOF || ret == READ_ERROR);
				/* Verify no packets are remaining */
				/* TODO refactor this sanity check out!! */
				while (!libtrace_ringbuffer_is_empty(&t->rbuffer)) {
					ASSERT_RET(trace->pread(trace, t, &packet, 1), <= 0);
					// No packets after this should have any data in them
					assert(packet->error <= 0);
				}
				fprintf(stderr, "PREAD_FAILED %d\n", ret);
				libtrace_ocache_free(&trace->packet_freelist, (void **) &packet, 1, 1);
				return -1;
			}
		}
	}
	libtrace_ocache_free(&trace->packet_freelist, (void **) &packet, 1, 1);

	/* Now we do the actual pause, this returns when we resumed */
	trace_thread_pause(trace, t);
	(*trace->per_pkt)(trace, t, MESSAGE_RESUMING, (libtrace_generic_t){0}, t);
	return 1;
}

/**
 * The is the entry point for our packet processing threads.
 */
static void* perpkt_threads_entry(void *data) {
	libtrace_t *trace = (libtrace_t *)data;
	libtrace_thread_t *t;
	libtrace_message_t message = {0};
	libtrace_packet_t *packets[trace->config.burst_size];
	size_t i;
	//int ret;
	/* The current reading position into the packets */
	int offset = 0;
	/* The number of packets last read */
	int nb_packets = 0;
	/* The offset to the first NULL packet upto offset */
	int empty = 0;

	/* Wait until trace_pstart has been completed */
	ASSERT_RET(pthread_mutex_lock(&trace->libtrace_lock), == 0);
	t = get_thread_table(trace);
	assert(t);
	if (trace->state == STATE_ERROR) {
		thread_change_state(trace, t, THREAD_FINISHED, false);
		ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
		pthread_exit(NULL);
	}
	//printf("Yay Started perpkt thread #%d\n", (int) get_thread_table_num(trace));
	ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);

	if (trace->format->pregister_thread) {
		trace->format->pregister_thread(trace, t, !trace_has_dedicated_hasher(trace));
	}

	/* Fill our buffer with empty packets */
	memset(&packets, 0, sizeof(void*) * trace->config.burst_size);
	libtrace_ocache_alloc(&trace->packet_freelist, (void **) packets,
	                      trace->config.burst_size,
	                      trace->config.burst_size);

	/* ~~~~~~~~~~~ Setup complete now we loop ~~~~~~~~~~~~~~~ */

	/* Let the per_packet function know we have started */
	(*trace->per_pkt)(trace, t, MESSAGE_STARTING, (libtrace_generic_t){0}, t);
	(*trace->per_pkt)(trace, t, MESSAGE_RESUMING, (libtrace_generic_t){0}, t);

	for (;;) {

		if (libtrace_message_queue_try_get(&t->messages, &message) != LIBTRACE_MQ_FAILED) {
			int ret;
			switch (message.code) {
				case MESSAGE_DO_PAUSE: // This is internal
					ret = trace_perpkt_thread_pause(trace, t,
					      packets, nb_packets, &empty, &offset);
					if (ret == READ_EOF) {
						fprintf(stderr, "PAUSE stop eof!!\n");
						goto eof;
					} else if (ret == READ_ERROR) {
						fprintf(stderr, "PAUSE stop error!!\n");
						goto error;
					}
					assert(ret == 1);
					continue;
				case MESSAGE_DO_STOP: // This is internal
					fprintf(stderr, "DO_STOP stop!!\n");
					goto eof;
			}
			(*trace->per_pkt)(trace, t, message.code, message.additional, message.sender);
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
				assert(packets[0]);
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
			/* Store the first packet */
			if (packets[0]->error > 0) {
				store_first_packet(trace, packets[0], t);
			}
			dispatch_packets(trace, t, packets, nb_packets, &empty,
			                 &offset, trace->tracetime);
		} else {
			switch (nb_packets) {
			case READ_EOF:
				fprintf(stderr, "EOF stop %d!!\n", nb_packets);
				goto eof;
			case READ_ERROR:
				fprintf(stderr, "ERROR stop %d!!\n", nb_packets);
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
	fprintf(stderr, "An error occured in trace\n");
	message.code = MESSAGE_DO_STOP;
	message.sender = t;
	message.additional.uint64 = 0;
	trace_send_message_to_perpkts(trace, &message);
eof:
	fprintf(stderr, "An eof occured in trace\n");
	/* ~~~~~~~~~~~~~~ Trace is finished do tear down ~~~~~~~~~~~~~~~~~~~~~ */

	// Let the per_packet function know we have stopped
	(*trace->per_pkt)(trace, t, MESSAGE_PAUSING, (libtrace_generic_t){0}, t);
	(*trace->per_pkt)(trace, t, MESSAGE_STOPPING, (libtrace_generic_t){0}, t);

	// Free any remaining packets
	for (i = 0; i < trace->config.burst_size; i++) {
		if (packets[i]) {
			libtrace_ocache_free(&trace->packet_freelist, (void **) &packets[i], 1, 1);
			packets[i] = NULL;
		}
	}

	thread_change_state(trace, t, THREAD_FINISHED, true);

	// Notify only after we've defiantly set the state to finished
	message.code = MESSAGE_PERPKT_ENDED;
	message.additional.uint64 = 0;
	trace_send_message_to_reporter(trace, &message);

	// Release all ocache memory before unregistering with the format
	// because this might(it does in DPDK) unlink the formats mempool
	// causing destroy/finish packet to fail.
	libtrace_ocache_unregister_thread(&trace->packet_freelist);
	if (trace->format->punregister_thread) {
		trace->format->punregister_thread(trace, t);
	}
	print_memory_stats();

	pthread_exit(NULL);
};

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
	libtrace_message_t message = {0};
	int pkt_skipped = 0;

	assert(trace_has_dedicated_hasher(trace));
	/* Wait until all threads are started and objects are initialised (ring buffers) */
	ASSERT_RET(pthread_mutex_lock(&trace->libtrace_lock), == 0);
	t = &trace->hasher_thread;
	assert(t->type == THREAD_HASHER && pthread_equal(pthread_self(), t->tid));
	if (trace->state == STATE_ERROR) {
		thread_change_state(trace, t, THREAD_FINISHED, false);
		ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
		pthread_exit(NULL);
	}

	printf("Hasher Thread started\n");
	ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);

	if (trace->format->pregister_thread) {
		trace->format->pregister_thread(trace, t, true);
	}

	/* Read all packets in then hash and queue against the correct thread */
	while (1) {
		int thread;
		if (!pkt_skipped)
			libtrace_ocache_alloc(&trace->packet_freelist, (void **) &packet, 1, 1);
		assert(packet);

		if (libtrace_halt) {
			packet->error = 0;
			break;
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
					assert(trace->started == false);
					assert(trace->state == STATE_FINSHED);
					/* Mark the current packet as EOF */
					packet->error = 0;
					break;
				default:
					fprintf(stderr, "Hasher thread didn't expect message code=%d\n", message.code);
			}
			pkt_skipped = 1;
			continue;
		}

		if ((packet->error = trace_read_packet(trace, packet)) <1) {
			break; /* We are EOF or error'd either way we stop  */
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
		} else {
			assert(!"Dropping a packet!!");
			pkt_skipped = 1; // Reuse that packet no one read it
		}
	}

	/* Broadcast our last failed read to all threads */
	for (i = 0; i < trace->perpkt_thread_count; i++) {
		libtrace_packet_t * bcast;
		fprintf(stderr, "Broadcasting error/EOF now the trace is over\n");
		if (i == trace->perpkt_thread_count - 1) {
			bcast = packet;
		} else {
			libtrace_ocache_alloc(&trace->packet_freelist, (void **) &bcast, 1, 1);
			bcast->error = packet->error;
		}
		ASSERT_RET(pthread_mutex_lock(&trace->libtrace_lock), == 0);
		if (trace->perpkt_threads[i].state != THREAD_FINISHED) {
			// Unlock early otherwise we could deadlock
			libtrace_ringbuffer_write(&trace->perpkt_threads[i].rbuffer, bcast);
			ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
		} else {
			fprintf(stderr, "SKIPPING THREAD !!!%d!!!/n", (int) i);
			ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
		}
	}

	// We don't need to free the packet
	thread_change_state(trace, t, THREAD_FINISHED, true);

	// Notify only after we've defiantly set the state to finished
	message.code = MESSAGE_PERPKT_ENDED;
	message.additional.uint64 = 0;
	trace_send_message_to_reporter(trace, &message);
	libtrace_ocache_unregister_thread(&trace->packet_freelist);
	if (trace->format->punregister_thread) {
		trace->format->punregister_thread(trace, t);
	}
	print_memory_stats();

	// TODO remove from TTABLE t sometime
	pthread_exit(NULL);
};

/**
 * Moves src into dest(Complete copy) and copies the memory buffer and
 * its flags from dest into src ready for reuse without needing extra mallocs.
 */
static inline void swap_packets(libtrace_packet_t *dest, libtrace_packet_t *src) {
	// Save the passed in buffer status
	assert(dest->trace == NULL); // Must be a empty packet
	void * temp_buf = dest->buffer;
	buf_control_t temp_buf_control = dest->buf_control;
	// Completely copy StoredPacket into packet
	memcpy(dest, src, sizeof(libtrace_packet_t));
	// Set the buffer settings on the returned packet
	src->buffer = temp_buf;
	src->buf_control = temp_buf_control;
	src->trace = NULL;
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

	ASSERT_RET(pthread_mutex_lock(&libtrace->libtrace_lock), == 0);
	/* Read nb_packets */
	for (i = 0; i < nb_packets; ++i) {
		if (libtrace_halt) {
			break;
		}
		packets[i]->error = trace_read_packet(libtrace, packets[i]);

		if (packets[i]->error <= 0) {
			/* We'll catch this next time if we have already got packets */
			if ( i==0 ) {
				ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);
				return packets[i]->error;
			} else {
				break;
			}
		}
		/*
		if (libtrace->config.tick_count && trace_packet_get_order(packets[i]) % libtrace->config.tick_count == 0) {
			tick_hit = true;
		}*/
	}
	// Doing this inside the lock ensures the first packet is always
	// recorded first
	if (packets[0]->error > 0) {
		store_first_packet(libtrace, packets[0], t);
	}
	ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);
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
		fprintf(stderr, "Hit me, ohh yeah got error %d\n",
		        ((libtrace_packet_t *)t->format_data)->error);
		return ((libtrace_packet_t *)t->format_data)->error;
	}

	// Always grab at least one
	if (packets[0]) // Recycle the old get the new
		libtrace_ocache_free(&libtrace->packet_freelist, (void **) packets, 1, 1);
	packets[0] = libtrace_ringbuffer_read(&t->rbuffer);

	if (packets[0]->error <= 0 && packets[0]->error != READ_TICK) {
		fprintf(stderr, "Hit me, ohh yeah returning error %d\n", packets[0]->error);
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
				assert(t->format_data == NULL);
				t->format_data = packets[i];
				fprintf(stderr, "Hit me, ohh yeah set error %d\n",
				        ((libtrace_packet_t *)t->format_data)->error);
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
	if (!t->recorded_first) {
		struct timeval tv;
		libtrace_packet_t * dup;
		// For what it's worth we can call these outside of the lock
		gettimeofday(&tv, NULL);
		dup = trace_copy_packet(packet);
		ASSERT_RET(pthread_spin_lock(&libtrace->first_packets.lock), == 0);
		libtrace->first_packets.packets[t->perpkt_num].packet = dup;
		//printf("Stored first packet time=%f\n", trace_get_seconds(dup));
		memcpy(&libtrace->first_packets.packets[t->perpkt_num].tv, &tv, sizeof(tv));
		// Now update the first
		libtrace->first_packets.count++;
		if (libtrace->first_packets.count == 1) {
			// We the first entry hence also the first known packet
			libtrace->first_packets.first = t->perpkt_num;
		} else {
			// Check if we are newer than the previous 'first' packet
			size_t first = libtrace->first_packets.first;
			if (trace_get_seconds(dup) <
				trace_get_seconds(libtrace->first_packets.packets[first].packet))
				libtrace->first_packets.first = t->perpkt_num;
		}
		ASSERT_RET(pthread_spin_unlock(&libtrace->first_packets.lock), == 0);
		libtrace_message_t mesg = {0};
		mesg.code = MESSAGE_FIRST_PACKET;
		trace_send_message_to_reporter(libtrace, &mesg);
		t->recorded_first = true;
	}
}

/**
 * Returns 1 if it's certain that the first packet is truly the first packet
 * rather than a best guess based upon threads that have published so far.
 * Otherwise 0 is returned.
 * It's recommended that this result is stored rather than calling this
 * function again.
 */
DLLEXPORT int retrive_first_packet(libtrace_t *libtrace, libtrace_packet_t **packet, struct timeval **tv)
{
	int ret = 0;
	ASSERT_RET(pthread_spin_lock(&libtrace->first_packets.lock), == 0);
	if (libtrace->first_packets.count) {
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


DLLEXPORT uint64_t tv_to_usec(struct timeval *tv)
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
	libtrace_message_t message = {0};
	libtrace_t *trace = (libtrace_t *)data;
	libtrace_thread_t *t = &trace->reporter_thread;

	fprintf(stderr, "Reporter thread starting\n");

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

	(*trace->reporter)(trace, MESSAGE_STARTING, (libtrace_generic_t) {0}, t);
	(*trace->reporter)(trace, MESSAGE_RESUMING, (libtrace_generic_t) {0}, t);

	while (!trace_finished(trace)) {
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
				assert(trace->combiner.pause);
				trace->combiner.pause(trace, &trace->combiner);
				(*trace->reporter)(trace, MESSAGE_PAUSING, (libtrace_generic_t) {0}, t);
				trace_thread_pause(trace, t);
				(*trace->reporter)(trace, MESSAGE_RESUMING, (libtrace_generic_t) {0}, t);
				break;
		default:
			(*trace->reporter)(trace, message.code, message.additional, message.sender);
		}
	}

	// Flush out whats left now all our threads have finished
	trace->combiner.read_final(trace, &trace->combiner);

	// GOODBYE
	(*trace->reporter)(trace, MESSAGE_PAUSING, (libtrace_generic_t) {0}, t);
	(*trace->reporter)(trace, MESSAGE_STOPPING, (libtrace_generic_t) {0}, t);

	thread_change_state(trace, &trace->reporter_thread, THREAD_FINISHED, true);
	print_memory_stats();
	return NULL;
}

/** Similar to delay_tracetime but send messages to all threads periodically */
static void* keepalive_entry(void *data) {
	struct timeval prev, next;
	libtrace_message_t message = {0};
	libtrace_t *trace = (libtrace_t *)data;
	uint64_t next_release;
	fprintf(stderr, "keepalive thread is starting\n");

	/* Wait until all threads are started */
	ASSERT_RET(pthread_mutex_lock(&trace->libtrace_lock), == 0);
	if (trace->state == STATE_ERROR) {
		thread_change_state(trace, &trace->keepalive_thread, THREAD_FINISHED, false);
		ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);
		pthread_exit(NULL);
	}
	ASSERT_RET(pthread_mutex_unlock(&trace->libtrace_lock), == 0);

	gettimeofday(&prev, NULL);
	message.code = MESSAGE_TICK;
	while (trace->state != STATE_FINSHED) {
		fd_set rfds;
		next_release = tv_to_usec(&prev) + (trace->config.tick_interval * 1000);
		gettimeofday(&next, NULL);
		if (next_release > tv_to_usec(&next)) {
			next = usec_to_tv(next_release - tv_to_usec(&next));
			// Wait for timeout or a message
			FD_ZERO(&rfds);
			FD_SET(libtrace_message_queue_get_fd(&trace->keepalive_thread.messages), &rfds);
			if (select(libtrace_message_queue_get_fd(&trace->keepalive_thread.messages)+1, &rfds, NULL, NULL, &next) == 1) {
				libtrace_message_t msg;
				libtrace_message_queue_get(&trace->keepalive_thread.messages, &msg);
				assert(msg.code == MESSAGE_DO_STOP);
				goto done;
			}
		}
		prev = usec_to_tv(next_release);
		if (trace->state == STATE_RUNNING) {
			message.additional.uint64 = tv_to_usec(&prev);
			trace_send_message_to_perpkts(trace, &message);
		}
	}
done:

	thread_change_state(trace, &trace->keepalive_thread, THREAD_FINISHED, true);
	return NULL;
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
		libtrace_packet_t *first_pkt;
		struct timeval *sys_tv;
		int64_t initial_offset;
		int stable = retrive_first_packet(libtrace, &first_pkt, &sys_tv);
		assert(first_pkt);
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

		//printf("WAITING for %d.%d next=%"PRIu64" curr=%"PRIu64" seconds packettime %f\n", delay_tv.tv_sec, delay_tv.tv_usec, next_release, curr_usec, trace_get_seconds(packet));
		ret = select(mesg_fd+1, &rfds, NULL, NULL, &delay_tv);
		if (ret == 0) {
			return 0;
		} else if (ret > 0) {
			return READ_MESSAGE;
		} else {
			fprintf(stderr, "I thnik we broke select\n");
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
	assert(nb_packets);
	assert(libtrace && "libtrace is NULL in trace_read_packet()");
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
			assert(i[packets]);
			if (!(packets[i]->buf_control==TRACE_CTRL_PACKET ||
			      packets[i]->buf_control==TRACE_CTRL_EXTERNAL)) {
				trace_set_err(libtrace,TRACE_ERR_BAD_STATE,
				              "Packet passed to trace_read_packet() is invalid\n");
				return -1;
			}
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
				trace_packet_set_order(packets[i], trace_get_erf_timestamp(packets[i]));
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
                          fn_per_pkt per_pkt, fn_reporter reporter) {
	int err = 0;
	if (libtrace->state != STATE_PAUSED) {
		trace_set_err(libtrace, TRACE_ERR_BAD_STATE,
			"trace(%s) is not currently paused",
		              libtrace->uridata);
		return -1;
	}

	/* Update functions if requested */
	if (per_pkt)
		libtrace->per_pkt = per_pkt;
	if (reporter)
		libtrace->reporter = reporter;
	if(global_blob)
		libtrace->global_blob = global_blob;

	assert(libtrace_parallel);
	assert(!libtrace->perpkt_thread_states[THREAD_RUNNING]);
	assert(libtrace->per_pkt);

	if (libtrace->perpkt_thread_count > 1 &&
	    trace_supports_parallel(libtrace) &&
	    !trace_has_dedicated_hasher(libtrace)) {
		fprintf(stderr, "Restarting trace pstart_input()\n");
		err = libtrace->format->pstart_input(libtrace);
	} else {
		if (libtrace->format->start_input) {
			fprintf(stderr, "Restarting trace start_input()\n");
			err = libtrace->format->start_input(libtrace);
		}
	}

	if (err == 0) {
		libtrace->started = true;
		libtrace_change_state(libtrace, STATE_RUNNING, false);
	}
	return err;
}

/**
 * Verifies the configuration and sets default values for any values not
 * specified by the user.
 */
static void verify_configuration(libtrace_t *libtrace) {
	bool require_hasher = false;

	/* Might we need a dedicated hasher thread? */
	if (libtrace->hasher && libtrace->hasher_type != HASHER_HARDWARE) {
		require_hasher = true;
	}

	if (libtrace->config.hasher_queue_size <= 0)
		libtrace->config.hasher_queue_size = 1000;

	if (libtrace->config.perpkt_threads <= 0) {
		// TODO add BSD support
		libtrace->perpkt_thread_count = sysconf(_SC_NPROCESSORS_ONLN);
		if (libtrace->perpkt_thread_count <= 0)
			// Lets just use one
			libtrace->perpkt_thread_count = 1;
	} else {
		libtrace->perpkt_thread_count = libtrace->config.perpkt_threads;
	}

	if (libtrace->config.reporter_thold <= 0)
		libtrace->config.reporter_thold = 100;
	if (libtrace->config.burst_size <= 0)
		libtrace->config.burst_size = 10;
	if (libtrace->config.packet_thread_cache_size <= 0)
		libtrace->config.packet_thread_cache_size = 20;
	if (libtrace->config.packet_cache_size <= 0)
		libtrace->config.packet_cache_size = (libtrace->config.hasher_queue_size + 1) * libtrace->perpkt_thread_count;

	if (libtrace->config.packet_cache_size <
		(libtrace->config.hasher_queue_size + 1) * libtrace->perpkt_thread_count)
		fprintf(stderr, "WARNING deadlocks may occur and extra memory allocating buffer sizes (packet_freelist_size) mismatched\n");

	if (libtrace->combiner.initialise == NULL && libtrace->combiner.publish == NULL)
		libtrace->combiner = combiner_unordered;


	/* Figure out if we are using a dedicated hasher thread? */
	if (require_hasher && libtrace->perpkt_thread_count > 1) {
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
	int ret;
	assert(t->type == THREAD_EMPTY);
	t->trace = trace;
	t->ret = NULL;
	t->user_data = NULL;
	t->type = type;
	t->state = THREAD_RUNNING;
	ret = pthread_create(&t->tid, NULL, start_routine, (void *) trace);
	if (ret != 0) {
		libtrace_zero_thread(t);
		trace_set_err(trace, ret, "Failed to create a thread");
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
	if(name)
		pthread_setname_np(t->tid, name);
	t->perpkt_num = perpkt_num;
	return 0;
}

/** Parses the environment variable LIBTRACE_CONF into the supplied
 * configuration structure.
 *
 * @param libtrace The trace from which we determine the URI
 * @param uc A configuration structure to be configured.
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
 * @note All enironment variables names MUST only contian
 * [A-Z], [0-9] and [_] (underscore) and not start with a number. Any characters
 * outside of this range should be captilised if possible or replaced with an
 * underscore.
 */
static void parse_env_config (libtrace_t *libtrace, struct user_configuration* uc) {
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
		parse_user_config(uc, env);
	}

	/* Then format settings LIBTRACE_CONF_<FORMAT> */
	if (mark != 0) {
		env_name[mark] = 0;
		env = getenv(env_name);
		if (env) {
			printf("Got %s=%s", env_name, env);
			parse_user_config(uc, env);
		}
		env_name[mark] = '_';
	}

	/* Finally this specific trace LIBTRACE_CONF_<FORMAT_URI> */
	env = getenv(env_name);
	if (env) {
		printf("Got %s=%s", env_name, env);
		parse_user_config(uc, env);
	}
}

DLLEXPORT int trace_pstart(libtrace_t *libtrace, void* global_blob,
                           fn_per_pkt per_pkt, fn_reporter reporter) {
	int i;
	int ret = -1;
	char name[16];
	sigset_t sig_before, sig_block_all;
	assert(libtrace);

	ASSERT_RET(pthread_mutex_lock(&libtrace->libtrace_lock), == 0);
	if (trace_is_err(libtrace)) {
		goto cleanup_none;
	}

	if (libtrace->state == STATE_PAUSED) {
		ret = trace_prestart(libtrace, global_blob, per_pkt, reporter);
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
	libtrace->per_pkt = per_pkt;
	libtrace->reporter = reporter;
	/* And zero other fields */
	for (i = 0; i < THREAD_STATE_MAX; ++i) {
		libtrace->perpkt_thread_states[i] = 0;
	}
	libtrace->first_packets.first = 0;
	libtrace->first_packets.count = 0;
	libtrace->first_packets.packets = NULL;
	libtrace->perpkt_threads = NULL;
	/* Set a global which says we are using a parallel trace. This is
	 * for backwards compatability due to changes when destroying packets */
	libtrace_parallel = 1;

	/* Parses configuration passed through environment variables */
	parse_env_config(libtrace, &libtrace->config);
	verify_configuration(libtrace);

	/* Try start the format - we prefer parallel over single threaded, as
	 * these formats should support messages better */
	if (trace_supports_parallel(libtrace) &&
	    !trace_has_dedicated_hasher(libtrace)) {
		printf("Using the parallel trace format\n");
		ret = libtrace->format->pstart_input(libtrace);
		libtrace->pread = trace_pread_packet_wrapper;
	} else {
		printf("Using single threaded interface\n");
		if (libtrace->format->start_input) {
			ret = libtrace->format->start_input(libtrace);
		}
		if (libtrace->perpkt_thread_count > 1)
			libtrace->pread = trace_pread_packet_first_in_first_served;
		else
			/* Use standard read_packet */
			libtrace->pread = NULL;
	}

	if (ret != 0) {
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
		if (ret != 0) {
			trace_set_err(libtrace, errno, "trace_pstart "
			              "failed to start a hasher thread.");
			goto cleanup_started;
		}
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
		if (ret != 0) {
			trace_set_err(libtrace, errno, "trace_pstart "
			              "failed to start a perpkt thread.");
			goto cleanup_threads;
		}
	}

	/* Start the reporter thread */
	if (reporter) {
		if (libtrace->combiner.initialise)
			libtrace->combiner.initialise(libtrace, &libtrace->combiner);
		ret = trace_start_thread(libtrace, &libtrace->reporter_thread,
		                   THREAD_REPORTER, reporter_entry, -1,
		                   "reporter_thread");
		if (ret != 0) {
			trace_set_err(libtrace, errno, "trace_pstart "
			              "failed to start reporter thread.");
			goto cleanup_threads;
		}
	}

	/* Start the keepalive thread */
	if (libtrace->config.tick_interval > 0) {
		ret = trace_start_thread(libtrace, &libtrace->keepalive_thread,
		                   THREAD_KEEPALIVE, keepalive_entry, -1,
		                   "keepalive_thread");
		if (ret != 0) {
			trace_set_err(libtrace, errno, "trace_pstart "
			              "failed to start keepalive thread.");
			goto cleanup_threads;
		}
	}

	/* Init other data structures */
	libtrace->perpkt_thread_states[THREAD_RUNNING] = libtrace->perpkt_thread_count;
	ASSERT_RET(pthread_spin_init(&libtrace->first_packets.lock, 0), == 0);
	libtrace->first_packets.packets = calloc(libtrace->perpkt_thread_count,
	                                         sizeof(struct  __packet_storage_magic_type));
	if (libtrace->first_packets.packets == NULL) {
		trace_set_err(libtrace, errno, "trace_pstart "
		              "failed to allocate memory.");
		goto cleanup_threads;
	}

	if (libtrace_ocache_init(&libtrace->packet_freelist,
	                     (void* (*)()) trace_create_packet,
	                     (void (*)(void *))trace_destroy_packet,
	                     libtrace->config.packet_thread_cache_size,
	                     libtrace->config.packet_cache_size * 4,
	                     libtrace->config.fixed_packet_count) != 0) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "trace_pstart "
		              "failed to allocate ocache.");
		goto cleanup_threads;
	}

	/* Threads don't start */
	libtrace->started = true;
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
	assert(libtrace->perpkt_thread_states[THREAD_RUNNING] == 0);
	libtrace->perpkt_thread_states[THREAD_FINISHED] = 0;
cleanup_started:
	if (trace_supports_parallel(libtrace) &&
	    !trace_has_dedicated_hasher(libtrace)
	    && libtrace->perpkt_thread_count > 1) {
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

/**
 * Pauses a trace, this should only be called by the main thread
 * 1. Set started = false
 * 2. All perpkt threads are paused waiting on a condition var
 * 3. Then call ppause on the underlying format if found
 * 4. The traces state is paused
 *
 * Once done you should be able to modify the trace setup and call pstart again
 * TODO handle changing thread numbers
 */
DLLEXPORT int trace_ppause(libtrace_t *libtrace)
{
	libtrace_thread_t *t;
	int i;
	assert(libtrace);

	t = get_thread_table(libtrace);
	// Check state from within the lock if we are going to change it
	ASSERT_RET(pthread_mutex_lock(&libtrace->libtrace_lock), == 0);
	if (!libtrace->started || libtrace->state != STATE_RUNNING) {
		fprintf(stderr, "pause failed started=%d state=%s (%d)\n", libtrace->started, get_trace_state_name(libtrace->state), libtrace->state);
		trace_set_err(libtrace,TRACE_ERR_BAD_STATE, "You must call trace_start() before calling trace_ppause()");
		ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);
		return -1;
	}

	libtrace_change_state(libtrace, STATE_PAUSING, false);
	ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);

	// Special case handle the hasher thread case
	if (trace_has_dedicated_hasher(libtrace)) {
		if (libtrace->config.debug_state)
			fprintf(stderr, "Hasher thread is running, asking it to pause ...");
		libtrace_message_t message = {0};
		message.code = MESSAGE_DO_PAUSE;
		trace_send_message_to_thread(libtrace, &libtrace->hasher_thread, &message);
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
			libtrace_message_t message = {0};
			message.code = MESSAGE_DO_PAUSE;
			trace_send_message_to_thread(libtrace, &libtrace->perpkt_threads[i], &message);
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
	if (trace_has_dedicated_reporter(libtrace)) {
		if (libtrace->config.debug_state)
			fprintf(stderr, "Reporter thread is running, asking it to pause ...");
		libtrace_message_t message = {0};
		message.code = MESSAGE_DO_PAUSE;
		trace_send_message_to_thread(libtrace, &libtrace->reporter_thread, &message);
		// Wait for it to pause
		ASSERT_RET(pthread_mutex_lock(&libtrace->libtrace_lock), == 0);
		while (libtrace->reporter_thread.state == THREAD_RUNNING) {
			ASSERT_RET(pthread_cond_wait(&libtrace->perpkt_cond, &libtrace->libtrace_lock), == 0);
		}
		ASSERT_RET(pthread_mutex_unlock(&libtrace->libtrace_lock), == 0);
		if (libtrace->config.debug_state)
			fprintf(stderr, " DONE\n");
	}

	/* Cache values before we pause */
	if (libtrace->stats == NULL)
		libtrace->stats = trace_create_statistics();
	// Save the statistics against the trace
	trace_get_statistics(libtrace, NULL);
	if (trace_supports_parallel(libtrace) && !trace_has_dedicated_hasher(libtrace) && libtrace->perpkt_thread_count > 1) {
		libtrace->started = false;
		if (libtrace->format->ppause_input)
			libtrace->format->ppause_input(libtrace);
		// TODO What happens if we don't have pause input??
	} else {
		int err;
		fprintf(stderr, "Trace is not parallel so we are doing a normal pause %s\n", libtrace->uridata);
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
	libtrace_message_t message = {0};
	assert(libtrace);

	// Ensure all threads have paused and the underlying trace format has
	// been closed and all packets associated are cleaned up
	// Pause will do any state checks for us
	err = trace_ppause(libtrace);
	if (err)
		return err;

	// Now send a message asking the threads to stop
	// This will be retrieved before trying to read another packet

	message.code = MESSAGE_DO_STOP;
	trace_send_message_to_perpkts(libtrace, &message);
	if (trace_has_dedicated_hasher(libtrace))
		trace_send_message_to_thread(libtrace, &libtrace->hasher_thread, &message);

	for (i = 0; i < libtrace->perpkt_thread_count; i++) {
		trace_send_message_to_thread(libtrace, &libtrace->perpkt_threads[i], &message);
	}

	// Now release the threads and let them stop
	libtrace_change_state(libtrace, STATE_FINSHED, true);
	return 0;
}

/**
 * Set the hasher type along with a selected function, if hardware supports
 * that generic type of hashing it will be used otherwise the supplied
 * hasher function will be used and passed data when called.
 *
 * @return 0 if successful otherwise -1 on error
 */
DLLEXPORT int trace_set_hasher(libtrace_t *trace, enum hasher_types type, fn_hasher hasher, void *data) {
	int ret = -1;
	if (type == HASHER_HARDWARE || (type == HASHER_CUSTOM && !hasher) || (type == HASHER_BALANCE && hasher)) {
		return -1;
	}

	// Save the requirements
	trace->hasher_type = type;
	if (hasher) {
		trace->hasher = hasher;
		trace->hasher_data = data;
	} else {
		trace->hasher = NULL;
		trace->hasher_data = NULL;
	}

	// Try push this to hardware - NOTE hardware could do custom if
	// there is a more efficient way to apply it, in this case
	// it will simply grab the function out of libtrace_t
	if (trace->format->pconfig_input)
		ret = trace->format->pconfig_input(trace, TRACE_OPTION_SET_HASHER, &type);

	if (ret == -1) {
		// We have to deal with this ourself
		// This most likely means single threaded reading of the trace
		if (!hasher) {
			switch (type)
			{
				case HASHER_CUSTOM:
				case HASHER_BALANCE:
					return 0;
				case HASHER_BIDIRECTIONAL:
					trace->hasher = (fn_hasher) toeplitz_hash_packet;
					trace->hasher_data = calloc(1, sizeof(toeplitz_conf_t));
					toeplitz_init_config(trace->hasher_data, 1);
					return 0;
				case HASHER_UNIDIRECTIONAL:
					trace->hasher = (fn_hasher) toeplitz_hash_packet;
					trace->hasher_data = calloc(1, sizeof(toeplitz_conf_t));
					toeplitz_init_config(trace->hasher_data, 0);
					return 0;
				case HASHER_HARDWARE:
					return -1;
			}
			return -1;
		}
	} else {
		// The hardware is dealing with this yay
		trace->hasher_type = HASHER_HARDWARE;
	}

	return 0;
}

// Waits for all threads to finish
DLLEXPORT void trace_join(libtrace_t *libtrace) {
	int i;

	/* Firstly wait for the perpkt threads to finish, since these are
	 * user controlled */
	for (i=0; i< libtrace->perpkt_thread_count; i++) {
		//printf("Waiting to join with perpkt #%d\n", i);
		ASSERT_RET(pthread_join(libtrace->perpkt_threads[i].tid, NULL), == 0);
		//printf("Joined with perpkt #%d\n", i);
		// So we must do our best effort to empty the queue - so
		// the producer (or any other threads) don't block.
		libtrace_packet_t * packet;
		assert(libtrace->perpkt_threads[i].state == THREAD_FINISHED);
		while(libtrace_ringbuffer_try_read(&libtrace->perpkt_threads[i].rbuffer, (void **) &packet))
			if (packet) // This could be NULL iff the perpkt finishes early
				trace_destroy_packet(packet);
	}

	/* Now the hasher */
	if (trace_has_dedicated_hasher(libtrace)) {
		pthread_join(libtrace->hasher_thread.tid, NULL);
		assert(libtrace->hasher_thread.state == THREAD_FINISHED);
	}

	// Now that everything is finished nothing can be touching our
	// buffers so clean them up
	for (i = 0; i < libtrace->perpkt_thread_count; i++) {
		// Its possible 1 packet got added by the reporter (or 1 per any other thread) since we cleaned up
		// if they lost timeslice before-during a write
		libtrace_packet_t * packet;
		while(libtrace_ringbuffer_try_read(&libtrace->perpkt_threads[i].rbuffer, (void **) &packet))
			trace_destroy_packet(packet);
		if (libtrace->hasher) {
			assert(libtrace_ringbuffer_is_empty(&libtrace->perpkt_threads[i].rbuffer));
			libtrace_ringbuffer_destroy(&libtrace->perpkt_threads[i].rbuffer);
		}
		// Cannot destroy vector yet, this happens with trace_destroy
	}
	// TODO consider perpkt threads marking trace as finished before join is called
	libtrace_change_state(libtrace, STATE_FINSHED, true);

	if (trace_has_dedicated_reporter(libtrace)) {
		pthread_join(libtrace->reporter_thread.tid, NULL);
		assert(libtrace->reporter_thread.state == THREAD_FINISHED);
	}

	// Wait for the tick (keepalive) thread if it has been started
	if (libtrace->keepalive_thread.type == THREAD_KEEPALIVE) {
		libtrace_message_t msg = {0};
		msg.code = MESSAGE_DO_STOP;
		trace_send_message_to_thread(libtrace, &libtrace->keepalive_thread, &msg);
		pthread_join(libtrace->keepalive_thread.tid, NULL);
	}

	libtrace_change_state(libtrace, STATE_JOINED, true);
	print_memory_stats();
}

DLLEXPORT int libtrace_thread_get_message_count(libtrace_t * libtrace)
{
	libtrace_thread_t * t = get_thread_descriptor(libtrace);
	assert(t);
	return libtrace_message_queue_count(&t->messages);
}

DLLEXPORT int libtrace_thread_get_message(libtrace_t * libtrace, libtrace_message_t * message)
{
	libtrace_thread_t * t = get_thread_descriptor(libtrace);
	assert(t);
	return libtrace_message_queue_get(&t->messages, message);
}

DLLEXPORT int libtrace_thread_try_get_message(libtrace_t * libtrace, libtrace_message_t * message)
{
	libtrace_thread_t * t = get_thread_descriptor(libtrace);
	assert(t);
	return libtrace_message_queue_try_get(&t->messages, message);
}

/**
 * Return backlog indicator
 */
DLLEXPORT int trace_post_reporter(libtrace_t *libtrace)
{
	libtrace_message_t message = {0};
	message.code = MESSAGE_POST_REPORTER;
	message.sender = get_thread_descriptor(libtrace);
	return libtrace_message_queue_put(&libtrace->reporter_thread.messages, (void *) &message);
}

/**
 * Return backlog indicator
 */
DLLEXPORT int trace_send_message_to_reporter(libtrace_t * libtrace, libtrace_message_t * message)
{
	//printf("Sending message code=%d to reporter\n", message->code);
	message->sender = get_thread_descriptor(libtrace);
	return libtrace_message_queue_put(&libtrace->reporter_thread.messages, message);
}

/**
 *
 */
DLLEXPORT int trace_send_message_to_thread(libtrace_t * libtrace, libtrace_thread_t *t, libtrace_message_t * message)
{
	//printf("Sending message code=%d to reporter\n", message->code);
	message->sender = get_thread_descriptor(libtrace);
	return libtrace_message_queue_put(&t->messages, message);
}

DLLEXPORT int trace_send_message_to_perpkts(libtrace_t * libtrace, libtrace_message_t * message)
{
	int i;
	message->sender = get_thread_descriptor(libtrace);
	for (i = 0; i < libtrace->perpkt_thread_count; i++) {
		libtrace_message_queue_put(&libtrace->perpkt_threads[i].messages, message);
	}
	//printf("Sending message code=%d to reporter\n", message->code);
	return 0;
}

DLLEXPORT void libtrace_result_set_key(libtrace_result_t * result, uint64_t key) {
	result->key = key;
}
DLLEXPORT uint64_t libtrace_result_get_key(libtrace_result_t * result) {
	return result->key;
}
DLLEXPORT void libtrace_result_set_value(libtrace_result_t * result, libtrace_generic_t value) {
	result->value = value;
}
DLLEXPORT libtrace_generic_t libtrace_result_get_value(libtrace_result_t * result) {
	return result->value;
}
DLLEXPORT void libtrace_result_set_key_value(libtrace_result_t * result, uint64_t key, libtrace_generic_t value) {
	result->key = key;
	result->value = value;
}
DLLEXPORT void trace_destroy_result(libtrace_result_t ** result) {
	free(*result);
	result = NULL;
	// TODO automatically back with a free list!!
}

DLLEXPORT void * trace_get_local(libtrace_t *trace)
{
	return trace->global_blob;
}

DLLEXPORT void * trace_set_local(libtrace_t *trace, void * data)
{
	void *ret;
	pthread_mutex_lock(&trace->libtrace_lock);
	ret = trace->global_blob;
	trace->global_blob = data;
	pthread_mutex_unlock(&trace->libtrace_lock);
	return ret;
}

DLLEXPORT void * trace_get_tls(libtrace_thread_t *t)
{
	return t->user_data;
}

DLLEXPORT void * trace_set_tls(libtrace_thread_t *t, void * data)
{
	void *ret = t->user_data;
	t->user_data = data;
	return ret;
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
	assert(libtrace->combiner.publish);
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

DLLEXPORT int trace_finished(libtrace_t * libtrace) {
	// TODO I don't like using this so much, we could use state!!!
	return libtrace->perpkt_thread_states[THREAD_FINISHED] == libtrace->perpkt_thread_count;
}

DLLEXPORT int trace_parallel_config(libtrace_t *libtrace, trace_parallel_option_t option, void *value)
{
	UNUSED int ret = -1;
	switch (option) {
		case TRACE_OPTION_TICK_INTERVAL:
			libtrace->config.tick_interval = *((int *) value);
			return 1;
		case TRACE_OPTION_SET_HASHER:
			return trace_set_hasher(libtrace, (enum hasher_types) *((int *) value), NULL, NULL);
		case TRACE_OPTION_SET_PERPKT_THREAD_COUNT:
			libtrace->config.perpkt_threads = *((int *) value);
			return 1;
		case TRACE_OPTION_TRACETIME:
			if(*((int *) value))
				libtrace->tracetime = 1;
			else
				libtrace->tracetime = 0;
			return 0;
		case TRACE_OPTION_SET_CONFIG:
			libtrace->config = *((struct user_configuration *) value);
		case TRACE_OPTION_GET_CONFIG:
			*((struct user_configuration *) value) = libtrace->config;
	}
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

static void config_string(struct user_configuration *uc, char *key, size_t nkey, char *value, size_t nvalue) {
	assert(key);
	assert(value);
	assert(uc);
	if (strncmp(key, "packet_cache_size", nkey) == 0
	    || strncmp(key, "pcs", nkey) == 0) {
		uc->packet_cache_size = strtoll(value, NULL, 10);
	} else if (strncmp(key, "packet_thread_cache_size", nkey) == 0
	           || strncmp(key, "ptcs", nkey) == 0) {
		uc->packet_thread_cache_size = strtoll(value, NULL, 10);
	} else if (strncmp(key, "fixed_packet_count", nkey) == 0
	           || strncmp(key, "fpc", nkey) == 0) {
		uc->fixed_packet_count = config_bool_parse(value, nvalue);
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
		fprintf(stderr, "No matching value %s(=%s)\n", key, value);
	}
}

DLLEXPORT void parse_user_config(struct user_configuration* uc, char * str) {
	char *pch;
	char key[100];
	char value[100];
	assert(str);
	assert(uc);
	pch = strtok (str," ,.-");
	while (pch != NULL)
	{
		if (sscanf(pch, "%99[^=]=%99s", key, value) == 2) {
			config_string(uc, key, sizeof(key), value, sizeof(value));
		} else {
			fprintf(stderr, "Error parsing %s\n", pch);
		}
		pch = strtok (NULL," ,.-");
	}
}

DLLEXPORT void parse_user_config_file(struct user_configuration* uc, FILE *file) {
	char line[1024];
	while (fgets(line, sizeof(line), file) != NULL)
	{
		parse_user_config(uc, line);
	}
}

DLLEXPORT libtrace_packet_t* trace_result_packet(libtrace_t * libtrace, libtrace_packet_t * packet) {
	libtrace_packet_t* result;
	libtrace_ocache_alloc(&libtrace->packet_freelist, (void **) &result, 1, 1);
	assert(result);
	swap_packets(result, packet); // Move the current packet into our copy
	return result;
}

DLLEXPORT void trace_free_result_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {
	// Try write back the packet
	assert(packet);
	// Always release any resources this might be holding such as a slot in a ringbuffer
	trace_fin_packet(packet);
	libtrace_ocache_free(&libtrace->packet_freelist, (void **) &packet, 1, 1);
}

DLLEXPORT libtrace_info_t *trace_get_information(libtrace_t * libtrace) {
	if (libtrace->format)
		return &libtrace->format->info;
	else
		return NULL;
}
