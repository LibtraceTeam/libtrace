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

#include <pthread.h>
#include <signal.h>


extern int libtrace_parallel;

struct multithreading_stats {
	uint64_t full_queue_hits;
	uint64_t wait_for_fill_complete_hits;
} contention_stats[1024];


/**
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
	//return trace->format->pstart_input;
}

DLLEXPORT void print_contention_stats(libtrace_t *libtrace) {
	int i;
	struct multithreading_stats totals = {0};
	for (i = 0; i < libtrace->mapper_thread_count ; i++) {
		printf("\nStats for mapper thread#%d\n", i);
		printf("\tfull_queue_hits: %"PRIu64"\n", contention_stats[i].full_queue_hits);
		totals.full_queue_hits += contention_stats[i].full_queue_hits;
		printf("\twait_for_fill_complete_hits: %"PRIu64"\n", contention_stats[i].wait_for_fill_complete_hits);
		totals.wait_for_fill_complete_hits += contention_stats[i].wait_for_fill_complete_hits;
	}
	printf("\nTotals for mapper threads\n");
	printf("\tfull_queue_hits: %"PRIu64"\n", totals.full_queue_hits);
	printf("\twait_for_fill_complete_hits: %"PRIu64"\n", totals.wait_for_fill_complete_hits);

	return;
}

inline void libtrace_zero_thread(libtrace_thread_t * t) {
	t->trace = NULL;
	t->ret = NULL;
	t->type = THREAD_EMPTY;
	libtrace_zero_ringbuffer(&t->rbuffer);
	libtrace_zero_vector(&t->vector);
	libtrace_zero_deque(&t->deque);
	t->recorded_first = false;
	t->map_num = -1;
}

// Ints are aligned int is atomic so safe to read and write at same time
// However write must be locked, read doesn't (We never try read before written to table)
libtrace_thread_t * get_thread_table(libtrace_t *libtrace) {
	int i = 0;
	pthread_t tid = pthread_self();

	for (;i<libtrace->mapper_thread_count ;++i) {
		if (pthread_equal(tid, libtrace->mapper_threads[i].tid))
			return &libtrace->mapper_threads[i];
	}
	return NULL;
}

int get_thread_table_num(libtrace_t *libtrace);
DLLEXPORT int get_thread_table_num(libtrace_t *libtrace) {
	int i = 0;
	pthread_t tid = pthread_self();
	for (;i<libtrace->mapper_thread_count; ++i) {
		if (pthread_equal(tid, libtrace->mapper_threads[i].tid))
			return i;
	}
	return -1;
}

static libtrace_thread_t * get_thread_descriptor(libtrace_t *libtrace) {
	libtrace_thread_t *ret;
	if (!(ret = get_thread_table(libtrace))) {
		pthread_t tid = pthread_self();
		// Check if we are reducer or something else
		if (pthread_equal(tid, libtrace->reducer_thread.tid))
			ret = &libtrace->reducer_thread;
		else if (pthread_equal(tid, libtrace->hasher_thread.tid))
			ret = &libtrace->hasher_thread;
		else
			ret = NULL;
	}
	return ret;
}

/**
 * Holds threads in a paused state, until released by broadcasting
 * the condition mutex.
 */
static void trace_thread_pause(libtrace_t *trace) {
	printf("Pausing thread #%d\n", get_thread_table_num(trace));
	assert(pthread_mutex_lock(&trace->libtrace_lock) == 0);
	trace->perpkt_pausing++;
	pthread_cond_broadcast(&trace->perpkt_cond);
	while (!trace->started) {
		assert(pthread_cond_wait(&trace->perpkt_cond, &trace->libtrace_lock) == 0);
	}
	trace->perpkt_pausing--;
	pthread_cond_broadcast(&trace->perpkt_cond);
	assert(pthread_mutex_unlock(&trace->libtrace_lock) == 0);
	printf("Releasing thread #%d\n", get_thread_table_num(trace));
}

void* mapper_start(void *data) {
	libtrace_t *trace = (libtrace_t *)data;
	libtrace_thread_t * t;
	libtrace_message_t message;
	libtrace_packet_t *packet = NULL;

	assert(pthread_mutex_lock(&trace->libtrace_lock) == 0);
	t = get_thread_table(trace);
	assert(t);
	//printf("Yay Started Mapper thread #%d\n", (int) get_thread_table_num(trace));
	assert(pthread_mutex_unlock(&trace->libtrace_lock) == 0);

	/* ~~~~~~~~~~~ Setup complete now we loop ~~~~~~~~~~~~~~~ */
	// Send a message to say we've started

	message.code = MESSAGE_STARTED;
	message.sender = t;
	message.additional = NULL;

	// Let the per_packet function know we have started
	(*trace->per_pkt)(trace, NULL, &message, t);


	for (;;) {
		int psize;

		if (libtrace_message_queue_try_get(&t->messages, &message) != LIBTRACE_MQ_FAILED) {
			switch (message.code) {
				case MESSAGE_PAUSE:
					trace_thread_pause(trace);
					break;
				case MESSAGE_STOP:
					goto stop;
			}
			(*trace->per_pkt)(trace, NULL, &message, t);
			continue;
		}

		if (trace->mapper_thread_count == 1) {
			if (!packet) {
				if (!libtrace_ringbuffer_try_sread_bl(&trace->packet_freelist, (void **) &packet))
					packet = trace_create_packet();
			}
			assert(packet);
			if ((psize = trace_read_packet(trace, packet)) <1) {
				break;
			}
		} else {
			psize = trace_pread_packet(trace, &packet);
		}

		if (psize > 0) {
			packet = (*trace->per_pkt)(trace, packet, NULL, t);
			continue;
		}

		if (psize == -2)
			continue; // We have a message

		if (psize < 1) { // consider sending a message
			break;
		}

	}


stop:
	/* ~~~~~~~~~~~~~~ Trace is finished do tear down ~~~~~~~~~~~~~~~~~~~~~ */
	// Let the per_packet function know we have stopped
	message.code = MESSAGE_STOPPED;
	message.sender = message.additional = NULL;
	(*trace->per_pkt)(trace, NULL, &message, t);

	// And we're at the end free the memories
	assert(pthread_mutex_lock(&trace->libtrace_lock) == 0);
	t->state = THREAD_FINISHED;
	assert(pthread_mutex_unlock(&trace->libtrace_lock) == 0);

	// Notify only after we've defiantly set the state to finished
	message.code = MESSAGE_MAPPER_ENDED;
	message.additional = NULL;
	trace_send_message_to_reducer(trace, &message);

	pthread_exit(NULL);
};

/** True if trace has dedicated hasher thread otherwise false */
inline int trace_has_dedicated_hasher(libtrace_t * libtrace);
inline int trace_has_dedicated_hasher(libtrace_t * libtrace)
{
	return libtrace->hasher_thread.type == THREAD_HASHER;
}

/**
 * The start point for our single threaded hasher thread, this will read
 * and hash a packet from a data source and queue it against the correct
 * core to process it.
 */
static void* hasher_start(void *data) {
	libtrace_t *trace = (libtrace_t *)data;
	libtrace_thread_t * t;
	int i;
	libtrace_packet_t * packet;

	assert(trace_has_dedicated_hasher(trace));
	/* Wait until all threads are started and objects are initialised (ring buffers) */
	assert(pthread_mutex_lock(&trace->libtrace_lock) == 0);
	t = &trace->hasher_thread;
	assert(t->type == THREAD_HASHER && pthread_equal(pthread_self(), t->tid));
	printf("Hasher Thread started\n");
	assert(pthread_mutex_unlock(&trace->libtrace_lock) == 0);
	int pkt_skipped = 0;
	/* Read all packets in then hash and queue against the correct thread */
	while (1) {
		int thread;
		if (!pkt_skipped && !libtrace_ringbuffer_try_sread_bl(&trace->packet_freelist, (void **) &packet))
			packet = trace_create_packet();
		assert(packet);

		if (libtrace_halt) // Signal to die has been sent - TODO
			break;

		if ((packet->error = trace_read_packet(trace, packet)) <1 /*&& psize != LIBTRACE_MESSAGE_WAITING*/) {
			break; /* We are EOF or error'd either way we stop  */
		}

		/* We are guaranteed to have a hash function i.e. != NULL */
		trace_packet_set_hash(packet, (*trace->hasher)(packet, trace->hasher_data));
		thread = trace_packet_get_hash(packet) % trace->mapper_thread_count;
		/* Blocking write to the correct queue - I'm the only writer */
		if (trace->mapper_threads[thread].state != THREAD_FINISHED) {
			libtrace_ringbuffer_write(&trace->mapper_threads[thread].rbuffer, packet);
			pkt_skipped = 0;
		} else {
			pkt_skipped = 1; // Reuse that packet no one read it
		}
	}

	/* Broadcast our last failed read to all threads */
	for (i = 0; i < trace->mapper_thread_count; i++) {
		libtrace_packet_t * bcast;
		printf("Broadcasting error/EOF now the trace is over\n");
		if (i == trace->mapper_thread_count - 1) {
			bcast = packet;
		} else {
			bcast = trace_create_packet();
			bcast->error = packet->error;
		}
		assert(pthread_mutex_lock(&trace->libtrace_lock) == 0);
		if (trace->mapper_threads[i].state != THREAD_FINISHED) {
			assert(pthread_mutex_unlock(&trace->libtrace_lock) == 0);
			// Unlock early otherwise we could deadlock
			libtrace_ringbuffer_write(&trace->mapper_threads[i].rbuffer, NULL);
		} else {
			assert(pthread_mutex_unlock(&trace->libtrace_lock) == 0);
		}
	}
	// We dont need to free packet

	// And we're at the end free the memories
	t->state = THREAD_FINISHED;

	// Notify only after we've defiantly set the state to finished
	libtrace_message_t message;
	message.code = MESSAGE_MAPPER_ENDED;
	message.additional = NULL;
	trace_send_message_to_reducer(trace, &message);

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

/* Our simplest case when a thread becomes ready it can obtain a exclusive
 * lock to read a packet from the underlying trace.
 */
inline static int trace_pread_packet_first_in_first_served(libtrace_t *libtrace, libtrace_packet_t **packet)
{
	// We need this to fill the 'first' packet table
	libtrace_thread_t *t = get_thread_table(libtrace);
	if (!*packet) {
		if (!libtrace_ringbuffer_try_sread_bl(&libtrace->packet_freelist, (void **) packet))
			*packet = trace_create_packet();
	}
	assert(*packet);
	assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);
	/* Read a packet */
	(*packet)->error = trace_read_packet(libtrace, *packet);
	// Doing this inside the lock ensures the first packet is always
	// recorded first
	store_first_packet(libtrace, *packet, t);

	assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
	return (*packet)->error;
}

/**
 * For the case that we have a dedicated hasher thread
 * 1. We read a packet from our buffer
 * 2. Move that into the packet provided (packet)
 */
inline static int trace_pread_packet_hasher_thread(libtrace_t *libtrace, libtrace_packet_t **packet)
{
	int this_thread = get_thread_table_num(libtrace); // Could be worth caching ... ?
	libtrace_thread_t* t = &libtrace->mapper_threads[this_thread];

	if (*packet) // Recycle the old get the new
		if (!libtrace_ringbuffer_try_swrite_bl(&libtrace->packet_freelist, (void *) *packet))
			trace_destroy_packet(*packet);
	*packet = libtrace_ringbuffer_read(&t->rbuffer);

	if (*packet) {
		return 1;
	} else {
		printf("Got a NULL packet the trace is over\n");
		return -1; // We are done for some reason
	}
}

/**
 * Tries to read from our queue and returns 1 if a packet was retrieved
 */
static inline int try_waiting_queue(libtrace_t *libtrace, libtrace_thread_t * t, libtrace_packet_t **packet, int * ret)
{
	libtrace_packet_t* retrived_packet;

	/* Lets see if we have one waiting */
	if (libtrace_ringbuffer_try_read(&t->rbuffer, (void **) &retrived_packet)) {
		/* Copy paste from trace_pread_packet_hasher_thread() except that we try read (non-blocking) */
		assert(retrived_packet);

		if (*packet) // Recycle the old get the new
			if (!libtrace_ringbuffer_try_swrite_bl(&libtrace->packet_freelist, (void *) *packet))
				trace_destroy_packet(*packet);
		*packet = retrived_packet;
		*ret = (*packet)->error;
		return 1;
	}
	return 0;
}

/**
 * Allows us to ensure all threads are finished writing to our threads ring_buffer
 * before returning EOF/error.
 */
inline static int trace_handle_finishing_mapper(libtrace_t *libtrace, libtrace_packet_t **packet, libtrace_thread_t * t)
{
	/* We are waiting for the condition that another thread ends to check
	 * our queue for new data, once all threads end we can go to finished */
	bool complete = false;
	int ret;

	do {
		// Wait for a thread to end
		assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);

		// Check before
		if (libtrace->mappers_finishing == libtrace->mapper_thread_count) {
			complete = true;
			assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
			continue;
		}

		assert(pthread_cond_wait(&libtrace->perpkt_cond, &libtrace->libtrace_lock) == 0);

		// Check after
		if (libtrace->mappers_finishing == libtrace->mapper_thread_count) {
			complete = true;
			assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
			continue;
		}

		assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);

		// Always trying to keep our buffer empty for the unlikely case more threads than buffer space want to write into our queue
		if(try_waiting_queue(libtrace, t, packet, &ret))
			return ret;
	} while (!complete);

	// We can only end up here once all threads complete
	try_waiting_queue(libtrace, t, packet, &ret);

	return ret;
	// TODO rethink this logic fix bug here
}

/**
 * Expects the libtrace_lock to not be held
 */
inline static int trace_finish_mapper(libtrace_t *libtrace, libtrace_packet_t **packet, libtrace_thread_t * t)
{
	assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);
	t->state = THREAD_FINISHING;
	libtrace->mappers_finishing++;
	pthread_cond_broadcast(&libtrace->perpkt_cond);
	assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
	return trace_handle_finishing_mapper(libtrace, packet, t);
}

/**
 * This case is much like the dedicated hasher, except that we will become
 * hasher if we don't have a a packet waiting.
 *
 * Note: This is only every used if we have are doing hashing.
 *
 * TODO: Can block on zero copy formats such as ring: and dpdk: if the
 * queue sizes in total are larger than the ring size.
 *
 * 1. We read a packet from our buffer
 * 2. Move that into the packet provided (packet)
 */
inline static int trace_pread_packet_hash_locked(libtrace_t *libtrace, libtrace_packet_t **packet)
{
	int this_thread = get_thread_table_num(libtrace); // Could be worth caching ... ?
	libtrace_thread_t * t = &libtrace->mapper_threads[this_thread];
	int thread, ret, psize;

	while (1) {
		if(try_waiting_queue(libtrace, t, packet, &ret))
			return ret;
		// Can still block here if another thread is writing to a full queue
		assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);

		// Its impossible for our own queue to overfill, because no one can write
		// when we are in the lock
		if(try_waiting_queue(libtrace, t, packet, &ret)) {
			assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
			return ret;
		}

		// Another thread cannot write a packet because a queue has filled up. Is it ours?
		if (libtrace->mapper_queue_full) {
			contention_stats[this_thread].wait_for_fill_complete_hits++;
			assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
			continue;
		}

		if (!*packet) {
			if (!libtrace_ringbuffer_try_sread_bl(&libtrace->packet_freelist, (void **) packet))
				*packet = trace_create_packet();
		}
		assert(*packet);

		// If we fail here we can guarantee that our queue is empty (and no new data will be added because we hold the lock)
		if (libtrace_halt || ((*packet)->error = trace_read_packet(libtrace, *packet)) <1 /*&& psize != LIBTRACE_MESSAGE_WAITING*/) {
			assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
			if (libtrace_halt)
				return 0;
			else
				return (*packet)->error;
		}

		trace_packet_set_hash(*packet, (*libtrace->hasher)(*packet, libtrace->hasher_data));
		thread = trace_packet_get_hash(*packet) % libtrace->mapper_thread_count;
		if (thread == this_thread) {
			// If it's this thread we must be in order because we checked the buffer once we got the lock
			assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
			return (*packet)->error;
		}

		if (libtrace->mapper_threads[thread].state != THREAD_FINISHED) {
			while (!libtrace_ringbuffer_try_swrite_bl(&libtrace->mapper_threads[thread].rbuffer, *packet)) {
				libtrace->mapper_queue_full = true;
				assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
				contention_stats[this_thread].full_queue_hits++;
				assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);
			}
			*packet = NULL;
			libtrace->mapper_queue_full = false;
		} else {
			/* We can get here if the user closes the thread before natural completion/or error */
			assert (!"packet_hash_locked() The user terminated the trace in a abnormal manner");
		}
		assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
	}
}

/**
 * This case is much like the dedicated hasher, except that we will become
 * hasher if we don't have a a packet waiting.
 *
 * TODO: You can loose the tail of a trace if the final thread
 * fills its own queue and therefore breaks early and doesn't empty the sliding window.
 *
 * TODO: Can block on zero copy formats such as ring: and dpdk: if the
 * queue sizes in total are larger than the ring size.
 *
 * 1. We read a packet from our buffer
 * 2. Move that into the packet provided (packet)
 */
inline static int trace_pread_packet_sliding_window(libtrace_t *libtrace, libtrace_packet_t **packet)
{
	int this_thread = get_thread_table_num(libtrace); // Could be worth caching ... ?
	libtrace_thread_t * t = &libtrace->mapper_threads[this_thread];
	int ret, i, thread, psize;

	if (t->state == THREAD_FINISHING)
		return trace_handle_finishing_mapper(libtrace, packet, t);

	while (1) {
		// Check if we have packets ready
		if(try_waiting_queue(libtrace, t, packet, &ret))
			return ret;

		// We limit the number of packets we get to the size of the sliding window
		// such that it is impossible for any given thread to fail to store a packet
		assert(sem_wait(&libtrace->sem) == 0);
		/*~~~~Single threaded read of a packet~~~~*/
		assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);

		/* Re-check our queue things we might have data waiting */
		if(try_waiting_queue(libtrace, t, packet, &ret)) {
			assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
			assert(sem_post(&libtrace->sem) == 0);
			return ret;
		}

		// TODO put on *proper* condition variable
		if (libtrace->mapper_queue_full) {
			assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
			assert(sem_post(&libtrace->sem) == 0);
			contention_stats[this_thread].wait_for_fill_complete_hits++;
			continue;
		}

		if (!*packet) {
			if (!libtrace_ringbuffer_try_sread_bl(&libtrace->packet_freelist, (void **) packet))
				*packet = trace_create_packet();
		}
		assert(*packet);

		if (libtrace_halt || ((*packet)->error = trace_read_packet(libtrace, *packet)) <1 /*&& psize != LIBTRACE_MESSAGE_WAITING*/) {
			assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
			assert(sem_post(&libtrace->sem) == 0);
			// Finish this thread ensuring that any data written later by another thread is retrieved also
			if (libtrace_halt)
				return 0;
			else
				return trace_finish_mapper(libtrace, packet, t);
		}
		assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);

		/* ~~~~Multiple threads can run the hasher~~~~ */
		trace_packet_set_hash(*packet, (*libtrace->hasher)(*packet, libtrace->hasher_data));

		/* Yes this is correct opposite read lock for a write operation */
		assert(pthread_rwlock_rdlock(&libtrace->window_lock) == 0);
		if (!libtrace_slidingwindow_try_write(&libtrace->sliding_window, trace_packet_get_order(*packet), *packet))
			assert(!"Semaphore should stop us from ever overfilling the sliding window");
		assert(pthread_rwlock_unlock(&libtrace->window_lock) == 0);
		*packet = NULL;

		// Always try read any data from the sliding window
		while (libtrace_slidingwindow_read_ready(&libtrace->sliding_window)) {
			assert(pthread_rwlock_wrlock(&libtrace->window_lock) == 0);
			if (libtrace->mapper_queue_full) {
				// I might be the holdup in which case if I can read my queue I should do that and return
				if(try_waiting_queue(libtrace, t, packet, &ret)) {
					assert(pthread_rwlock_unlock(&libtrace->window_lock) == 0);
					return ret;
				}
				assert(pthread_rwlock_unlock(&libtrace->window_lock) == 0);
				continue;
			}
			// Read greedily as many as we can
			while (libtrace_slidingwindow_try_read(&libtrace->sliding_window, (void **) packet, NULL)) {
				thread = trace_packet_get_hash(*packet) % libtrace->mapper_thread_count;
				if (libtrace->mapper_threads[thread].state != THREAD_FINISHED) {
					while (!libtrace_ringbuffer_try_swrite_bl(&libtrace->mapper_threads[thread].rbuffer, *packet)) {
						if (this_thread == thread)
						{
							// TODO think about this case more because we have to stop early if this were to happen on the last read
							// before EOF/error we might not have emptied the sliding window
							printf("!~!~!~!~!~!~In this Code~!~!~!~!\n");
							// Its our queue we must have a packet to read out
							if(try_waiting_queue(libtrace, t, packet, &ret)) {
								// We must be able to write this now 100% without fail
								libtrace_ringbuffer_write(&libtrace->mapper_threads[thread].rbuffer, *packet);
								assert(sem_post(&libtrace->sem) == 0);
								assert(pthread_rwlock_unlock(&libtrace->window_lock) == 0);
								return ret;
							} else {
								assert(!"Our queue is full but I cannot read from it??");
							}
						}
						// Not us we have to give the other threads a chance to write there packets then
						libtrace->mapper_queue_full = true;
						assert(pthread_rwlock_unlock(&libtrace->window_lock) == 0);
						for (i = 0; i < libtrace->mapper_thread_count-1; i++) // Release all other threads to read there packets
							assert(sem_post(&libtrace->sem) == 0);

						contention_stats[this_thread].full_queue_hits++;
						assert(pthread_rwlock_wrlock(&libtrace->window_lock) == 0);
						// Grab these back
						for (i = 0; i < libtrace->mapper_thread_count-1; i++) // Release all other threads to read there packets
							assert(sem_wait(&libtrace->sem) == 0);
						libtrace->mapper_queue_full = false;
					}
					assert(sem_post(&libtrace->sem) == 0);
					*packet = NULL;
				} else {
					// Cannot write to a queue if no ones waiting (I think this is unreachable)
					// in the general case (unless the user ends early without proper clean up).
					assert (!"unreachable code??");
				}
			}
			assert(pthread_rwlock_unlock(&libtrace->window_lock) == 0);
		}
		// Now we go back to checking our queue anyways
	}
}


/**
 * For the first packet of each queue we keep a copy and note the system
 * time it was received at.
 *
 * This is used for finding the first packet when playing back a trace
 * in trace time. And can be used by real time applications to print
 * results out every XXX seconds.
 */
inline void store_first_packet(libtrace_t *libtrace, libtrace_packet_t *packet, libtrace_thread_t *t)
{
	if (!t->recorded_first) {
		struct timeval tv;
		libtrace_packet_t * dup;
		// For what it's worth we can call these outside of the lock
		gettimeofday(&tv, NULL);
		dup = trace_copy_packet(packet);
		assert(pthread_spin_lock(&libtrace->first_packets.lock) == 0);
		libtrace->first_packets.packets[t->map_num].packet = dup;
		//printf("Stored first packet time=%f\n", trace_get_seconds(dup));
		memcpy(&libtrace->first_packets.packets[t->map_num].tv, &tv, sizeof(tv));
		// Now update the first
		libtrace->first_packets.count++;
		if (libtrace->first_packets.count == 1) {
			// We the first entry hence also the first known packet
			libtrace->first_packets.first = t->map_num;
		} else {
			// Check if we are newer than the previous 'first' packet
			size_t first = libtrace->first_packets.first;
			if (trace_get_seconds(dup) <
				trace_get_seconds(libtrace->first_packets.packets[first].packet))
				libtrace->first_packets.first = t->map_num;
		}
		assert(pthread_spin_unlock(&libtrace->first_packets.lock) == 0);
		libtrace_message_t mesg;
		mesg.code = MESSAGE_FIRST_PACKET;
		mesg.additional = NULL;
		trace_send_message_to_reducer(libtrace, &mesg);
		t->recorded_first = true;
	}
}

/**
 * Returns 1 if its certain that the first packet is truly the first packet
 * rather than a best guess based upon threads that have published so far.
 * Otherwise 0 is returned.
 * It's recommended that this result is stored rather than calling this
 * function again.
 */
DLLEXPORT int retrive_first_packet(libtrace_t *libtrace, libtrace_packet_t **packet, struct timeval **tv)
{
	int ret = 0;
	assert(pthread_spin_lock(&libtrace->first_packets.lock) == 0);
	if (libtrace->first_packets.count) {
		*packet = libtrace->first_packets.packets[libtrace->first_packets.first].packet;
		*tv = &libtrace->first_packets.packets[libtrace->first_packets.first].tv;
		if (libtrace->first_packets.count == libtrace->mapper_thread_count) {
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
	assert(pthread_spin_unlock(&libtrace->first_packets.lock) == 0);
	return ret;
}


DLLEXPORT inline uint64_t tv_to_usec(struct timeval *tv)
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


/**
 * Delays a packets playback so the playback will be in trace time
 */
static inline void delay_tracetime(libtrace_t *libtrace, libtrace_packet_t *packet, libtrace_thread_t *t) {
	struct timeval curr_tv, pkt_tv;
	uint64_t next_release = t->tracetime_offset_usec; // Time at which to release the packet
	uint64_t curr_usec;
	/* Tracetime we might delay releasing this packet */
	if (!t->tracetime_offset_usec) {
		libtrace_packet_t * first_pkt;
		struct timeval *sys_tv;
		int64_t initial_offset;
		int stable = retrive_first_packet(libtrace, &first_pkt, &sys_tv);
		assert(first_pkt);
		pkt_tv = trace_get_timeval(first_pkt);
		initial_offset = (int64_t)tv_to_usec(sys_tv) - (int64_t)tv_to_usec(&pkt_tv);
		if (stable)
			// 0->1 because 0 is used to mean unset
			t->tracetime_offset_usec = initial_offset ? initial_offset: 1;
		next_release = initial_offset;
	}
	/* next_release == offset */
	pkt_tv = trace_get_timeval(packet);
	next_release += tv_to_usec(&pkt_tv);
	gettimeofday(&curr_tv, NULL);
	curr_usec = tv_to_usec(&curr_tv);
	if (next_release > curr_usec) {
		// We need to wait
		struct timeval delay_tv = usec_to_tv(next_release-curr_usec);
		//printf("WAITING for %d.%d next=%"PRIu64" curr=%"PRIu64" seconds packettime %f\n", delay_tv.tv_sec, delay_tv.tv_usec, next_release, curr_usec, trace_get_seconds(packet));
		select(0, NULL, NULL, NULL, &delay_tv);
	}
}

/* Read one packet from the trace into a buffer. Note that this function will
 * block until a packet is read (or EOF is reached).
 *
 * @param libtrace 	the libtrace opaque pointer
 * @param packet  	the packet opaque pointer
 * @returns 0 on EOF, negative value on error
 *
 * Note this is identical to read_packet but calls pread_packet instead of
 * read packet in the format.
 *
 */
static inline int trace_pread_packet_wrapper(libtrace_t *libtrace, libtrace_packet_t *packet) {

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

	if (libtrace->format->read_packet) {
		do {
			size_t ret;
			/* Finalise the packet, freeing any resources the format module
			 * may have allocated it and zeroing all data associated with it.
			 */
			trace_fin_packet(packet);
			/* Store the trace we are reading from into the packet opaque
			 * structure */
			packet->trace = libtrace;
			ret=libtrace->format->pread_packet(libtrace,packet);
			if (ret==(size_t)-1 || ret==(size_t)-2 || ret==0) {
				return ret;
			}
			if (libtrace->filter) {
				/* If the filter doesn't match, read another
				 * packet
				 */
				if (!trace_apply_filter(libtrace->filter,packet)){
					++libtrace->filtered_packets;
					continue;
				}
			}
			if (libtrace->snaplen>0) {
				/* Snap the packet */
				trace_set_capture_length(packet,
						libtrace->snaplen);
			}
			trace_packet_set_order(packet, libtrace->accepted_packets);
			++libtrace->accepted_packets;
			return ret;
		} while(1);
	}
	trace_set_err(libtrace,TRACE_ERR_UNSUPPORTED,"This format does not support reading packets\n");
	return ~0U;
}

/**
 * Read a packet from the parallel trace
 */
DLLEXPORT int trace_pread_packet(libtrace_t *libtrace, libtrace_packet_t **packet)
{
	int ret;
	libtrace_thread_t *t = get_thread_table(libtrace);

	// Cleanup the packet passed back
	if (*packet)
		trace_fin_packet(*packet);

	if (libtrace->format->pread_packet) {
		if (!*packet)
			*packet = trace_create_packet();
		ret = trace_pread_packet_wrapper(libtrace, *packet);
	} else	if (!libtrace->hasher) {
		/* We don't care about which core a packet goes to */
		ret =  trace_pread_packet_first_in_first_served(libtrace, packet);
	} else if (trace_has_dedicated_hasher(libtrace)) {
		ret = trace_pread_packet_hasher_thread(libtrace, packet);
	} else if (libtrace->reducer_flags & MAPPER_USE_SLIDING_WINDOW) {
		ret = trace_pread_packet_sliding_window(libtrace, packet);
	} else {
		ret = trace_pread_packet_hash_locked(libtrace, packet);
	}

	// Formats can also optionally do this internally to ensure the first
	// packet is always reported correctly
	if (ret > 0) {
		store_first_packet(libtrace, *packet, t);
		if (libtrace->tracetime)
			delay_tracetime(libtrace, *packet, t);
	}

	return ret;
}

/* Starts perpkt threads
 * @return threads_started
 */
static inline int trace_start_perpkt_threads (libtrace_t *libtrace) {
	int i;

	for (i = 0; i < libtrace->mapper_thread_count; i++) {
		libtrace_thread_t *t = &libtrace->mapper_threads[i];
		assert(pthread_create(&t->tid, NULL, mapper_start, (void *) libtrace) == 0);
	}
	return libtrace->mapper_thread_count;
}

/* Start an input trace in a parallel fashion.
 *
 * @param libtrace	the input trace to start
 * @param global_blob some global data you can share with the new thread
 * @returns 0 on success
 */
DLLEXPORT int trace_pstart(libtrace_t *libtrace, void* global_blob, fn_per_pkt per_pkt, fn_reducer reducer)
{
	int i;
	sigset_t sig_before, sig_block_all;

	assert(libtrace);
	if (trace_is_err(libtrace))
		return -1;;
	if (libtrace->perpkt_pausing != 0) {
		printf("Restarting trace\n");
		libtrace->format->pstart_input(libtrace);
		// TODO empty any queues out here //
		assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);
		libtrace->started = true;
		assert(pthread_cond_broadcast(&libtrace->perpkt_cond) == 0);
		assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
		return 0;
	}

	libtrace_parallel = 1;

	// Store the user defined things against the trace
	libtrace->global_blob = global_blob;
	libtrace->per_pkt = per_pkt;
	libtrace->reducer = reducer;
	libtrace->mappers_finishing = 0;
	// libtrace->hasher = &rand_hash; /* Hasher now set via option */

	assert(pthread_mutex_init(&libtrace->libtrace_lock, NULL) == 0);
	assert(pthread_cond_init(&libtrace->perpkt_cond, NULL) == 0);
	assert(pthread_rwlock_init(&libtrace->window_lock, NULL) == 0);
	assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);

	// Set default buffer sizes
	if (libtrace->mapper_buffer_size <= 0)
		libtrace->mapper_buffer_size = 1000;

	if (libtrace->mapper_thread_count <= 0)
		libtrace->mapper_thread_count = 2; // XXX scale to system

	if(libtrace->packet_freelist_size <= 0)
		libtrace->packet_freelist_size = (libtrace->mapper_buffer_size + 1) * libtrace->mapper_thread_count;

	if(libtrace->packet_freelist_size <
		(libtrace->mapper_buffer_size + 1) * libtrace->mapper_thread_count)
		fprintf(stderr, "WARNING deadlocks may occur and extra memory allocating buffer sizes (packet_freelist_size) mismatched\n");

	libtrace->started=true; // Before we start the threads otherwise we could have issues
	/* Disable signals - Pthread signal handling */

	sigemptyset(&sig_block_all);

	assert(pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) == 0);

	// If we are using a hasher start it
	if (libtrace->hasher && libtrace->hasher_thread.type == THREAD_HASHER) {
		libtrace_thread_t *t = &libtrace->hasher_thread;
		t->trace = libtrace;
		t->ret = NULL;
		t->type = THREAD_HASHER;
		t->state = THREAD_RUNNING;
		assert(pthread_create(&t->tid, NULL, hasher_start, (void *) libtrace) == 0);
	} else {
		libtrace->hasher_thread.type = THREAD_EMPTY;
	}
	libtrace_ringbuffer_init(&libtrace->packet_freelist, libtrace->packet_freelist_size, LIBTRACE_RINGBUFFER_POLLING);
	libtrace_slidingwindow_init(&libtrace->sliding_window, libtrace->packet_freelist_size, 0);
	assert(sem_init(&libtrace->sem, 0, libtrace->packet_freelist_size) == 0);
	// This will be applied to every new thread that starts, i.e. they will block all signals
	// Lets start a fixed number of reading threads

	// For now we never have a dedicated thread for the reducer
	// i.e. This main thread is used as the reducer
	libtrace->reducer_thread.tid = pthread_self();
	libtrace->reducer_thread.type = THREAD_REDUCER;
	libtrace->reducer_thread.state = THREAD_RUNNING;
	libtrace_message_queue_init(&libtrace->reducer_thread.messages, sizeof(libtrace_message_t));

	/* Ready some storages */
	libtrace->first_packets.first = 0;
	libtrace->first_packets.count = 0;
	assert(pthread_spin_init(&libtrace->first_packets.lock, 0) == 0);
	libtrace->first_packets.packets = calloc(libtrace->mapper_thread_count, sizeof(struct  __packet_storage_magic_type));


	/* Start all of our mapper threads */
	libtrace->mapper_threads = calloc(sizeof(libtrace_thread_t), libtrace->mapper_thread_count);
	for (i = 0; i < libtrace->mapper_thread_count; i++) {
		libtrace_thread_t *t = &libtrace->mapper_threads[i];
		t->trace = libtrace;
		t->ret = NULL;
		t->type = THREAD_MAPPER;
		t->state = THREAD_RUNNING;
		t->user_data = NULL;
		// t->tid DONE on create
		t->map_num = i;
		if (libtrace->hasher)
			libtrace_ringbuffer_init(&t->rbuffer, libtrace->mapper_buffer_size, LIBTRACE_RINGBUFFER_POLLING);
		// Depending on the mode vector or deque might be chosen
		libtrace_vector_init(&t->vector, sizeof(libtrace_result_t));
		libtrace_deque_init(&t->deque, sizeof(libtrace_result_t));
		libtrace_message_queue_init(&t->messages, sizeof(libtrace_message_t));
		t->tmp_key = 0;
		t->tmp_data = NULL;
		t->recorded_first = false;
		assert(pthread_spin_init(&t->tmp_spinlock, 0) == 0);
		t->tracetime_offset_usec = 0;;
	}

	int threads_started = 0;
	/* Setup the trace and start our threads */
	if (libtrace->mapper_thread_count > 1 && libtrace->format->pstart_input) {
		printf("This format has direct support for p's\n");
		threads_started = libtrace->format->pstart_input(libtrace);
	} else {
		if (libtrace->format->start_input) {
			threads_started=libtrace->format->start_input(libtrace);
		}
	}
	if (threads_started == 0)
		threads_started = trace_start_perpkt_threads(libtrace);


	// Revert back - Allow signals again
	assert(pthread_sigmask(SIG_SETMASK, &sig_before, NULL) == 0);
	assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);

	if (threads_started < 0)
		// Error
		return threads_started;

	// TODO fix these leaks etc
	if (libtrace->mapper_thread_count != threads_started)
		printf("Warning started threads not equal requested s=%d r=%d", threads_started, libtrace->mapper_thread_count);


	return 0;
}

/**
 * Pauses a trace, this should only be called by the main thread
 * 1. Set started = false 
 * 2. All perpkt threads are paused waiting on a condition var
 * 3. Then call ppause on the underlying format if found
 * 4. Return with perpkt_pausing set to mapper_count (Used when restarting so we reuse the threads)
 * 
 * Once done you should be a able to modify the trace setup and call pstart again
 * TODO handle changing thread numbers
 */
DLLEXPORT int trace_ppause(libtrace_t *libtrace)
{
	libtrace_thread_t *t;
	int i;
	assert(libtrace);
	if (!libtrace->started) {
		trace_set_err(libtrace,TRACE_ERR_BAD_STATE, "You must call trace_start() before calling trace_ppause()");
		return -1;
	}

	t = get_thread_table(libtrace);

	// Set paused
	assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);
	libtrace->started = false;
	pthread_cond_broadcast(&libtrace->perpkt_cond);
	assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);

	printf("Sending messages \n");
	// Stop threads, skip this one if its a mapper
	for (i = 0; i < libtrace->mapper_thread_count; i++) {
		if (&libtrace->mapper_threads[i] != t) {
			libtrace_message_t message;
			message.code = MESSAGE_PAUSE;
			message.additional = NULL;
			trace_send_message_to_thread(libtrace, &libtrace->mapper_threads[i], &message);
		}
	}

	// Formats must support native message handling if a message is ready
	// Approach per Perry's suggestion is a non-blocking read
	// followed by a blocking read. XXX STRIP THIS OUT

	if (t) {
		// A mapper is doing the pausing interesting fake a extra thread paused
		// We rely on the user to not return before starting the trace again
		assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);
		libtrace->perpkt_pausing++;
		assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
	}

	printf("Threads are pausing\n");

	// Do a early pause to kick threads out - XXX testing for int
	if (libtrace->format->pause_input)
			libtrace->format->pause_input(libtrace);

	// Wait for all threads to pause
	assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);
	while (libtrace->mapper_thread_count != libtrace->perpkt_pausing) {
		assert(pthread_cond_wait(&libtrace->perpkt_cond, &libtrace->libtrace_lock) == 0);
	}
	assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);

	printf("Threads have paused\n");

	if (trace_supports_parallel(libtrace)) {
		if (libtrace->format->ppause_input)
			libtrace->format->ppause_input(libtrace);
		// TODO What happens if we don't have pause input??
	} else {
		printf("Trace is not parallel so we are doing a normal pause %s\n", libtrace->uridata);
		// This doesn't really work because this could be called by any thread
		// Maybe we should grab the lock here??
		if (libtrace->format->pause_input)
			libtrace->format->pause_input(libtrace);
		// TODO What happens if we don't have pause input??
	}

	return 0;
}

/**
 * Stop trace finish prematurely as though it meet an EOF
 * This should only be called by the main thread
 * 1. Calls ppause
 * 2. Sends a message asking for threads to finish
 * 
 */
DLLEXPORT int trace_pstop(libtrace_t *libtrace)
{
	int i;
	if (!libtrace->started) {
		trace_set_err(libtrace,TRACE_ERR_BAD_STATE, "You must call trace_start() before calling trace_pstop()");
		return -1;
	}

	// Ensure all threads have paused and the underlying trace format has
	// been closed
	trace_ppause(libtrace);

	// Now send a message asking the threads to stop
	// This will be retrieved before trying to read another packet
	for (i = 0; i < libtrace->mapper_thread_count; i++) {
		libtrace_message_t message;
		message.code = MESSAGE_STOP;
		message.additional = NULL;
		trace_send_message_to_thread(libtrace, &libtrace->mapper_threads[i], &message);
	}

	// Now release the threads and let them stop
	assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);
	libtrace->started = true;
	assert(pthread_cond_broadcast(&libtrace->perpkt_cond) == 0);
	assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
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
		trace->hasher_data = hasher;
	} else {
		trace->hasher = NULL;
		// TODO consider how to handle freeing this
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
					trace->hasher = toeplitz_hash_packet;
					trace->hasher_data = calloc(1, sizeof(toeplitz_conf_t));
					toeplitz_init_config(trace->hasher_data, 1);
					return 0;
				case HASHER_UNIDIRECTIONAL:
					trace->hasher = toeplitz_hash_packet;
					trace->hasher_data = calloc(1, sizeof(toeplitz_conf_t));
					toeplitz_init_config(trace->hasher_data, 1);
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

	/* Firstly wait for the mapper threads to finish, since these are
	 * user controlled */
	for (i=0; i< libtrace->mapper_thread_count; i++) {
		//printf("Waiting to join with mapper #%d\n", i);
		assert(pthread_join(libtrace->mapper_threads[i].tid, NULL) == 0);
		//printf("Joined with mapper #%d\n", i);
		// So we must do our best effort to empty the queue - so
		// the producer (or any other threads) don't block.
		libtrace_packet_t * packet;
		// Mark that we are no longer accepting packets
		assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);
		libtrace->mapper_threads[i].state = THREAD_FINISHED; // Important we are finished before we empty the buffer
		assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
		while(libtrace_ringbuffer_try_read(&libtrace->mapper_threads[i].rbuffer, (void **) &packet))
			if (packet) // This could be NULL iff the mapper finishes early
				trace_destroy_packet(packet);
	}

	/* Now the hasher */
	// XXX signal it to stop
	if (trace_has_dedicated_hasher(libtrace)) {
		printf("Waiting to join with the hasher\n");
		pthread_join(libtrace->hasher_thread.tid, NULL);
		printf("Joined with with the hasher\n");
		libtrace->hasher_thread.state = THREAD_FINISHED;
	}

	// Now that everything is finished nothing can be touching our
	// buffers so clean them up
	for (i = 0; i < libtrace->mapper_thread_count; i++) {
		// Its possible 1 packet got added by the reducer (or 1 per any other thread) since we cleaned up
		// if they lost timeslice before-during a write
		libtrace_packet_t * packet;
		while(libtrace_ringbuffer_try_read(&libtrace->mapper_threads[i].rbuffer, (void **) &packet))
			trace_destroy_packet(packet);
		if (libtrace->hasher) {
			assert(libtrace_ringbuffer_is_empty(&libtrace->mapper_threads[i].rbuffer));
			libtrace_ringbuffer_destroy(&libtrace->mapper_threads[i].rbuffer);
		}
		// Cannot destroy vector yet, this happens with trace_destroy
	}

	// Lets mark this as done for now
	libtrace->joined = true;
}

// Don't use extra overhead = :( directly place in storage structure using
// post
DLLEXPORT libtrace_result_t *trace_create_result()
{
	libtrace_result_t *result = malloc(sizeof(libtrace_result_t));
	assert(result);
	result->key = 0;
	result->value = NULL;
	// TODO automatically back with a free list!!
	return result;
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
DLLEXPORT int trace_post_reduce(libtrace_t *libtrace)
{
	libtrace_message_t message = {0};
	message.code = MESSAGE_POST_REDUCE;
	message.additional = NULL;
	message.sender = get_thread_descriptor(libtrace);
	return libtrace_message_queue_put(&libtrace->reducer_thread.messages, (void *) &message);
}

/**
 * Return backlog indicator
 */
DLLEXPORT int trace_send_message_to_reducer(libtrace_t * libtrace, libtrace_message_t * message)
{
	//printf("Sending message code=%d to reducer\n", message->code);
	message->sender = get_thread_descriptor(libtrace);
	return libtrace_message_queue_put(&libtrace->reducer_thread.messages, message);
}

/**
 *
 */
DLLEXPORT int trace_send_message_to_thread(libtrace_t * libtrace, libtrace_thread_t *t, libtrace_message_t * message)
{
	//printf("Sending message code=%d to reducer\n", message->code);
	message->sender = get_thread_descriptor(libtrace);
	return libtrace_message_queue_put(&t->messages, message);
}

DLLEXPORT void libtrace_result_set_key(libtrace_result_t * result, uint64_t key) {
	result->key = key;
}
DLLEXPORT uint64_t libtrace_result_get_key(libtrace_result_t * result) {
	return result->key;
}
DLLEXPORT void libtrace_result_set_value(libtrace_result_t * result, void * value) {
	result->value = value;
}
DLLEXPORT void* libtrace_result_get_value(libtrace_result_t * result) {
	return result->value;
}
DLLEXPORT void libtrace_result_set_key_value(libtrace_result_t * result, uint64_t key, void * value) {
	result->key = key;
	result->value = value;
}
DLLEXPORT void trace_destroy_result(libtrace_result_t ** result) {
	free(*result);
	result = NULL;
	// TODO automatically back with a free list!!
}

DLLEXPORT void * trace_get_global(libtrace_t *trace)
{
	return trace->global_blob;
}

DLLEXPORT void * trace_set_global(libtrace_t *trace, void * data)
{
	if (trace->global_blob && trace->global_blob != data) {
		void * ret = trace->global_blob;
		trace->global_blob = data;
		return ret;
	} else {
		trace->global_blob = data;
		return NULL;
	}
}

DLLEXPORT void * trace_get_tls(libtrace_thread_t *t)
{
	return t->user_data;
}

DLLEXPORT void * trace_set_tls(libtrace_thread_t *t, void * data)
{
	if(t->user_data && t->user_data != data) {
		void *ret = t->user_data;
		t->user_data = data;
		return ret;
	} else {
		t->user_data = data;
		return NULL;
	}
}

/**
 * Note: This function grabs a lock and expects trace_update_inprogress_result
 * to be called to release the lock.
 *
 * Expected to be used in trace-time situations to allow a result to be pending
 * a publish that can be taken by the reducer before publish if it wants to
 * publish a result. Such as publish a result every second but a queue hasn't
 * processed a packet (or is overloaded) and hasn't published yet.
 *
 * Currently this only supports a single temporary result,
 * as such if a key is different to the current temporary result the existing
 * one will be published and NULL returned.
 */
DLLEXPORT void * trace_retrive_inprogress_result(libtrace_t *libtrace, uint64_t key)
{
	int this_thread = get_thread_table_num(libtrace); // Could be worth caching ... ?
	libtrace_thread_t * t = &libtrace->mapper_threads[this_thread];

	assert (pthread_spin_lock(&t->tmp_spinlock) == 0);
	if (t->tmp_key != key) {
		if (t->tmp_data) {
			//printf("publising data key=%"PRIu64"\n", t->tmp_key);
			trace_publish_result(libtrace, t->tmp_key, t->tmp_data);
		}
		t->tmp_data = NULL;
		t->tmp_key = key;
	}
	return t->tmp_data;
}

/**
 * Updates a temporary result and releases the lock previously grabbed by trace_retrive_inprogress_result
 */
DLLEXPORT void trace_update_inprogress_result(libtrace_t *libtrace, uint64_t key, void * value)
{
	int this_thread = get_thread_table_num(libtrace); // Could be worth caching ... ?
	libtrace_thread_t * t = &libtrace->mapper_threads[this_thread];
	if (t->tmp_key != key) {
		if (t->tmp_data) {
			printf("BAD publihsing data key=%"PRIu64"\n", t->tmp_key);
			trace_publish_result(libtrace, t->tmp_key, t->tmp_data);
		}
		t->tmp_key = key;
	}
	t->tmp_data = value;
	assert (pthread_spin_unlock(&t->tmp_spinlock) == 0);
}

/**
 * Publish to the reduce queue, return
 */
DLLEXPORT void trace_publish_result(libtrace_t *libtrace, uint64_t key, void * value) {
	libtrace_result_t res;
	// Who am I???
	int this_thread = get_thread_table_num(libtrace); // Could be worth caching ... ?
	libtrace_thread_t * t = &libtrace->mapper_threads[this_thread];
	// Now put it into my table
	static __thread int count = 0;


	libtrace_result_set_key_value(&res, key, value);
	/*
	if (count == 1)
		printf("My vector size is %d\n", libtrace_vector_get_size(&t->vector));
	count = (count+1) %1000;
	libtrace_vector_push_back(&t->vector, &res); // Automatically locking for us :)
	*/
	/*if (count == 1)
		printf("My vector size is %d\n", libtrace_deque_get_size(&t->deque));
	count = (count+1)%1000;*/
	if (libtrace->reducer_flags & (REDUCE_SEQUENTIAL | REDUCE_ORDERED)) {
		if (libtrace_deque_get_size(&t->deque) >= 800) {
			trace_post_reduce(libtrace);
		}
		//while (libtrace_deque_get_size(&t->deque) >= 1000)
		//	sched_yield();
		libtrace_deque_push_back(&t->deque, &res); // Automatically locking for us :)
	} else {
		//while (libtrace_vector_get_size(&t->vector) >= 1000)
		//	sched_yield();

		if (libtrace_deque_get_size(&t->deque) >= 800) {
			trace_post_reduce(libtrace);
		}
		libtrace_vector_push_back(&t->vector, &res); // Automatically locking for us :)
	}
}


static int compareres(const void* p1, const void* p2)
{
	if (libtrace_result_get_key((libtrace_result_t *) p1) < libtrace_result_get_key((libtrace_result_t *) p2))
		return -1;
	if (libtrace_result_get_key((libtrace_result_t *) p1) == libtrace_result_get_key((libtrace_result_t *) p2))
		return 0;
	else
		return 1;
}

/* Retrieves all results with the key requested from the temporary result
 * holding zone.
 */
DLLEXPORT int trace_get_results_check_temp(libtrace_t *libtrace, libtrace_vector_t *results, uint64_t key)
{
	int i;

	libtrace_vector_empty(results);
	// Check all of the temp queues
	for (i = 0; i < libtrace->mapper_thread_count; ++i) {
		libtrace_result_t r = {0,0};
		assert (pthread_spin_lock(&libtrace->mapper_threads[i].tmp_spinlock) == 0);
		if (libtrace->mapper_threads[i].tmp_key == key) {
			libtrace_result_set_key_value(&r, key, libtrace->mapper_threads[i].tmp_data);
			libtrace->mapper_threads[i].tmp_data = NULL;
			printf("Found in temp queue\n");
		}
		assert (pthread_spin_unlock(&libtrace->mapper_threads[i].tmp_spinlock) == 0);
		if (libtrace_result_get_value(&r)) {
			// Got a result still in temporary
			printf("Publishing from temp queue\n");
			libtrace_vector_push_back(results, &r);
		} else {
			// This might be waiting on the actual queue
			libtrace_queue_t *v = &libtrace->mapper_threads[i].deque;
			if (libtrace_deque_peek_front(v, (void *) &r) &&
					libtrace_result_get_value(&r)) {
				assert (libtrace_deque_pop_front(&libtrace->mapper_threads[i].deque, (void *) &r) == 1);
				printf("Found in real queue\n");
				libtrace_vector_push_back(results, &r);
			} // else no data (probably means no packets)
			else {
				printf("Result missing in real queue\n");
			}
		}
	}
	//printf("Loop done yo, that means we've got #%d results to print fool!\n", libtrace_vector_get_size(results));
	return libtrace_vector_get_size(results);
}

DLLEXPORT int trace_get_results(libtrace_t *libtrace, libtrace_vector_t * results) {
	int i;
	int flags = libtrace->reducer_flags; // Hint these aren't a changing

	libtrace_vector_empty(results);

	/* Here we assume queues are in order ascending order and they want
	 * the smallest result first. If they are not in order the results
	 * may not be in order.
	 */
	if (flags & (REDUCE_SEQUENTIAL | REDUCE_ORDERED)) {
		int live_count = 0;
		bool live[libtrace->mapper_thread_count]; // Set if a trace is alive
		uint64_t key[libtrace->mapper_thread_count]; // Cached keys
		uint64_t min_key = UINT64_MAX; // XXX use max int here stdlimit.h?
		int min_queue = -1;

		/* Loop through check all are alive (have data) and find the smallest */
		for (i = 0; i < libtrace->mapper_thread_count; ++i) {
			libtrace_queue_t *v = &libtrace->mapper_threads[i].deque;
			if (libtrace_deque_get_size(v) != 0) {
				libtrace_result_t r;
				libtrace_deque_peek_front(v, (void *) &r);
				live_count++;
				live[i] = 1;
				key[i] = libtrace_result_get_key(&r);
				if (i==0 || min_key > key[i]) {
					min_key = key[i];
					min_queue = i;
				}
			} else {
				live[i] = 0;
			}
		}

		/* Now remove the smallest and loop - special case if all threads have joined we always flush whats left */
		while ((live_count == libtrace->mapper_thread_count) || (live_count &&
				((flags & REDUCE_SEQUENTIAL && min_key == libtrace->expected_key) ||
				libtrace->joined))) {
			/* Get the minimum queue and then do stuff */
			libtrace_result_t r;

			assert (libtrace_deque_pop_front(&libtrace->mapper_threads[min_queue].deque, (void *) &r) == 1);
			libtrace_vector_push_back(results, &r);

			// We expect the key we read +1 now
			libtrace->expected_key = key[min_queue] + 1;

			// Now update the one we just removed
			if (libtrace_deque_get_size(&libtrace->mapper_threads[min_queue].deque) )
			{
				libtrace_deque_peek_front(&libtrace->mapper_threads[min_queue].deque, (void *) &r);
				key[min_queue] = libtrace_result_get_key(&r);
				if (key[min_queue] <= min_key) {
					// We are still the smallest, might be out of order though :(
					min_key = key[min_queue];
				} else {
					min_key = key[min_queue]; // Update our minimum
					// Check all find the smallest again - all are alive
					for (i = 0; i < libtrace->mapper_thread_count; ++i) {
						if (live[i] && min_key > key[i]) {
							min_key = key[i];
							min_queue = i;
						}
					}
				}
			} else {
				live[min_queue] = 0;
				live_count--;
				min_key = UINT64_MAX; // Update our minimum
				// Check all find the smallest again - all are alive
				for (i = 0; i < libtrace->mapper_thread_count; ++i) {
					// Still not 100% TODO (what if order is wrong or not increasing)
					if (live[i] && min_key >= key[i]) {
						min_key = key[i];
						min_queue = i;
					}
				}
			}
		}
	} else { // Queues are not in order - return all results in the queue
		for (i = 0; i < libtrace->mapper_thread_count; i++) {
			libtrace_vector_append(results, &libtrace->mapper_threads[i].vector);
		}
		if (flags & REDUCE_SORT) {
			qsort(results->elements, results->size, results->element_size, &compareres);
		}
	}
	return libtrace_vector_get_size(results);
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
	int i;
	int b = 0;
	// TODO I don't like using this so much
	//assert(pthread_mutex_lock(&libtrace->libtrace_lock) == 0);
	for (i = 0; i < libtrace->mapper_thread_count; i++) {
		if (libtrace->mapper_threads[i].state == THREAD_RUNNING)
			b++;
	}
	//assert(pthread_mutex_unlock(&libtrace->libtrace_lock) == 0);
	return !b;
}

DLLEXPORT int trace_parallel_config(libtrace_t *libtrace, trace_parallel_option_t option, void *value)
{
	int ret = -1;
	switch (option) {
		case TRACE_OPTION_SET_HASHER:
			return trace_set_hasher(libtrace, (enum hasher_types) *((int *) value), NULL, NULL);
		case TRACE_OPTION_SET_MAPPER_BUFFER_SIZE:
			libtrace->mapper_buffer_size = *((int *) value);
			return 1;
		case TRACE_OPTION_SET_PACKET_FREELIST_SIZE:
			libtrace->packet_freelist_size = *((int *) value);
			return 1;
		case TRACE_OPTION_SET_MAPPER_THREAD_COUNT:
			libtrace->mapper_thread_count = *((int *) value);
			return 1;
		case TRACE_DROP_OUT_OF_ORDER:
			if (*((int *) value))
				libtrace->reducer_flags |= REDUCE_DROP_OOO;
			else
				libtrace->reducer_flags &= ~REDUCE_DROP_OOO;
			return 1;
		case TRACE_OPTION_SEQUENTIAL:
			if (*((int *) value))
				libtrace->reducer_flags |= REDUCE_SEQUENTIAL;
			else
				libtrace->reducer_flags &= ~REDUCE_SEQUENTIAL;
			return 1;
		case TRACE_OPTION_ORDERED:
			if (*((int *) value))
				libtrace->reducer_flags |= REDUCE_ORDERED;
			else
				libtrace->reducer_flags &= ~REDUCE_ORDERED;
			return 1;
		case TRACE_OPTION_USE_DEDICATED_HASHER:
			if (*((int *) value))
				libtrace->hasher_thread.type = THREAD_HASHER;
			else
				libtrace->hasher_thread.type = THREAD_EMPTY;
			return 1;
		case TRACE_OPTION_USE_SLIDING_WINDOW_BUFFER:
			if (*((int *) value))
				libtrace->reducer_flags |= MAPPER_USE_SLIDING_WINDOW;
			else
				libtrace->reducer_flags &= ~MAPPER_USE_SLIDING_WINDOW;
			return 1;
		case TRACE_OPTION_TRACETIME:
			if(*((int *) value))
				libtrace->tracetime = 1;
			else
				libtrace->tracetime = 0;
			return 0;
	}
	return 0;
}

DLLEXPORT libtrace_packet_t* trace_result_packet(libtrace_t * libtrace, libtrace_packet_t * packet) {
	libtrace_packet_t* result;
	if (!libtrace_ringbuffer_try_sread_bl(&libtrace->packet_freelist, (void **) &result))
		result = trace_create_packet();
	assert(result);
	swap_packets(result, packet); // Move the current packet into our copy
	return result;
}

DLLEXPORT void trace_free_result_packet(libtrace_t * libtrace, libtrace_packet_t * packet) {
	// Try write back the packet
	assert(packet);
	// Always release any resources this might be holding such as a slot in a ringbuffer
	trace_fin_packet(packet);
	if (!libtrace_ringbuffer_try_swrite_bl(&libtrace->packet_freelist, packet)) {
		/* We couldn't, oh well lets just destroy it - XXX consider non managed formats i.e. rings buffers loosing packets and jamming up :( */
		//assert(1 == 90);
		trace_destroy_packet(packet);
	}
}
