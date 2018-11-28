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


#include "libtrace.h"
#include "libtrace_int.h"
#include "data-struct/deque.h"
#include <assert.h>
#include <stdlib.h>

/* TODO hook up configuration option for sequentual packets again */

static int init_combiner(libtrace_t *t, libtrace_combine_t *c) {
	int i = 0;
	if (trace_get_perpkt_threads(t) <= 0) {
		trace_set_err(t, TRACE_ERR_INIT_FAILED, "You must have atleast 1 processing thread");
		return -1;
	}
	libtrace_queue_t *queues;
	c->queues = calloc(sizeof(libtrace_queue_t), trace_get_perpkt_threads(t));
	queues = c->queues;
	for (i = 0; i < trace_get_perpkt_threads(t); ++i) {
		libtrace_deque_init(&queues[i], sizeof(libtrace_result_t));
	}
	return 0;
}

static void publish(libtrace_t *trace, int t_id, libtrace_combine_t *c, libtrace_result_t *res) {
	libtrace_queue_t *queue = &((libtrace_queue_t*)c->queues)[t_id];
	//while (libtrace_deque_get_size(&t->deque) >= 1000)
	//	sched_yield();
	libtrace_deque_push_back(queue, res); // Automatically locking for us :)

	if (libtrace_deque_get_size(queue) >= trace->config.reporter_thold) {
		trace_post_reporter(trace);
	}
}

inline static int peek_queue(libtrace_t *trace, libtrace_combine_t *c,
                libtrace_queue_t *v, uint64_t *key, libtrace_result_t *peeked) {

        libtrace_result_t r;
        if (!peeked) {
                libtrace_deque_peek_front(v, (void *) &r);
                peeked = &r;
        }

        /* Ticks are a bit tricky, because we can get TS
         * ticks in amongst packets indexed by their cardinal
         * order and vice versa. Also, every thread will
         * produce an equivalent tick and we should really
         * combine those into a single tick for the reporter
         * thread.
         */

        if (peeked->type == RESULT_TICK_INTERVAL) {
                if (peeked->key > c->last_ts_tick) {
                        c->last_ts_tick = peeked->key;

                        /* Pass straight to reporter */
                        libtrace_generic_t gt = {.res = peeked};
                        ASSERT_RET (libtrace_deque_pop_front(v, (void *) peeked), == 1);
                        send_message(trace, &trace->reporter_thread,
                                        MESSAGE_RESULT, gt,
                                        &trace->reporter_thread);
                        return 0;

                } else {
                        /* Duplicate -- pop it */
                        ASSERT_RET (libtrace_deque_pop_front(v, (void *) peeked), == 1);
                        return 0;
                }
        }

        if (peeked->type == RESULT_TICK_COUNT) {
                if (peeked->key > c->last_count_tick) {
                        c->last_count_tick = peeked->key;

                        /* Tick doesn't match packet order */
                        if (trace_is_parallel(trace)) {
                                /* Pass straight to reporter */
                                libtrace_generic_t gt = {.res = peeked};
                                ASSERT_RET (libtrace_deque_pop_front(v, (void *) peeked), == 1);
                                send_message(trace, &trace->reporter_thread,
                                                MESSAGE_RESULT, gt,
                                                &trace->reporter_thread);
                                return 0;
                        }
                        /* Tick matches packet order */
                        *key = peeked->key;
                        return 1;

                        /* Tick doesn't match packet order */
                } else {
                        /* Duplicate -- pop it */
                        ASSERT_RET (libtrace_deque_pop_front(v, (void *) peeked), == 1);
                        return 0;
                }
        }

        *key = peeked->key;
        return 1;
}

inline static uint64_t next_message(libtrace_t *trace, libtrace_combine_t *c,
                libtrace_queue_t *v) {

        libtrace_result_t r;
        uint64_t nextkey = 0;

        do {
                if (libtrace_deque_peek_front(v, (void *) &r) == 0) {
                        return 0;
                }
        } while (peek_queue(trace, c, v, &nextkey, &r) == 0);

        return nextkey;
}


inline static void read_internal(libtrace_t *trace, libtrace_combine_t *c, const bool final){
	int i;
	int live_count = 0;
        libtrace_queue_t *queues = c->queues;
	bool allactive = true;
        bool live[trace_get_perpkt_threads(trace)]; // Set if a trace is alive
	uint64_t key[trace_get_perpkt_threads(trace)]; // Cached keys
	uint64_t min_key = UINT64_MAX;
        uint64_t peeked = 0;
	int min_queue = -1;

	/* Loop through check all are alive (have data) and find the smallest */
        for (i = 0; i < trace_get_perpkt_threads(trace); ++i) {
		libtrace_queue_t *v = &queues[i];
                if (libtrace_deque_get_size(v) != 0 &&
                                peek_queue(trace, c, v, &peeked, NULL)) {
                        live_count ++;
                        live[i] = true;
                        key[i] = peeked;
                        if (i == 0 || min_key > peeked) {
                                min_key = peeked;
                                min_queue = i;
                        }
                } else {
                        allactive = false;
                        live[i] = false;
                        key[i] = 0;
                }
	}

	/* Now remove the smallest and loop - special case if all threads have
	 * joined we always flush what's left. Or the next smallest is the same
	 * value or less than the previous */
        while (allactive || (live_count && final)) {
		/* Get the minimum queue and then do stuff */
		libtrace_result_t r;
		libtrace_generic_t gt = {.res = &r};

		ASSERT_RET (libtrace_deque_pop_front(&queues[min_queue], (void *) &r), == 1);

                //printf("%lu %lu %lu %lu %d\n", key[0], key[1], key[2], key[3], min_queue);

                send_message(trace, &trace->reporter_thread,
                                MESSAGE_RESULT, gt,
                                NULL);

		// Now update the one we just removed
                peeked = next_message(trace, c, &queues[min_queue]);
                if (peeked != 0) {

                        key[min_queue] = peeked;
                        // We are still the smallest, might be out of order :(
                        if (key[min_queue] <= min_key) {
                                min_key = key[min_queue];
                        } else {
                                min_key = key[min_queue]; // Update our minimum
                                // Check all find the smallest again - all are alive
                                for (i = 0; i < trace_get_perpkt_threads(trace); ++i) {
                                        if (live[i] && min_key >= key[i]) {
                                                min_key = key[i];
                                                min_queue = i;
                                        }
                                }
                        }
		} else {
			allactive = false;
                        live[min_queue] = false;
                        key[min_queue] = 0;
			live_count--;
			min_key = UINT64_MAX; // Update our minimum
                        min_queue = -1;
			// Check all find the smallest again - all are alive
			for (i = 0; i < trace_get_perpkt_threads(trace); ++i) {
				if (live[i] && min_key >= key[i]) {
					min_key = key[i];
					min_queue = i;
				}
			}
		}
	}
}

static void read(libtrace_t *trace, libtrace_combine_t *c) {
	read_internal(trace, c, false);
}

static void read_final(libtrace_t *trace, libtrace_combine_t *c) {
        int empty = 0, i;
        libtrace_queue_t *q = c->queues;

        do {
                read_internal(trace, c, true);
                empty = 0;
		for (i = 0; i < trace_get_perpkt_threads(trace); ++i) {
                        if (libtrace_deque_get_size(&q[i]) == 0)
                                empty ++;
                }
        }
        while (empty < trace_get_perpkt_threads(trace));
}

static void destroy(libtrace_t *trace, libtrace_combine_t *c) {
	int i;
	libtrace_queue_t *queues = c->queues;

	for (i = 0; i < trace_get_perpkt_threads(trace); i++) {
		if (libtrace_deque_get_size(&queues[i]) != 0) {
			trace_set_err(trace, TRACE_ERR_COMBINER,
				"Failed to destroy queues, A thread still has data in destroy()");
			return;
		}
	}
	free(queues);
	queues = NULL;
}


static void pause(libtrace_t *trace, libtrace_combine_t *c) {
	libtrace_queue_t *queues = c->queues;
	int i;
	for (i = 0; i < trace_get_perpkt_threads(trace); i++) {
		libtrace_deque_apply_function(&queues[i], (deque_data_fn) libtrace_make_result_safe);
	}
}

DLLEXPORT const libtrace_combine_t combiner_ordered = {
	init_combiner,	/* initialise */
	destroy,		/* destroy */
	publish,		/* publish */
	read,			/* read */
	read_final,		/* read_final */
	pause,			/* pause */
	NULL,			/* queues */
        0,                      /* last_count_tick */
        0,                      /* last_ts_tick */
	{0}				/* opts */
};
