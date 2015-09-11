#include "libtrace.h"
#include "libtrace_int.h"
#include "data-struct/deque.h"
#include <assert.h>
#include <stdlib.h>

/* TODO hook up configuration option for sequentual packets again */

static int init_combiner(libtrace_t *t, libtrace_combine_t *c) {
	int i = 0;
	assert(libtrace_get_perpkt_count(t) > 0);
	libtrace_queue_t *queues;
	c->queues = calloc(sizeof(libtrace_queue_t), libtrace_get_perpkt_count(t));
	queues = c->queues;
	for (i = 0; i < libtrace_get_perpkt_count(t); ++i) {
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

inline static uint64_t next_message(libtrace_queue_t *v) {

        libtrace_result_t r;
        if (libtrace_deque_peek_front(v, (void *) &r) == 0)
                return 0;

        if (r.type == RESULT_TICK_INTERVAL || r.type == RESULT_TICK_COUNT)
                return 0;

        return r.key;
}

inline static int peek_queue(libtrace_t *trace, libtrace_combine_t *c,
                libtrace_queue_t *v, uint64_t *key) {

        libtrace_result_t r;
        libtrace_deque_peek_front(v, (void *) &r);

        /* Ticks are a bit tricky, because we can get TS
         * ticks in amongst packets indexed by their cardinal
         * order and vice versa. Also, every thread will
         * produce an equivalent tick and we should really
         * combine those into a single tick for the reporter
         * thread.
         */

        if (r.type == RESULT_TICK_INTERVAL) {
                if (r.key > c->last_ts_tick) {
                        c->last_ts_tick = r.key;

                        /* Tick doesn't match packet order */
                        if (!trace_is_parallel(trace)) {
                                /* Pass straight to reporter */
                                libtrace_generic_t gt = {.res = &r};
                                ASSERT_RET (libtrace_deque_pop_front(v, (void *) &r), == 1);
                                send_message(trace, &trace->reporter_thread,
                                                MESSAGE_RESULT, gt,
                                                &trace->reporter_thread);
                                return 0;
                        }
                        /* Tick matches packet order */
                        *key = r.key;
                        return 1;

                } else {
                        /* Duplicate -- pop it */
                        ASSERT_RET (libtrace_deque_pop_front(v, (void *) &r), == 1);
                        return 0;
                }
        }

        if (r.type == RESULT_TICK_COUNT) {
                if (r.key > c->last_count_tick) {
                        c->last_count_tick = r.key;

                        /* Tick doesn't match packet order */
                        if (trace_is_parallel(trace)) {
                                /* Pass straight to reporter */
                                libtrace_generic_t gt = {.res = &r};
                                ASSERT_RET (libtrace_deque_pop_front(v, (void *) &r), == 1);
                                send_message(trace, &trace->reporter_thread,
                                                MESSAGE_RESULT, gt,
                                                &trace->reporter_thread);
                                return 0;
                        }
                        /* Tick matches packet order */
                        *key = r.key;
                        return 1;

                        /* Tick doesn't match packet order */
                } else {
                        /* Duplicate -- pop it */
                        ASSERT_RET (libtrace_deque_pop_front(v, (void *) &r), == 1);
                        return 0;
                }
        }
        
        *key = r.key;
        return 1;
}

inline static void read_internal(libtrace_t *trace, libtrace_combine_t *c, const bool final){
	int i;
	int live_count = 0;
        libtrace_queue_t *queues = c->queues;
	bool allactive = true;
        bool live[libtrace_get_perpkt_count(trace)]; // Set if a trace is alive
	uint64_t key[libtrace_get_perpkt_count(trace)]; // Cached keys
	uint64_t min_key = UINT64_MAX;
	uint64_t prev_min = 0;
        uint64_t peeked = 0;
	int min_queue = -1;

	/* Loop through check all are alive (have data) and find the smallest */
        for (i = 0; i < libtrace_get_perpkt_count(trace); ++i) {
		libtrace_queue_t *v = &queues[i];
		if (libtrace_deque_get_size(v) != 0) {
                        if (peek_queue(trace, c, v, &peeked)) {
                                live_count ++;
                                live[i] = true;
                                key[i] = peeked;
                                if (i == 0 || min_key > peeked) {
                                        min_key = peeked;
                                        min_queue = i;
                                }
                        } else {
                                live[i] = false;
                                key[i] = 0;
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
	while ((allactive && min_queue != -1) || (live_count && final)
	       || (live_count && prev_min >= min_key)) {
		/* Get the minimum queue and then do stuff */
		libtrace_result_t r;
		libtrace_generic_t gt = {.res = &r};

		ASSERT_RET (libtrace_deque_pop_front(&queues[min_queue], (void *) &r), == 1);
                send_message(trace, &trace->reporter_thread,
                                MESSAGE_RESULT, gt,
                                NULL);

		// Now update the one we just removed
                peeked = next_message(&queues[min_queue]);
		if (libtrace_deque_get_size(&queues[min_queue]) &&
                                peeked != 0) {

                        key[min_queue] = peeked;
                        // We are still the smallest, might be out of order :(
                        if (key[min_queue] <= min_key) {
                                min_key = key[min_queue];
                        } else {
                                min_key = key[min_queue]; // Update our minimum
                                // Check all find the smallest again - all are alive
                                for (i = 0; i < libtrace_get_perpkt_count(trace); ++i) {
                                        if (live[i] && min_key >= key[i]) {
                                                min_key = key[i];
                                                min_queue = i;
                                        }
                                }
                        }
		} else {
			allactive = false;
                        live[min_queue] = false;
			live_count--;
			prev_min = min_key;
			min_key = UINT64_MAX; // Update our minimum
			// Check all find the smallest again - all are alive
			for (i = 0; i < libtrace_get_perpkt_count(trace); ++i) {
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
		for (i = 0; i < libtrace_get_perpkt_count(trace); ++i) {
                        if (libtrace_deque_get_size(&q[i]) == 0)
                                empty ++;
                }
        }
        while (empty < libtrace_get_perpkt_count(trace));
}

static void destroy(libtrace_t *trace, libtrace_combine_t *c) {
	int i;
	libtrace_queue_t *queues = c->queues;

	for (i = 0; i < libtrace_get_perpkt_count(trace); i++) {
		assert(libtrace_deque_get_size(&queues[i]) == 0);
	}
	free(queues);
	queues = NULL;
}


static void pause(libtrace_t *trace, libtrace_combine_t *c) {
	libtrace_queue_t *queues = c->queues;
	int i;
	for (i = 0; i < libtrace_get_perpkt_count(trace); i++) {
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
