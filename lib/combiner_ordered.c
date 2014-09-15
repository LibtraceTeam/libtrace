#include "libtrace.h"
#include "libtrace_int.h"
#include "data-struct/deque.h"
#include <assert.h>
#include <stdlib.h>

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
	if (libtrace_deque_get_size(queue) >= trace->config.reporter_thold) {
		trace_post_reporter(trace);
	}
	//while (libtrace_deque_get_size(&t->deque) >= 1000)
	//	sched_yield();
	libtrace_deque_push_back(queue, res); // Automatically locking for us :)
}

static void inline read_internal(libtrace_t *trace, libtrace_queue_t *queues, bool final){
	int i;
	int flags = trace->reporter_flags; // Hint these aren't changing
	int live_count = 0;
	bool live[libtrace_get_perpkt_count(trace)]; // Set if a trace is alive
	uint64_t key[libtrace_get_perpkt_count(trace)]; // Cached keys
	uint64_t min_key = UINT64_MAX;
	int min_queue = -1;

	/* Loop through check all are alive (have data) and find the smallest */
	for (i = 0; i < libtrace_get_perpkt_count(trace); ++i) {
		libtrace_queue_t *v = &queues[i];
		if (libtrace_deque_get_size(v) != 0) {
			libtrace_result_t r;
			libtrace_deque_peek_front(v, (void *) &r);
			live_count++;
			live[i] = true;
			key[i] = libtrace_result_get_key(&r);
			if (i==0 || min_key > key[i]) {
				min_key = key[i];
				min_queue = i;
			}
		} else {
			live[i] = false;
		}
	}

	/* Now remove the smallest and loop - special case if all threads have joined we always flush what's left */
	while ((live_count == libtrace_get_perpkt_count(trace)) || (live_count &&
			((flags & REDUCE_SEQUENTIAL && min_key == trace->expected_key) ||
			final))) {
		/* Get the minimum queue and then do stuff */
		libtrace_result_t r;

		ASSERT_RET (libtrace_deque_pop_front(&queues[min_queue], (void *) &r), == 1);
		trace->reporter(trace, &r, NULL);

		// We expect the key we read +1 now , todo put expected in our storage area
		trace->expected_key = key[min_queue] + 1;

		// Now update the one we just removed
		if (libtrace_deque_get_size(&queues[min_queue]) )
		{
			libtrace_deque_peek_front(&queues[min_queue], (void *) &r);
			key[min_queue] = libtrace_result_get_key(&r);
			if (key[min_queue] <= min_key) {
				// We are still the smallest, might be out of order though :(
				min_key = key[min_queue];
			} else {
				min_key = key[min_queue]; // Update our minimum
				// Check all find the smallest again - all are alive
				for (i = 0; i < libtrace_get_perpkt_count(trace); ++i) {
					if (live[i] && min_key > key[i]) {
						min_key = key[i];
						min_queue = i;
					}
				}
			}
		} else {
			live[min_queue] = false;
			live_count--;
			min_key = UINT64_MAX; // Update our minimum
			// Check all find the smallest again - all are alive
			for (i = 0; i < libtrace_get_perpkt_count(trace); ++i) {
				// Still not 100% TODO (what if order is wrong or not increasing)
				if (live[i] && min_key >= key[i]) {
					min_key = key[i];
					min_queue = i;
				}
			}
		}
	}
}

static void read(libtrace_t *trace, libtrace_combine_t *c) {
	read_internal(trace, c->queues, false);
}

static void read_final(libtrace_t *trace, libtrace_combine_t *c) {
	read_internal(trace, c->queues, true);
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

/** Used below in trace_make_results_packets_safe*/
static void do_copy_result_packet(void *data)
{
	libtrace_result_t *res = (libtrace_result_t *)data;
	if (res->type == RESULT_PACKET) {
		// Duplicate the packet in standard malloc'd memory and free the
		// original, This is a 1:1 exchange so is ocache count remains unchanged.
		libtrace_packet_t *oldpkt, *dup;
		oldpkt = (libtrace_packet_t *) res->value;
		dup = trace_copy_packet(oldpkt);
		res->value = (void *)dup;
		trace_destroy_packet(oldpkt);
	}
}

static void pause(libtrace_t *trace, libtrace_combine_t *c) {
	libtrace_queue_t *queues = c->queues;
	int i;
	for (i = 0; i < libtrace_get_perpkt_count(trace); i++) {
		libtrace_deque_apply_function(&queues[i], &do_copy_result_packet);
	}
}

const libtrace_combine_t combiner_ordered = {
    init_combiner,	/* initialise */
	destroy,		/* destroy */
	publish,		/* publish */
    read,			/* read */
    read_final,		/* read_final */
    pause,			/* pause */
    NULL,			/* queues */
    0				/* opts */
};
