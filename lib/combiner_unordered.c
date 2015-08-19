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
	libtrace_deque_push_back(queue, res); // Automatically locking for us :)

	if (libtrace_deque_get_size(queue) >= trace->config.reporter_thold) {
		trace_post_reporter(trace);
	}
}

static void read(libtrace_t *trace, libtrace_combine_t *c){
	libtrace_queue_t *queues = c->queues;
	int i;

	/* Loop through and read all that are here */
	for (i = 0; i < libtrace_get_perpkt_count(trace); ++i) {
		libtrace_queue_t *v = &queues[i];
		while (libtrace_deque_get_size(v) != 0) {
			libtrace_result_t r;
			libtrace_generic_t gt = {.res = &r};
			ASSERT_RET (libtrace_deque_pop_front(v, (void *) &r), == 1);
			trace->reporter(trace, MESSAGE_RESULT, gt, &trace->reporter_thread);
		}
	}
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

DLLEXPORT const libtrace_combine_t combiner_unordered = {
    init_combiner,	/* initialise */
	destroy,		/* destroy */
	publish,		/* publish */
    read,			/* read */
    read,			/* read_final */
    read,			/* pause */
    NULL,			/* queues */
    {0}				/* opts */
};
