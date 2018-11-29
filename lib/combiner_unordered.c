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
	libtrace_deque_push_back(queue, res); // Automatically locking for us :)

	if (libtrace_deque_get_size(queue) >= trace->config.reporter_thold) {
		trace_post_reporter(trace);
	}
}

static void read(libtrace_t *trace, libtrace_combine_t *c){
	libtrace_queue_t *queues = c->queues;
	int i;

	/* Loop through and read all that are here */
	for (i = 0; i < trace_get_perpkt_threads(trace); ++i) {
		libtrace_queue_t *v = &queues[i];
		while (libtrace_deque_get_size(v) != 0) {
			libtrace_result_t r;
                        libtrace_generic_t gt = {.res = &r};
			ASSERT_RET (libtrace_deque_pop_front(v, (void *) &r), == 1);
                        /* Ignore any ticks that we've already seen */
                        if (r.type == RESULT_TICK_INTERVAL) {
                                if (r.key <= c->last_ts_tick)
                                        continue;
                                c->last_ts_tick = r.key;
                        }

                        if (r.type == RESULT_TICK_COUNT) {
                                if (r.key <= c->last_count_tick)
                                        continue;
                                c->last_count_tick = r.key;
                        }
			send_message(trace, &trace->reporter_thread,
                                MESSAGE_RESULT, gt, NULL);
		}
	}
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

DLLEXPORT const libtrace_combine_t combiner_unordered = {
    init_combiner,	/* initialise */
	destroy,		/* destroy */
	publish,		/* publish */
    read,			/* read */
    read,			/* read_final */
    read,			/* pause */
    NULL,			/* queues */
    0,                          /* last_count_tick */
    0,                          /* last_ts_tick */
    {0}				/* opts */
};
