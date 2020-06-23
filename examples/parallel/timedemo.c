/* A parallel libtrace program that prints a count of packets observed
 * every 10 seconds.
 *
 * Using this approach allows results to be reported promptly for live
 * formats, even if data is not arriving on a given thread. This method also
 * works perfectly fine when run against a trace file.
 *
 * Designed to demonstrate the correct usage of TICK_INTERVAL. TICK_COUNT can
 * be used instead, which will trigger the result reporting based on seeing
 * a fixed number of packets.
 *
 * This example is based upon examples/tutorial/timedemo.c
 */
#include "libtrace_parallel.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <stdlib.h>

#define SECONDS_TO_ERF(sec) (((uint64_t)sec)<<32)
#define ERF_TO_SECONDS(erf) (((uint64_t)erf)>>32)
#define USEC_TO_ERF(usec) ((uint64_t)usec * 0xFFFFFFFFull)
#define TV_TO_ERF(tv) ((((uint64_t)(tv).tv_sec) << 32) + ((((uint64_t)(tv).tv_usec)<< 32)/1000000))

struct localdata {
        uint64_t nextreport;
        uint64_t count;
};

/* Due to the amount of error checking required in our main function, it
 * is a lot simpler and tidier to place all the calls to various libtrace
 * destroy functions into a separate function.
 */
static void libtrace_cleanup(libtrace_t *trace,
                libtrace_callback_set_t *processing,
                libtrace_callback_set_t *reporter) {

	/* It's very important to ensure that we aren't trying to destroy
	 * a NULL structure, so each of the destroy calls will only occur
	 * if the structure exists */
	if (trace)
		trace_destroy(trace);

        if (processing)
                trace_destroy_callback_set(processing);

        if (reporter)
                trace_destroy_callback_set(reporter);

}

/* Creates a localdata structure for a processing thread */
static void *init_local(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
                void *global UNUSED) {

        struct localdata *local = (struct localdata *)malloc(sizeof(struct
                        localdata));
        local->nextreport = 0;
        local->count = 0;

        return local;

}

/* Frees the localdata associated with a processing thread */
static void fin_local(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
                void *global UNUSED, void *tls) {

        free(tls);
}

static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *t,
                void *global UNUSED, void *tls, libtrace_packet_t *packet) {

        uint64_t ts;
        /* Cast our thread local storage to the right type */
        struct localdata *local = (struct localdata *)tls;

        /* Get the timestamp for the current packet */
        ts = trace_get_erf_timestamp(packet);

        /* Check whether we need to report a packet count or not.
         *
         * If the timestamp for the current packet is beyond the time when the
         * next report was due then we have to output our current count and
         * reset it to zero.
         *
         * Note that I use a while loop here to ensure that we correctly deal
         * with periods in which no packets are observed. This can still
         * happen because TICK_INTERVAL is not used for realtime playback
         * such as a file.
         */
        while (local->nextreport && ts > local->nextreport) {
                libtrace_generic_t c;
                c.uint64 = local->count;
                /* Report the result for the current time interval.
                 * Each thread will report once for each given time
                 * interval */
                trace_publish_result(trace, t, local->nextreport, c,
                                RESULT_USER);

                /* Reset the counter */
                local->count = 0;
                /* Determine when the next report is due */
                local->nextreport += SECONDS_TO_ERF(10);
        }

        /* No matter what else happens during this function call, we still
         * need to increment our counter */
        local->count += 1;

        /* We have finished processing this packet so return it */
        return packet;

}

/* As soon as any thread has seen a packet, we need to initialise the
 * next reporting time for each of our processing threads */
static void first_packet(libtrace_t *trace, libtrace_thread_t *t UNUSED,
                void *global UNUSED, void *tls,
                libtrace_thread_t *sender UNUSED) {

        /* Cast our thread local storage to the right type */
        struct localdata *local = (struct localdata *)tls;

        if (local->nextreport == 0) {
                uint64_t first_ts;
                /* Get the timestamp of the first packet across all threads */
                const libtrace_packet_t * tmp = NULL;
                const struct timeval *tv;

                /* Get the first packet across all threads */
                if (trace_get_first_packet(trace, NULL, &tmp, &tv) == 1) {
                        first_ts = trace_get_erf_timestamp(tmp);
                        /* We know our first reporting time now */
                        local->nextreport = first_ts + SECONDS_TO_ERF(10);
                }
        }
}

static void process_tick(libtrace_t *trace, libtrace_thread_t *t,
                void *global UNUSED, void *tls, uint64_t tick) {

        struct localdata *local = (struct localdata *)tls;

        /* If a thread has received a tick event before a packet is seen
         * nextreport needs to be set */
        if (local->nextreport == 0) {
            local->nextreport = tick + SECONDS_TO_ERF(10);
        }

        while (local->nextreport && tick > local->nextreport) {
                libtrace_generic_t c;
                c.uint64 = local->count;
                /* If the tick is past the time that our next report is
                 * due, flush our current counter to the reporting
                 * thread. This ensures that we keep sending results even
                 * if this thread receives no new packets
                 */
                trace_publish_result(trace, t, local->nextreport, c,
                        RESULT_USER);

                /* Reset the counter */
                local->count = 0;
                /* Determine when the next report is due */
                local->nextreport += SECONDS_TO_ERF(10);
        }

}

static inline void dump_results(struct localdata *local, uint64_t key) {

        /* Using a while loop here, so that we can correctly handle any
         * 10 second intervals where no packets were counted.
         */
        while (key >= local->nextreport) {
                printf("%u \t%" PRIu64 "\n",
                                (int) ERF_TO_SECONDS(local->nextreport),
                                local->count);
                local->count = 0;
                local->nextreport += SECONDS_TO_ERF(10);
        }
}

/* Process results sent to the reporter thread */
static void report_results(libtrace_t *trace,
                libtrace_thread_t *sender UNUSED,
                void *global UNUSED, void *tls, libtrace_result_t *result) {

        static __thread int reported = 0;
        struct localdata *local = (struct localdata *)tls;


        /* Set the initial reporting time and print the heading
         * Note: we could do these in starting and first_packet callbacks
         * but there is only one reporting thread so we can get away
         * with this. */
        if (local->nextreport == 0) {
                printf("Time\t\tPackets\n");
                local->nextreport = result->key;
        }
        assert(result->key == local->nextreport);

        reported ++;
        if (reported == trace_get_perpkt_threads(trace)) {
                dump_results(local, result->key);
                reported = 0;
        }

        local->count += result->value.uint64;

}

/* Dump the final value for the counter and free up our local data struct */
static void end_reporter(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
                void *global UNUSED, void *tls) {

        struct localdata *local = (struct localdata *)tls;

        /* If we have any counted packets that haven't been reported, do
         * so now.
         */
        if (local->count > 0)
                dump_results(local, local->nextreport + 1);

        free(local);
}

int main(int argc, char *argv[])
{
	libtrace_t *trace = NULL;
        libtrace_callback_set_t *processing = NULL;
        libtrace_callback_set_t *reporter = NULL;

	/* Ensure we have at least one argument after the program name */
	if (argc < 2) {
		fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
		return 1;
	}

	trace = trace_create(argv[1]);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace file");
		libtrace_cleanup(trace, processing, reporter);
		return 1;
	}

	/* Send every result to the reporter immediately, i.e. do not buffer
         * them. */
	trace_set_reporter_thold(trace, 1);

	/* Sends a tick message once per second */
	trace_set_tick_interval(trace, 1000);

	/* The combiner sits between trace_publish_result() and the reporter
	 * function and determines how the results show be ordered and combined.
	 *
	 * Our results are ordered by timestamp and we want them to be returned
	 * in order so we use combiner_ordered.
	 *
	 * This is typically the most useful combiner to use.
	 */
	trace_set_combiner(trace, &combiner_ordered, (libtrace_generic_t){0});

        /* Limit to 4 processing threads */
        trace_set_perpkt_threads(trace, 4);

        /* Set up our processing callbacks */
        processing = trace_create_callback_set();
        trace_set_starting_cb(processing, init_local);
        trace_set_first_packet_cb(processing, first_packet);
        trace_set_stopping_cb(processing, fin_local);
        trace_set_packet_cb(processing, per_packet);
        trace_set_tick_interval_cb(processing, process_tick);

        /* Set up our reporting callbacks -- note that we re-use the init_local
         * callback */
        reporter = trace_create_callback_set();
        trace_set_starting_cb(reporter, init_local);
        trace_set_result_cb(reporter, report_results);
        trace_set_stopping_cb(reporter, end_reporter);

        /* Start everything going -- no global data required so set that
         * to NULL */
	if (trace_pstart(trace, NULL, processing, reporter) == -1) {
		trace_perror(trace,"Starting trace");
		libtrace_cleanup(trace, processing, reporter);
		return 1;
	}

	/* Wait for completion */
	trace_join(trace);
	if (trace_is_err(trace)) {
		trace_perror(trace,"Reading packets");
		libtrace_cleanup(trace, processing, reporter);
		return 1;
	}

	libtrace_cleanup(trace, processing, reporter);
	return 0;
}
