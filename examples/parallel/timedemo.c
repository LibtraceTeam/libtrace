/* A parallel libtrace program that prints a count of packets observered
 * after a 10 seconds of the trace running.
 *
 * Using this approach allows results to be reported quickly for trracetime
 * formats, even if data is not arriving on a given thread. While maintaining
 * a consistant output when run on a file etc.
 *
 * Designed to demonstrate the correct usage of TICK_INTERVAL. Also note
 * TICK_COUNT is not needed for this example.
 *
 * This example is based upon examples/tutorial/timedemo.c
 */
#include "libtrace_parallel.h"
#include "combiners.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>

#define SECONDS_TO_ERF(sec) (((uint64_t)sec)<<32)
#define ERF_TO_SECONDS(erf) (((uint64_t)erf)>>32)
#define USEC_TO_ERF(usec) ((uint64_t)usec * 0xFFFFFFFFull)
#define TV_TO_ERF(tv) ((((uint64_t)(tv).tv_sec) << 32) + ((((uint64_t)(tv).tv_usec)<< 32)/1000000))

/* Due to the amount of error checking required in our main function, it
 * is a lot simpler and tidier to place all the calls to various libtrace
 * destroy functions into a separate function.
 */
static void libtrace_cleanup(libtrace_t *trace) {

	/* It's very important to ensure that we aren't trying to destroy
	 * a NULL structure, so each of the destroy calls will only occur
	 * if the structure exists */
	if (trace)
		trace_destroy(trace);

}

/* Every time a packet becomes ready this function will be called. It will also
 * be called when messages from the library is received. This function
 * is run in parallel.
 */
static void* per_packet(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
                        int mesg, libtrace_generic_t data,
                        libtrace_thread_t *sender UNUSED)
{
	/* __thread, says make this unique per each thread */
	static __thread uint64_t count = 0; /* The number of packets in this 10sec interval */
	static __thread uint64_t next_report = 0; /* The start of the next interval */
	static __thread uint64_t offset = 0; /* Offset between trace time and system time */
	uint64_t ts; /* The timestamp of the current packet */

	switch (mesg) {
	case MESSAGE_PACKET:
		/* Get the timestamp for the current packet */
		ts = trace_get_erf_timestamp(data.pkt);

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
		while (next_report && ts > next_report) {
			libtrace_generic_t c;
			c.uint64 = count;
			/* Report the result for the current time interval
			 * Each thread will report once for each given time
			 * interval */
			trace_publish_result(trace, t, next_report, c, RESULT_USER);

			/* Reset the counter */
			count = 0;
			/* Determine when the next report is due */
			next_report += SECONDS_TO_ERF(10);
		}

		/* No matter what else happens during this function call, we still
		 * need to increment our counter */
		count += 1;

		/* We have finished processing this packet return it */
		return data.pkt;
	case MESSAGE_TICK_INTERVAL:

		 /* If we are a second passed when we should have reported last
		  * we will do it now. We would be in this situation if we
		  * haven't been receiving packets.
		  * Make sure we dont report until we have seen the first packet
		  */
		while (next_report &&
		       (data.uint64 - offset - SECONDS_TO_ERF(1) > next_report)) {
			libtrace_generic_t c;
			c.uint64 = count;
			/* Report the result for the current time interval */
			trace_publish_result(trace, t, next_report, c, RESULT_USER);

			/* Reset the counter */
			count = 0;
			/* Determine when the next report is due */
			next_report += SECONDS_TO_ERF(10);
		}

	/* !!! Fall through to check if we have the first packet yet !!! */
	case MESSAGE_FIRST_PACKET: /* Some thread has seen its first packet */

		if (next_report == 0) {
			uint64_t first_ts;
			/* Try get the timestamp of the first packet across all threads*/
			const libtrace_packet_t * tmp = NULL;
			const struct timeval *tv;

			/* Get the first packet across all threads */
			if (trace_get_first_packet(trace, NULL, &tmp, &tv) == 1) {
				/* We know this is the first packet across all threads */

				first_ts = trace_get_erf_timestamp(tmp);
				/* There might be a difference between system time
				 * and packet times. We need to account for this
				 * when interpreting TICK_INTERVAL messages */
				offset = TV_TO_ERF(*tv) - first_ts;
				/* We know our first reporting time now */
				next_report = first_ts + SECONDS_TO_ERF(10);
			}
		}
		return NULL;
	default:
		return NULL;
	}
	return NULL;
}

/* Every time a result (published using trace_publish_result()) becomes ready
 * this function will be called. It will also be called when messages from the
 * library is received. This function is only run on a single thread
 */
static void report_results(libtrace_t *trace UNUSED, int mesg,
                           libtrace_generic_t data,
                           libtrace_thread_t *sender UNUSED) {
	static uint64_t count = 0; /* The count for the current interval */
	static int reported = 0; /* The number of threads that have reported results for the interval */
	static uint64_t currentkey = 0; /* The key, which is next_report from perpkt */

	switch (mesg) {
	case MESSAGE_RESULT:
		if (data.res->type == RESULT_USER) {
			/* We should always get a result from each thread */
			if (currentkey)
				assert(data.res->key == currentkey);

			currentkey = data.res->key;
			reported++;
			/* Add on the packets */
			count += data.res->value.uint64;

			if (reported == libtrace_get_perpkt_count(trace)) {
				/* Print a timestamp for the report and the packet count */
				printf("%u \t%" PRIu64 "\n", (int) ERF_TO_SECONDS(data.res->key), count);
				/* Reset ready for the next batch of results */
				count = reported = 0;
				currentkey = data.res->key + SECONDS_TO_ERF(10);
			}
		}
		break;
	case MESSAGE_STARTING:
		/* Print heading when first started */
		printf("Time\t\tPackets\n");
		break;
	}
}

int main(int argc, char *argv[])
{
	libtrace_t *trace = NULL;

	/* Ensure we have at least one argument after the program name */
	if (argc < 2) {
		fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
		return 1;
	}

	trace = trace_create(argv[1]);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace file");
		libtrace_cleanup(trace);
		return 1;
	}

	/* We want to push through results ASAP */
	trace_set_reporter_thold(trace, 1);

	/* If the trace is live send a tick message every second */
	trace_set_tick_interval(trace, 1000);

	/* The combiner sits between trace_publish_result() and the reporter
	 * function and determines how the results show be ordered and combined.
	 *
	 * Our results are ordered by timestamp and we want them to be returned
	 * in order so we use combiner_ordered.
	 *
	 * This typically the most usefull combiner to use.
	 */
	trace_set_combiner(trace, &combiner_ordered, (libtrace_generic_t){0});

	if (trace_pstart(trace, NULL, per_packet, report_results) == -1) {
		trace_perror(trace,"Starting trace");
		libtrace_cleanup(trace);
		return 1;
	}

	/* Wait for completion */
	trace_join(trace);
	if (trace_is_err(trace)) {
		trace_perror(trace,"Reading packets");
		libtrace_cleanup(trace);
		return 1;
	}

	libtrace_cleanup(trace);
	return 0;
}
