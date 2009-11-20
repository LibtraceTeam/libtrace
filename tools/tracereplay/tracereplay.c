


/* This is a simple example program that demonstrates how to use the libtrace
 * event framework. The event framework is ideal for reading from devices and 
 * interfaces in a non-blocking manner, and for reading from a trace in 
 * "tracetime" as opposed to as fast as possible.
 */



#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <libtrace.h>

static libtrace_packet_t * per_packet(libtrace_packet_t *packet) {
  
  uint32_t remaining;
  libtrace_linktype_t linktype;
  void * pkt_buffer = trace_get_packet_buffer(packet,&linktype,&remaining);
  libtrace_packet_t *new_packet = trace_create_packet();

  size_t wire_length = trace_get_wire_length(packet);

  trace_construct_packet(new_packet,linktype,pkt_buffer,wire_length);


  return new_packet;
  
}

static uint32_t event_read_packet(libtrace_t *trace, libtrace_packet_t *packet) 
{
	libtrace_eventobj_t obj;
	fd_set rfds;
	struct timeval sleep_tv;
	
	FD_ZERO(&rfds);
	
	for (;;) {
		obj = trace_event(trace, packet);

		switch(obj.type) {
			
			/* Device has no packets at present - lets wait until
			 * it does get something */
			case TRACE_EVENT_IOWAIT:
				FD_ZERO(&rfds);
				FD_SET(obj.fd, &rfds);
				select(obj.fd + 1, &rfds, NULL, NULL, 0);
				continue;
				
			/* Replaying a trace in tracetime and the next packet
			 * is not due yet */
			case TRACE_EVENT_SLEEP:
				/* select offers good precision for sleeping */
				sleep_tv.tv_sec = (int)obj.seconds;
				sleep_tv.tv_usec = (int) ((obj.seconds - sleep_tv.tv_sec) * 1000000.0);
				select(0, NULL, NULL, NULL, &sleep_tv);
				continue;
				
			/* We've got a packet! */
			case TRACE_EVENT_PACKET:
				/* Check for error first */
				if (obj.size == -1)
					return -1;
				return 1;
				
			/* End of trace has been reached */
			case TRACE_EVENT_TERMINATE:
				return -1;
				
			/* An event we don't know about has occured */
			default:
				fprintf(stderr, "Unknown event type occured\n");
				return -1;
		}
	}
}
		
int main(int argc, char *argv[]) {
	
	libtrace_t *trace;
	libtrace_out_t *output;
	libtrace_packet_t *packet;
	int psize = 0;
	char *uri = 0;
	
	if (argc == 3) {
		uri = strdup(argv[1]);
	} else {
		fprintf(stderr,"usage: %s <input uri> <outputuri>\n",argv[0]);
		return -1;
	}

	/* Create the trace */
	trace = trace_create(uri);
	if (trace_is_err(trace)) {
		trace_perror(trace, "trace_create");
		return 1;
	}
	
	/* Starting the trace */
	if (trace_start(trace) != 0) {
		trace_perror(trace, "trace_start");
		return 1;
	}

	/* Creating output trace */
	output = trace_create_output(argv[2]);
	
	if (trace_is_err_output(output)) {
		trace_perror_output(output, "Opening output trace");
		return 1;
	}
	if (trace_start_output(output)) {
		trace_perror_output(output, "Starting output trace");
		trace_destroy_output(output);
		trace_destroy(trace);
		return 1;
	}
		

	packet = trace_create_packet();

	for (;;) {
		if ((psize = event_read_packet(trace, packet)) <= 0) {
			break;
		}

		/* Got a packet - let's do something with it */
		libtrace_packet_t * new = per_packet(packet);

		if (trace_write_packet(output, new) < 0) {
			trace_perror_output(output, "Writing packet");
			trace_destroy(trace);
			trace_destroy_output(output);
			trace_destroy_packet(packet);
			return 1;
		}
		trace_destroy_packet(new);
	}
	free(uri);
	trace_destroy(trace);
	trace_destroy_output(output);
	trace_destroy_packet(packet);
	return 0;

}
