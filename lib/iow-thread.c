#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>

/* 1MB Buffer */
#define BUFFERSIZE (1024*1024)
#define BUFFERS 100

extern iow_source_t thread_wsource;

struct buffer_t {
	char buffer[BUFFERSIZE];
	int len;
	enum { EMPTY = 0, FULL = 1 } state;
	pthread_cond_t dataready;
	pthread_cond_t spaceavail;
	pthread_mutex_t mutex;
};

struct state_t {
	struct buffer_t buffer[BUFFERS];
	int out_buffer;
	off_t offset;
	pthread_t consumer;
	bool closing;
	iow_t *iow;
};

#define DATA(x) ((struct state_t *)((x)->data))
#define OUTBUFFER(x) (DATA(x)->buffer[DATA(x)->out_buffer])
#define min(a,b) ((a)<(b) ? (a) : (b))

static void *thread_consumer(void *userdata)
{
	int buffer=0;
	bool running = true;
	iow_t *state = (iow_t *) userdata;

	do {
		pthread_mutex_lock(&DATA(state)->buffer[buffer].mutex);
		while (DATA(state)->buffer[buffer].state == EMPTY) {
			if (DATA(state)->closing)
				break;
			pthread_cond_wait(&DATA(state)->buffer[buffer].dataready,
					&DATA(state)->buffer[buffer].mutex);
		}
		/* Empty the buffer */
		wandio_wwrite(
				DATA(state)->iow,
				DATA(state)->buffer[buffer].buffer,
				DATA(state)->buffer[buffer].len);


		/* if we've not reached the end of the file keep going */
		running = ( DATA(state)->buffer[buffer].len > 0 );
		DATA(state)->buffer[buffer].len = 0;
		DATA(state)->buffer[buffer].state = EMPTY;

		pthread_cond_signal(&DATA(state)->buffer[buffer].spaceavail);

		pthread_mutex_unlock(&DATA(state)->buffer[buffer].mutex);

		/* Flip buffers */
		buffer=(buffer+1) % BUFFERS;

	} while(running);

	fprintf(stderr,"Write thread leaving\n");

	wandio_wdestroy(DATA(state)->iow);

	return NULL;
}

iow_t *thread_wopen(iow_t *child)
{
	iow_t *state;

	if (!child) {
		return NULL;
	}
	

	state = malloc(sizeof(iow_t));
	state->data = calloc(1,sizeof(struct state_t));
	state->source = &thread_wsource;

	DATA(state)->out_buffer = 0;
	DATA(state)->offset = 0;
	pthread_mutex_init(&DATA(state)->buffer[0].mutex,NULL);
	pthread_cond_init(&DATA(state)->buffer[0].dataready,NULL);
	pthread_cond_init(&DATA(state)->buffer[0].spaceavail,NULL);

	DATA(state)->iow = child;
	DATA(state)->closing = false;

	pthread_create(&DATA(state)->consumer,NULL,thread_consumer,state);

	return state;
}

static off_t thread_wwrite(iow_t *state, const char *buffer, off_t len)
{
	int slice;
	int copied=0;
	int newbuffer;

	while(len>0) {
		pthread_mutex_lock(&OUTBUFFER(state).mutex);
		while (OUTBUFFER(state).state == FULL) {
			pthread_cond_wait(&OUTBUFFER(state).spaceavail,
					&OUTBUFFER(state).mutex);
		}

		slice=min( 
			(off_t)sizeof(OUTBUFFER(state).buffer)-DATA(state)->offset,
			len);
				
		memcpy(
			OUTBUFFER(state).buffer+DATA(state)->offset,
			buffer,
			slice
			);

		DATA(state)->offset += slice;
		OUTBUFFER(state).len += slice;

		buffer += slice;
		len -= slice;
		copied += slice;
		newbuffer = DATA(state)->out_buffer;

		if (DATA(state)->offset >= (off_t)sizeof(OUTBUFFER(state).buffer)) {
			OUTBUFFER(state).state = FULL;
			pthread_cond_signal(&OUTBUFFER(state).dataready);
			DATA(state)->offset = 0;
			newbuffer = (newbuffer+1) % BUFFERS;
		}

		pthread_mutex_unlock(&OUTBUFFER(state).mutex);

		DATA(state)->out_buffer = newbuffer;
	}
	return copied;
}

static void thread_wclose(iow_t *iow)
{
	pthread_mutex_lock(&OUTBUFFER(iow).mutex);
	DATA(iow)->closing = true;
	pthread_cond_signal(&OUTBUFFER(iow).dataready);
	pthread_mutex_unlock(&OUTBUFFER(iow).mutex);
	pthread_join(DATA(iow)->consumer,NULL);
	free(iow->data);
	free(iow);
}

iow_source_t thread_wsource = {
	"threadw",
	thread_wwrite,
	thread_wclose
};
