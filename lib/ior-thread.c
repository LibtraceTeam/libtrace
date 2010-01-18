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

extern io_source_t thread_source;

struct buffer_t {
	char buffer[BUFFERSIZE];
	int len;
	enum { EMPTY = 0, FULL = 1 } state;
};

struct state_t {
	struct buffer_t buffer[BUFFERS];
	int in_buffer;
	int offset;
	pthread_t producer;
	pthread_cond_t space_avail;
	pthread_cond_t data_ready;
	pthread_mutex_t mutex;
	io_t *io;
	bool closing;
};

#define DATA(x) ((struct state_t *)((x)->data))
#define INBUFFER(x) (DATA(x)->buffer[DATA(x)->in_buffer])
#define min(a,b) ((a)<(b) ? (a) : (b))

static void *thread_producer(void* userdata)
{
	io_t *state = (io_t*) userdata;
	int buffer=0;
	bool running = true;

	pthread_mutex_lock(&DATA(state)->mutex);
	do {
		while (DATA(state)->buffer[buffer].state == FULL) {
			if (DATA(state)->closing)
				break;
			pthread_cond_wait(&DATA(state)->space_avail, &DATA(state)->mutex);
		}

		if (DATA(state)->closing) {
			break;
		}
		pthread_mutex_unlock(&DATA(state)->mutex);

		/* Fill the buffer */
		DATA(state)->buffer[buffer].len=wandio_read(
				DATA(state)->io,
				DATA(state)->buffer[buffer].buffer,
				sizeof(DATA(state)->buffer[buffer].buffer));

		pthread_mutex_lock(&DATA(state)->mutex);

		DATA(state)->buffer[buffer].state = FULL;

		/* if we've not reached the end of the file keep going */
		running = (DATA(state)->buffer[buffer].len > 0 );

		pthread_cond_signal(&DATA(state)->data_ready);

		/* Flip buffers */
		buffer=(buffer+1) % BUFFERS;

	} while(running);


	wandio_destroy(DATA(state)->io);

	pthread_cond_signal(&DATA(state)->data_ready);
	pthread_mutex_unlock(&DATA(state)->mutex);

	return NULL;
}

io_t *thread_open(io_t *parent)
{
	io_t *state;

	if (!parent) {
		return NULL;
	}
	

	state = malloc(sizeof(io_t));
	state->data = calloc(1,sizeof(struct state_t));
	state->source = &thread_source;

	DATA(state)->in_buffer = 0;
	DATA(state)->offset = 0;
	pthread_mutex_init(&DATA(state)->mutex,NULL);
	pthread_cond_init(&DATA(state)->data_ready,NULL);
	pthread_cond_init(&DATA(state)->space_avail,NULL);

	DATA(state)->io = parent;
	DATA(state)->closing = false;

	pthread_create(&DATA(state)->producer,NULL,thread_producer,state);

	return state;
}

static off_t thread_read(io_t *state, void *buffer, off_t len)
{
	int slice;
	int copied=0;
	int newbuffer;

	while(len>0) {
		pthread_mutex_lock(&DATA(state)->mutex);
		while (INBUFFER(state).state == EMPTY) {
			pthread_cond_wait(&DATA(state)->data_ready, &DATA(state)->mutex);

		}

		if (INBUFFER(state).len <1) {

			if (copied<1) {
				errno=EIO; /* FIXME: Preserve the errno from the other thread */
				copied = INBUFFER(state).len;
			}

			pthread_mutex_unlock(&DATA(state)->mutex);
			return copied;
		}

		slice=min( INBUFFER(state).len-DATA(state)->offset,len);

		pthread_mutex_unlock(&DATA(state)->mutex);
				
		memcpy(
			buffer,
			INBUFFER(state).buffer+DATA(state)->offset,
			slice
			);

		buffer+=slice;
		len-=slice;
		copied+=slice;

		pthread_mutex_lock(&DATA(state)->mutex);
		DATA(state)->offset+=slice;
		newbuffer = DATA(state)->in_buffer;

		if (DATA(state)->offset >= INBUFFER(state).len) {
			INBUFFER(state).state = EMPTY;
			pthread_cond_signal(&DATA(state)->space_avail);
			newbuffer = (newbuffer+1) % BUFFERS;
			DATA(state)->offset = 0;
		}

		pthread_mutex_unlock(&DATA(state)->mutex);

		DATA(state)->in_buffer = newbuffer;
	}
	return copied;
}

static void thread_close(io_t *io)
{
	pthread_mutex_lock(&DATA(io)->mutex);
	DATA(io)->closing = true;
	pthread_cond_signal(&DATA(io)->space_avail);
	pthread_mutex_unlock(&DATA(io)->mutex);

	/* Wait for the thread to exit */
	pthread_join(DATA(io)->producer, NULL);
	free(DATA(io));
	free(io);
}

io_source_t thread_source = {
	"thread",
	thread_read,
	NULL,	/* peek */
	NULL,	/* tell */
	NULL,	/* seek */
	thread_close
};
