#include "data-struct/ring_buffer.h"
#include <pthread.h>
#include <assert.h>

#define TEST_SIZE ((char *) 1000000)
#define RINGBUFFER_SIZE ((char *) 10000)

static void * producer(void * a) {
	libtrace_ringbuffer_t * rb = (libtrace_ringbuffer_t *) a;
	char * i;
	for (i = NULL; i < TEST_SIZE; i++) {
		libtrace_ringbuffer_write(rb, i);
	}
	return 0;
}

static void * consumer(void * a) {
	libtrace_ringbuffer_t * rb = (libtrace_ringbuffer_t *) a;
	char *i;
	void *value;
	for (i = NULL; i < TEST_SIZE; i++) {
		value = libtrace_ringbuffer_read(rb);
		assert(value == i);
	}
	return 0;
}

static void * producer_bulk(void * a) {
	libtrace_ringbuffer_t * rb = (libtrace_ringbuffer_t *) a;
	char * i;
	for (i = NULL; i < TEST_SIZE; i++) {
		assert(libtrace_ringbuffer_write_bulk(rb, (void **) &i, 1, 1) == 1);
	}
	return 0;
}

static void * consumer_bulk(void * a) {
	libtrace_ringbuffer_t * rb = (libtrace_ringbuffer_t *) a;
	char *i;
	void *value;
	for (i = NULL; i < TEST_SIZE; i++) {
		assert (libtrace_ringbuffer_read_bulk(rb, &value, 1, 1) == 1);
		assert(value == i);
	}
	return 0;
}


/**
 * Tests the ringbuffer data structure, first this establishes that single
 * threaded operations work correctly, then does a basic consumer producer
 * thread-safety test.
 */
int main() {
	char *i;
	void *value;
	pthread_t t[4];
	libtrace_ringbuffer_t rb_block;
	libtrace_ringbuffer_t rb_polling;

	libtrace_ringbuffer_init(&rb_block, (size_t) RINGBUFFER_SIZE, LIBTRACE_RINGBUFFER_BLOCKING);
	libtrace_ringbuffer_init(&rb_polling, (size_t) RINGBUFFER_SIZE, LIBTRACE_RINGBUFFER_POLLING);
	assert(libtrace_ringbuffer_is_empty(&rb_block));
	assert(libtrace_ringbuffer_is_empty(&rb_polling));

	for (i = NULL; i < RINGBUFFER_SIZE; i++) {
		value = (void *) i;
		libtrace_ringbuffer_write(&rb_block, value);
		libtrace_ringbuffer_write(&rb_polling, value);
	}

	assert(libtrace_ringbuffer_is_full(&rb_block));
	assert(libtrace_ringbuffer_is_full(&rb_polling));

	// Full so trying to write should fail
	assert(!libtrace_ringbuffer_try_write(&rb_block, value));
	assert(!libtrace_ringbuffer_try_write(&rb_polling, value));
	assert(!libtrace_ringbuffer_try_swrite(&rb_block, value));
	assert(!libtrace_ringbuffer_try_swrite(&rb_polling, value));
	assert(!libtrace_ringbuffer_try_swrite_bl(&rb_block, value));
	assert(!libtrace_ringbuffer_try_swrite_bl(&rb_polling, value));

	// Cycle the buffer a few times
	for (i = NULL; i < TEST_SIZE; i++) {
		value = (void *) -1;
		value = libtrace_ringbuffer_read(&rb_block);
		assert(value == (void *) i);
		value = (void *) -1;
		value = libtrace_ringbuffer_read(&rb_polling);
		assert(value == (void *) i);
		value = (void *) (i + (size_t) RINGBUFFER_SIZE);
		libtrace_ringbuffer_write(&rb_block, value);
		libtrace_ringbuffer_write(&rb_polling, value);
	}

	// Empty it completely
	for (i = TEST_SIZE; i < TEST_SIZE + (size_t) RINGBUFFER_SIZE; i++) {
		value = libtrace_ringbuffer_read(&rb_block);
		assert(value == (void *) i);
		value = libtrace_ringbuffer_read(&rb_polling);
		assert(value == (void *) i);
	}
	assert(libtrace_ringbuffer_is_empty(&rb_block));
	assert(libtrace_ringbuffer_is_empty(&rb_polling));

	// Empty so trying to read should fail
	assert(!libtrace_ringbuffer_try_read(&rb_block, &value));
	assert(!libtrace_ringbuffer_try_read(&rb_polling, &value));
	assert(!libtrace_ringbuffer_try_sread(&rb_block, &value));
	assert(!libtrace_ringbuffer_try_sread(&rb_polling, &value));
	assert(!libtrace_ringbuffer_try_sread_bl(&rb_block, &value));
	assert(!libtrace_ringbuffer_try_sread_bl(&rb_polling, &value));

	// Test thread safety - We only really care about the single producer single
	// consumer case
	pthread_create(&t[0], NULL, &producer, (void *) &rb_block);
	pthread_create(&t[1], NULL, &consumer, (void *) &rb_block);
	pthread_join(t[0], NULL);
	pthread_join(t[1], NULL);
	assert(libtrace_ringbuffer_is_empty(&rb_block));

	pthread_create(&t[0], NULL, &producer, (void *) &rb_polling);
	pthread_create(&t[1], NULL, &consumer, (void *) &rb_polling);
	pthread_join(t[0], NULL);
	pthread_join(t[1], NULL);
	assert(libtrace_ringbuffer_is_empty(&rb_polling));

	pthread_create(&t[0], NULL, &producer_bulk, (void *) &rb_block);
	pthread_create(&t[1], NULL, &consumer_bulk, (void *) &rb_block);
	pthread_join(t[0], NULL);
	pthread_join(t[1], NULL);
	assert(libtrace_ringbuffer_is_empty(&rb_block));

	pthread_create(&t[0], NULL, &producer_bulk, (void *) &rb_polling);
	pthread_create(&t[1], NULL, &consumer_bulk, (void *) &rb_polling);
	pthread_join(t[0], NULL);
	pthread_join(t[1], NULL);
	assert(libtrace_ringbuffer_is_empty(&rb_polling));

        libtrace_ringbuffer_destroy(&rb_block);
        libtrace_ringbuffer_destroy(&rb_polling);

        return 0;
}
