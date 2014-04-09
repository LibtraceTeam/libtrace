#include "data-struct/ring_buffer.h"
#include <pthread.h>
#include <assert.h>

#define TEST_SIZE 1000000
#define RINGBUFFER_SIZE 10000

static void * producer(void * a) {
	libtrace_ringbuffer_t * rb = (libtrace_ringbuffer_t *) a;
	int i;
	void * value;
	for (i = 0; i < TEST_SIZE; i++) {
		value = (void *) i;
		libtrace_ringbuffer_write(rb, value);
	}
	return 0;
}

static void * consumer(void * a) {
	libtrace_ringbuffer_t * rb = (libtrace_ringbuffer_t *) a;
	int i;
	void * value;
	for (i = 0; i < TEST_SIZE; i++) {
		value = libtrace_ringbuffer_read(rb);
		assert(value == (void *) i);
	}
	return 0;
}

/**
 * Tests the ringbuffer data structure, first this establishes that single
 * threaded operations work correctly, then does a basic consumer producer
 * thread-safety test.
 */
int main() {
	int i;
	void *value;
	pthread_t t[4];
	libtrace_ringbuffer_t rb_block;
	libtrace_ringbuffer_t rb_polling;

	libtrace_ringbuffer_init(&rb_block, RINGBUFFER_SIZE, LIBTRACE_RINGBUFFER_BLOCKING);
	libtrace_ringbuffer_init(&rb_polling, RINGBUFFER_SIZE, LIBTRACE_RINGBUFFER_BLOCKING);
	assert(libtrace_ringbuffer_is_empty(&rb_block));
	assert(libtrace_ringbuffer_is_empty(&rb_polling));

	for (i = 0; i < RINGBUFFER_SIZE; i++) {
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
	for (i = 0; i < TEST_SIZE; i++) {
		value = (void *) -1;
		value = libtrace_ringbuffer_read(&rb_block);
		assert(value == (void *) i);
		value = (void *) -1;
		value = libtrace_ringbuffer_read(&rb_polling);
		assert(value == (void *) i);
		value = (void *) (i + RINGBUFFER_SIZE);
		libtrace_ringbuffer_write(&rb_block, value);
		libtrace_ringbuffer_write(&rb_polling, value);
	}

	// Empty it completely
	for (i = TEST_SIZE; i < TEST_SIZE + RINGBUFFER_SIZE; i++) {
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

	return 0;
}