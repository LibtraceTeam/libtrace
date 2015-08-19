#include "data-struct/deque.h"
#include <pthread.h>
#include <assert.h>

#define TEST_SIZE 1000000

static void * producer(void * a) {
	libtrace_queue_t * deque = (libtrace_queue_t *) a;
	int i;
	for (i = 0; i < TEST_SIZE; i++)
		libtrace_deque_push_front(deque, &i);
	return 0;
}

static void * consumer(void * a) {
	libtrace_queue_t * deque = (libtrace_queue_t *) a;
	int i, value;
	for (i = 0; i < TEST_SIZE; i++) {
		/* We are going to be running quite slow */
		while (libtrace_deque_pop_tail(deque, &value) == 0);
		assert(value == i);
	}
	return 0;
}

/**
 * Tests the deque data structure, first this establishes that single
 * threaded operations work correctly, then does a basic consumer producer
 * thread-safety test.
 */
int main() {
	int i, value;
	pthread_t t[2];
	libtrace_queue_t deque;

	libtrace_deque_init(&deque, sizeof(int));
	assert(libtrace_deque_get_size(&deque) == 0);

	/* Fill the deqeue like so (TEST_SIZE-1) ... 2 1 0 0 1 2... (TEST_SIZE-1) */
	for (i = 0; i < TEST_SIZE; i++)
		libtrace_deque_push_back(&deque, &i);
	for (i = 0; i < TEST_SIZE; i++)
		libtrace_deque_push_front(&deque, &i);

	assert(libtrace_deque_get_size(&deque) == TEST_SIZE * 2);

	/* Now verify and remove */
	for (i = TEST_SIZE-1; i >= 0; i--) {
		value = -1;
		assert(libtrace_deque_peek_front(&deque, &value));
		assert(value == i);
		value = -1;
		assert(libtrace_deque_pop_front(&deque, &value));
		assert(value == i);
		value = -1;
		assert(libtrace_deque_peek_tail(&deque, &value));
		assert(value == i);
		value = -1;
		assert(libtrace_deque_pop_tail(&deque, &value));
		assert(value == i);
	}
	// It's empty make sure nothing works
	value = -1;
	assert(!libtrace_deque_peek_front(&deque, &value));
	assert(!libtrace_deque_pop_front(&deque, &value));
	assert(!libtrace_deque_peek_tail(&deque, &value));
	assert(!libtrace_deque_pop_tail(&deque, &value));
	assert(value == -1);

	// Test thread safety - We only really care about the single producer single
	// consumer case
	pthread_create(&t[0], NULL, &producer, (void *) &deque);
	pthread_create(&t[1], NULL, &consumer, (void *) &deque);

	pthread_join(t[0], NULL);
	pthread_join(t[1], NULL);
	assert(libtrace_deque_get_size(&deque) == 0);

	return 0;
}