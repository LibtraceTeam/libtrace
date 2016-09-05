#include "data-struct/vector.h"
#include <pthread.h>
#include <assert.h>

// Note producer consumer is not very efficient using a vector 
#define TEST_SIZE 100000

static void * producer(void * a) {
	libtrace_vector_t * vec = (libtrace_vector_t *) a;
	int i;
	for (i = 0; i < TEST_SIZE; i++)
		libtrace_vector_push_back(vec, &i);
	return 0;
}

static void * consumer(void * a) {
	libtrace_vector_t * vec = (libtrace_vector_t *) a;
	int i, value;
	for (i = 0; i < TEST_SIZE; i++) {
		/* We are going to be running quite slow */
		while (libtrace_vector_get(vec, 0, &value) == 0);
		assert(value == i);
		libtrace_vector_remove_front(vec);
	}
	return 0;
}

/**
 * Tests the vector data structure, first this establishes that single
 * threaded operations work correctly, then does a basic consumer producer
 * thread-safety test.
 */
int main() {
	int i, value;
	pthread_t t[4];
	libtrace_vector_t vector, vector2;

	libtrace_vector_init(&vector, sizeof(int));
	assert(libtrace_vector_get_size(&vector) == 0);

	for (i = 0; i < TEST_SIZE; i++)
		libtrace_vector_push_back(&vector, &i);

	assert(libtrace_vector_get_size(&vector) == TEST_SIZE);

	for (i = 0; i < TEST_SIZE; i++) {
		assert(libtrace_vector_get(&vector, i, &value));
		assert (value == i);
	}

	assert(!libtrace_vector_get(&vector, -1, &value));
	assert(!libtrace_vector_get(&vector, TEST_SIZE, &value));

	for (i = 0; i < TEST_SIZE; i++) {
		assert(libtrace_vector_get(&vector, 0, &value));
		assert (value == i);
		libtrace_vector_remove_front(&vector);
	}
	assert(!libtrace_vector_get(&vector, 0, &value));
	assert(libtrace_vector_get_size(&vector) == 0);

	libtrace_vector_init(&vector2, sizeof(int));
	i = 500;
	libtrace_vector_push_back(&vector2, &i);
	libtrace_vector_append(&vector, &vector2);

	assert(libtrace_vector_get_size(&vector) == 1);
	// The other vector ends up empty
	assert(libtrace_vector_get_size(&vector2) == 0);
	assert(libtrace_vector_remove_front(&vector));

	// Test thread safety - We only really care about the single producer single
	// consumer case
	pthread_create(&t[0], NULL, &producer, (void *) &vector);
	pthread_create(&t[1], NULL, &consumer, (void *) &vector);

	pthread_join(t[0], NULL);
	pthread_join(t[1], NULL);
	assert(libtrace_vector_get_size(&vector) == 0);

	return 0;
}