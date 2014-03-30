#include "trace_sliding_window.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>

/**
 * Implements a sliding window via a ring buffer, this is a fixed size.
 * 
 * @param rb A pointer to a ringbuffer structure.
 * @param size The maximum size of the ring buffer, note 1 of these slots are unusable.
 * @param mode The mode allows selection to use semaphores to signal when data
 * 				becomes available. LIBTRACE_RINGBUFFER_BLOCKING or LIBTRACE_RINGBUFFER_POLLING.
 * 				NOTE: this mainly applies to the blocking functions
 */
inline void libtrace_slidingwindow_init(libtrace_slidingwindow_t *sw, int size, uint64_t start_number) {
	sw->size = size; // All of this size can be used
	sw->start = 0;
	sw->elements = calloc(sw->size, sizeof(void*));
	assert(sw->elements);
	memset(sw->elements, 0, sizeof(void*) * sw->size);
	sw->start_number = start_number;
}

/**
 * Destroys the ring buffer along with any memory allocated to it
 * @param rb The ringbuffer to destroy
 */
inline void libtrace_slidingwindow_destroy(libtrace_slidingwindow_t *sw) {
	sw->size = 0;
	sw->start = 0;
	sw->start_number = 0;
	free((void *)sw->elements);
	sw->elements = NULL;
}


/**
 * Performs a non-blocking write to the buffer, if their is no space
 * or the list is locked by another thread this will return immediately 
 * without writing the value. Assumes that only one thread is writing.
 * Otherwise use libtrace_ringbuffer_try_swrite.
 * 
 * @param rb a pointer to libtrace_ringbuffer structure
 * @param value the value to store
 * @return 1 if a object was written otherwise 0.
 */
inline int libtrace_slidingwindow_try_write(libtrace_slidingwindow_t *sw, uint64_t number, void* value) {
	uint64_t adjusted_number = number - sw->start_number;
	if (adjusted_number < sw->size) {
		// Add it
		sw->elements[(adjusted_number + sw->start) % sw->size] = value;
		return 1;
	} else {
		// Out of range don't add it
		return 0;
	}
}

static inline uint64_t libtrace_slidingwindow_get_min_number(libtrace_slidingwindow_t *sw) {
	return sw->start_number;
}

inline uint64_t libtrace_slidingwindow_read_ready(libtrace_slidingwindow_t *sw) {
	return sw->elements[sw->start] != NULL;
}

/**
 * Tries to read from the supplied buffer if it fails this and returns
 * 0 to indicate nothing was read.
 * 
 * @param rb a pointer to libtrace_ringbuffer structure
 * @param out a pointer to a memory address where the returned item would be placed
 * @return 1 if a object was received otherwise 0, in this case out remains unchanged
 */
inline int libtrace_slidingwindow_try_read(libtrace_slidingwindow_t *sw, void ** value, uint64_t *number) {
	if (sw->elements[sw->start]) {
		*value = sw->elements[sw->start];
		sw->elements[sw->start] = NULL;
		if (number)
			*number = sw->start_number;
		++sw->start_number;
		sw->start = (sw->start + 1) % sw->size;
		return 1;
	} else {
		return 0;
	}
}

inline void libtrace_zero_slidingwindow(libtrace_slidingwindow_t * sw)
{
	sw->start = 0;
	sw->start_number = 0;
	sw->size = 0;
	sw->elements = NULL;
}
