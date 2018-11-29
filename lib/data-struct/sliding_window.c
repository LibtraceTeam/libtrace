/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */
#include "sliding_window.h"

#include <stdlib.h>
#include <string.h>

#include <stdio.h>
/**
 * Implements a sliding window via a ring buffer, this is a fixed size.
 * 
 * @param rb A pointer to a ringbuffer structure.
 * @param size The maximum size of the ring buffer, note 1 of these slots are unusable.
 * @param mode The mode allows selection to use semaphores to signal when data
 * 				becomes available. LIBTRACE_RINGBUFFER_BLOCKING or LIBTRACE_RINGBUFFER_POLLING.
 * 				NOTE: this mainly applies to the blocking functions
 */
void libtrace_slidingwindow_init(libtrace_slidingwindow_t *sw, size_t size, uint64_t start_number) {
	sw->size = size; // All of this size can be used
	sw->start = 0;
	sw->elements = calloc(sw->size, sizeof(void*));
	if (!sw->elements) {
		fprintf(stderr, "Unable to allocate memory for sw->elements in libtrace_slidingwindow_init()\n");
		return;
	}
	memset((void *) sw->elements, 0, sizeof(void*) * sw->size);
	sw->start_number = start_number;
}

/**
 * Destroys the ring buffer along with any memory allocated to it
 * @param rb The ringbuffer to destroy
 */
void libtrace_slidingwindow_destroy(libtrace_slidingwindow_t *sw) {
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
int libtrace_slidingwindow_try_write(libtrace_slidingwindow_t *sw, uint64_t number, void* value) {
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

/* 
static inline uint64_t libtrace_slidingwindow_get_min_number(libtrace_slidingwindow_t *sw) {
	return sw->start_number;
}
*/

uint64_t libtrace_slidingwindow_read_ready(libtrace_slidingwindow_t *sw) {
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
int libtrace_slidingwindow_try_read(libtrace_slidingwindow_t *sw, void ** value, uint64_t *number) {
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

void libtrace_zero_slidingwindow(libtrace_slidingwindow_t * sw)
{
	sw->start = 0;
	sw->start_number = 0;
	sw->size = 0;
	sw->elements = NULL;
}
