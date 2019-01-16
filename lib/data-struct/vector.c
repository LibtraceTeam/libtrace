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
#include "vector.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

DLLEXPORT void libtrace_vector_init(libtrace_vector_t *v, size_t element_size) {
	v->element_size = element_size;
	v->size = 0; // Starts empty
	v->max_size = 128; // Pick a largish size to begin with
	v->elements = malloc(v->max_size * v->element_size);
	ASSERT_RET(pthread_mutex_init(&v->lock, NULL), == 0);
}

DLLEXPORT void libtrace_vector_destroy(libtrace_vector_t *v) {
	ASSERT_RET(pthread_mutex_destroy(&v->lock), == 0);
	free(v->elements);
	// Be safe make sure we wont work any more
	v->elements = NULL;
	v->size = 0;
	v->max_size = 0;
	v->element_size = 0;
}

DLLEXPORT void libtrace_vector_push_back(libtrace_vector_t *v, void *d) {
	ASSERT_RET(pthread_mutex_lock(&v->lock), == 0);
	if (v->size >= v->max_size) {
		/* Resize */
		v->max_size *= 2;
		v->elements = realloc(v->elements, v->max_size * v->element_size);
		if (!v->elements) {
			fprintf(stderr, "Unable to allocate memory for v->elements in libtrace_vector_push_back()\n");
			return;
		}
	}
	memcpy(&v->elements[v->size*v->element_size], d, v->element_size);
	v->size++;
	ASSERT_RET(pthread_mutex_unlock(&v->lock), == 0);
}

DLLEXPORT size_t libtrace_vector_get_size(libtrace_vector_t *v) {
	return v->size;
}

DLLEXPORT int libtrace_vector_get(libtrace_vector_t *v, size_t location, void *d) {
	ASSERT_RET(pthread_mutex_lock(&v->lock), == 0);
	if (location >= v->size) {
		ASSERT_RET(pthread_mutex_unlock(&v->lock), == 0);
		return 0;
	}
	memcpy(d, &v->elements[location*v->element_size], v->element_size);
	ASSERT_RET(pthread_mutex_unlock(&v->lock), == 0);
	return 1;
}

DLLEXPORT int libtrace_vector_remove_front(libtrace_vector_t *v) {
	size_t i;
	ASSERT_RET(pthread_mutex_lock(&v->lock), == 0);
	if (!v->size) {
		ASSERT_RET(pthread_mutex_unlock(&v->lock), == 0);
		return 0;
	}
	v->size--;
	// Of course this is mega slow
	for (i = 0; i < v->size * v->element_size; i++)
		v->elements[i] = v->elements[i+v->element_size];
	ASSERT_RET(pthread_mutex_unlock(&v->lock), == 0);
	return 1;
}

static inline void memswap(void *a, void *b, size_t size) {
	char c;
	size_t i;
	for (i=0; i<size; i++) {
		c = ((char *)a)[i];
		((char *)a)[i] = ((char *)b)[i];
		((char *)b)[i] = c;
	}
}
// Note elements must be the same size
// This also empties the second source array
DLLEXPORT void libtrace_vector_append(libtrace_vector_t *dest, libtrace_vector_t *src)
{
	if (dest->element_size != src->element_size) {
		fprintf(stderr, "Elements must be the same size in libtrace_vector_append()\n");
		return;
	}
	if (src->size == 0) // Nothing to do if this is the case
		return;
	ASSERT_RET(pthread_mutex_lock(&dest->lock), == 0);
	ASSERT_RET(pthread_mutex_lock(&src->lock), == 0);
	if (src->size == 0) // Double check now we've got the locks - Nothing to do if this is the case
		goto unlock;
	if (dest->size == 0) {
		memswap(&dest->max_size, &src->max_size, sizeof(src->max_size));
		memswap(&dest->size, &src->size, sizeof(src->size));
		memswap(&dest->element_size, &src->element_size, sizeof(src->element_size));
		memswap(&dest->elements, &src->elements, sizeof(src->elements));
	} else {
		size_t oldmax = dest->max_size;
		while (dest->max_size - dest->size < src->size) dest->max_size *= 2;
		if (oldmax != dest->max_size)
			dest->elements = realloc(dest->elements, dest->max_size * dest->element_size);
		// Now do the move
		memcpy(&dest->elements[dest->element_size * dest->size], src->elements, src->element_size * src->size);
		// Update the dest size
		dest->size += src->size;
		// Wipe the src
		src->size = 0;
	}
unlock:
	ASSERT_RET(pthread_mutex_unlock(&src->lock), == 0);
	ASSERT_RET(pthread_mutex_unlock(&dest->lock), == 0);
}

DLLEXPORT void libtrace_zero_vector(libtrace_vector_t *v)
{
	v->max_size = 0;
	v->size = 0;
	v->element_size = 0;
	v->elements = NULL;
}

DLLEXPORT void libtrace_vector_empty(libtrace_vector_t *v) {
	ASSERT_RET(pthread_mutex_lock(&v->lock), == 0);
	v->size = 0;
	ASSERT_RET(pthread_mutex_unlock(&v->lock), == 0);
}


DLLEXPORT void libtrace_vector_apply_function(libtrace_vector_t *v, vector_data_fn fn)
{
	size_t cur;
	ASSERT_RET(pthread_mutex_lock(&v->lock), == 0);
	for (cur = 0; cur < v->size; cur++) {
		(*fn)(&v->elements[cur*v->element_size]);
	}
	ASSERT_RET(pthread_mutex_unlock(&v->lock), == 0);
}

DLLEXPORT void libtrace_vector_qsort(libtrace_vector_t *v, int (*compar)(const void *, const void*)) {
	ASSERT_RET(pthread_mutex_lock(&v->lock), == 0);
	qsort(v->elements, v->element_size, v->element_size, compar);
	ASSERT_RET(pthread_mutex_unlock(&v->lock), == 0);
}
