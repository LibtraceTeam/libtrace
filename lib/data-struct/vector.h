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
#include <pthread.h>
/* Need libtrace.h for DLLEXPORT defines */
#include "../libtrace.h"

#ifndef LIBTRACE_VECTOR_H
#define LIBTRACE_VECTOR_H

typedef void (*vector_data_fn)(void *data);
typedef struct libtrace_vector {
	size_t max_size;
	size_t size;
	size_t element_size;
	char *elements; // Means we can use array indexing
	pthread_mutex_t lock;
} libtrace_vector_t;

DLLEXPORT void libtrace_vector_init(libtrace_vector_t *v, size_t element_size);
DLLEXPORT void libtrace_vector_push_back(libtrace_vector_t *v, void *d);
DLLEXPORT size_t libtrace_vector_get_size(libtrace_vector_t *v);
DLLEXPORT int libtrace_vector_get(libtrace_vector_t *v, size_t location, void *d);
DLLEXPORT void libtrace_vector_append(libtrace_vector_t *dest, libtrace_vector_t *src);
DLLEXPORT void libtrace_vector_destroy(libtrace_vector_t *v);
DLLEXPORT void libtrace_zero_vector(libtrace_vector_t *v);
DLLEXPORT int libtrace_vector_remove_front(libtrace_vector_t *v);
DLLEXPORT void libtrace_vector_empty(libtrace_vector_t *v);

// For now this is a special case and this doesn't really belong
// here, but to do this properly a full lock is required as 
// multiple items are changed
DLLEXPORT void libtrace_vector_apply_function(libtrace_vector_t *v, vector_data_fn fn);

// Sort the vector using qsort
DLLEXPORT void libtrace_vector_qsort(libtrace_vector_t *v, int (*compar)(const void *, const void*));
#endif
