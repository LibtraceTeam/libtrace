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
#ifndef LIBTRACE_OBJECT_CACHE_H
#define LIBTRACE_OBJECT_CACHE_H

#include "ring_buffer.h"
#include "vector.h"


struct local_cache;
typedef struct libtrace_ocache {
	libtrace_ringbuffer_t rb;
	void *(*alloc)(void);
	void (*free)(void *);
	size_t thread_cache_size;
	size_t max_allocations;
	size_t current_allocations;
	pthread_spinlock_t spin;
	size_t nb_thread_list;
	size_t max_nb_thread_list;
	struct local_cache **thread_list;
} libtrace_ocache_t;

DLLEXPORT int libtrace_ocache_init(libtrace_ocache_t *oc, void *(*alloc)(void), void (*free)(void*),
                                    size_t thread_cache_size, size_t buffer_size, bool limit_size);
DLLEXPORT int libtrace_ocache_destroy(libtrace_ocache_t *oc);
DLLEXPORT size_t libtrace_ocache_alloc(libtrace_ocache_t *oc, void *values[], size_t nb_buffers, size_t min_nb_buffers);
DLLEXPORT size_t libtrace_ocache_free(libtrace_ocache_t *oc, void *values[], size_t nb_buffers, size_t min_nb_buffers);
DLLEXPORT void libtrace_zero_ocache(libtrace_ocache_t *oc);
DLLEXPORT void libtrace_ocache_unregister_thread(libtrace_ocache_t *oc);
#endif // LIBTRACE_OBJECT_CACHE_H
