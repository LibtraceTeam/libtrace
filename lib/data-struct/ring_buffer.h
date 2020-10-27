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
#include <semaphore.h>
#include "libtrace.h"
#include "pthread_spinlock.h"

#ifndef LIBTRACE_RINGBUFFER_H
#define LIBTRACE_RINGBUFFER_H

#define LIBTRACE_RINGBUFFER_BLOCKING 0
#define LIBTRACE_RINGBUFFER_POLLING 1

// All of start, elements and end must be accessed in the listed order
// if LIBTRACE_RINGBUFFER_POLLING is to work.
typedef struct libtrace_ringbuffer {
	volatile size_t start;
	size_t size;
	int mode;
	void *volatile*elements;
	pthread_mutex_t wlock;
	pthread_mutex_t rlock;
	pthread_spinlock_t swlock;
	pthread_spinlock_t srlock;
	// We need to ensure that broadcasts dont get lost hence
	// these locks below
	// We avoid using semaphores since they don't allow
	// multiple releases.
	pthread_mutex_t empty_lock;
	pthread_mutex_t full_lock;
	pthread_cond_t empty_cond; // Signal when empties are ready
	pthread_cond_t full_cond; // Signal when fulls are ready
	// Aim to get this on a separate cache line to start - important if spinning
	volatile size_t end;
} libtrace_ringbuffer_t;

DLLEXPORT int libtrace_ringbuffer_init(libtrace_ringbuffer_t * rb, size_t size, int mode);
DLLEXPORT void libtrace_zero_ringbuffer(libtrace_ringbuffer_t * rb);
DLLEXPORT void libtrace_ringbuffer_destroy(libtrace_ringbuffer_t * rb);
DLLEXPORT int libtrace_ringbuffer_is_empty(const libtrace_ringbuffer_t * rb);
DLLEXPORT int libtrace_ringbuffer_is_full(const libtrace_ringbuffer_t * rb);

DLLEXPORT void libtrace_ringbuffer_write(libtrace_ringbuffer_t * rb, void* value);
DLLEXPORT int libtrace_ringbuffer_try_write(libtrace_ringbuffer_t * rb, void* value);
DLLEXPORT void libtrace_ringbuffer_swrite(libtrace_ringbuffer_t * rb, void* value);
DLLEXPORT int libtrace_ringbuffer_try_swrite(libtrace_ringbuffer_t * rb, void* value);
DLLEXPORT int libtrace_ringbuffer_try_swrite_bl(libtrace_ringbuffer_t * rb, void* value);

DLLEXPORT void* libtrace_ringbuffer_read(libtrace_ringbuffer_t *rb) ;
DLLEXPORT int libtrace_ringbuffer_try_read(libtrace_ringbuffer_t *rb, void ** value);
DLLEXPORT void * libtrace_ringbuffer_sread(libtrace_ringbuffer_t *rb);
DLLEXPORT int libtrace_ringbuffer_try_sread(libtrace_ringbuffer_t *rb, void ** value);
DLLEXPORT int libtrace_ringbuffer_try_sread_bl(libtrace_ringbuffer_t *rb, void ** value);



DLLEXPORT size_t libtrace_ringbuffer_write_bulk(libtrace_ringbuffer_t *rb, void *values[], size_t nb_buffers, size_t min_nb_buffers);
DLLEXPORT size_t libtrace_ringbuffer_read_bulk(libtrace_ringbuffer_t *rb, void *values[], size_t nb_buffers, size_t min_nb_buffers);
DLLEXPORT size_t libtrace_ringbuffer_sread_bulk(libtrace_ringbuffer_t *rb, void *values[], size_t nb_buffers, size_t min_nb_buffers);
DLLEXPORT size_t libtrace_ringbuffer_swrite_bulk(libtrace_ringbuffer_t *rb, void *values[], size_t nb_buffers, size_t min_nb_buffers);

#endif
