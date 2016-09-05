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
#include <stdint.h>
#include <stddef.h>

#ifndef LIBTRACE_SLIDING_WINDOW_H
#define LIBTRACE_SLIDING_WINDOW_H

#define LIBTRACE_SLIDING_WINDOW_BLOCKING 0
#define LIBTRACE_SLIDING_WINDOW_SPINNING 1

// All of start, elements and end must be accessed in the listed order
// if LIBTRACE_RINGBUFFER_SPINNING is to work.
typedef struct libtrace_slidingwindow {
	volatile size_t start;
	size_t size;
	volatile uint64_t start_number; 
	void *volatile*elements;
} libtrace_slidingwindow_t;

void libtrace_slidingwindow_init(libtrace_slidingwindow_t * sw, size_t size, uint64_t start_number);
void libtrace_zero_slidingwindow(libtrace_slidingwindow_t * sw);
void libtrace_slidingwindow_destroy(libtrace_slidingwindow_t * sw);

/*
int libtrace_slidingwindow_is_empty(const libtrace_slidingwindow_t * sw);
int libtrace_slidingwindow_is_full(const libtrace_slidingwindow_t * sw);
*/

/* void libtrace_slidingwindow_write(libtrace_slidingwindow_t * sw, uint64_t number, void* value); */
int libtrace_slidingwindow_try_write(libtrace_slidingwindow_t * sw, uint64_t number, void* value);

/*void* libtrace_slidingwindow_read(libtrace_slidingwindow_t *sw);*/
int libtrace_slidingwindow_try_read(libtrace_slidingwindow_t *sw, void ** value, uint64_t *number);

uint64_t libtrace_slidingwindow_read_ready(libtrace_slidingwindow_t *sw);
/*
void libtrace_slidingwindow_swrite(libtrace_slidingwindow_t * sw, void* value);
int libtrace_slidingwindow_try_swrite(libtrace_slidingwindow_t * sw, void* value);
int libtrace_slidingwindow_try_swrite_bl(libtrace_slidingwindow_t * sw, void* value);
*/
/*
void * libtrace_slidingwindow_sread(libtrace_slidingwindow_t *sw);
int libtrace_slidingwindow_try_sread(libtrace_slidingwindow_t *sw, void ** value);
int libtrace_slidingwindow_try_sread_bl(libtrace_slidingwindow_t *sw, void ** value);
*/
#endif
