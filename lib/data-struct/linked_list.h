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
#include "libtrace.h"

#ifndef LIBTRACE_LIST_H
#define LIBTRACE_LIST_H

typedef struct list_node libtrace_list_node_t;
struct list_node {
	void *data;
	libtrace_list_node_t *next;
	libtrace_list_node_t *prev;
};

typedef struct libtrace_list {
	libtrace_list_node_t *head;
	libtrace_list_node_t *tail;
	size_t size;
	size_t element_size;
} libtrace_list_t;

DLLEXPORT libtrace_list_t *libtrace_list_init(size_t element_size);
DLLEXPORT void libtrace_list_deinit(libtrace_list_t *l);

DLLEXPORT void libtrace_list_push_front(libtrace_list_t *l, void *item);
DLLEXPORT void libtrace_list_push_back(libtrace_list_t *l, void *item);
DLLEXPORT int libtrace_list_pop_front(libtrace_list_t *l, void *item);
DLLEXPORT int libtrace_list_pop_back(libtrace_list_t *l, void *item);

DLLEXPORT libtrace_list_node_t *libtrace_list_get_index(libtrace_list_t *list,
							size_t index);

DLLEXPORT size_t libtrace_list_get_size(libtrace_list_t *l);

#endif /* LIBTRACE_LINKED_LIST_H */
