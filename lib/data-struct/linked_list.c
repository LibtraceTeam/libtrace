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
#include "linked_list.h"
#include "libtrace_int.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

libtrace_list_t *libtrace_list_init(size_t element_size)
{
	libtrace_list_t *l = (libtrace_list_t *)calloc(1, sizeof(libtrace_list_t));
	if (l == NULL)
		return NULL;

	l->element_size = element_size;

	return l;
}

libtrace_list_t *libtrace_list_init_aligned(size_t element_size, size_t alignment)
{
	/* alignment needs to be 1) a power of 2, and 2) a multiple of sizeof(void *) */
	if (alignment >= sizeof(void *) &&
	    ((alignment & (alignment - 1)) == 0)) { /* pwr of 2 */
		libtrace_list_t *ret = libtrace_list_init(element_size);
		if (ret) {
			ret->alignment = alignment;
		}
		return ret;
	} else {
		fprintf(stderr, "libtrace_list_init_aligned() invalid alignment requested %zu", alignment);
		return NULL;
	}
}

void libtrace_list_deinit(libtrace_list_t *l)
{
	libtrace_list_node_t *tmp, *next;
	if (l == NULL)
		return;

	tmp = l->head;
	while (tmp != NULL) {
		next = tmp->next;

		if (tmp->data)
			free(tmp->data);
		free(tmp);

		tmp = next;
	}

	free(l);
}

void libtrace_list_push_front(libtrace_list_t *l, void *item)
{
	libtrace_list_node_t *new;

	if (l == NULL || item == NULL)
		return;

	/* Create the new node */
	new = (libtrace_list_node_t *)malloc(sizeof(libtrace_list_node_t));
	if (!new) {
		fprintf(stderr, "Unable to allocate memory for node in libtrace_list_push_front()\n");
		return;
	}
	new->data = malloc(l->element_size);
	if (!new->data) {
		fprintf(stderr, "Unable to allocate memory for node data in libtrace_list_push_front()\n");
	}

	new->prev = NULL;
	memcpy(new->data, item, l->element_size);

	if (l->head == NULL) {
		if (l->tail != NULL || l->size != 0) {
			fprintf(stderr, "Error cannot have a NULL head with a non NULL tail and a size of non 0 in libtrace_list_push_front()\n");
			return;
		}
		new->next = NULL;
		l->head = l->tail = new;
	} else {
		l->head->prev = new;
		new->next = l->head;
		l->head = new;
	}
	l->size++;
}

void libtrace_list_push_back(libtrace_list_t *l, void *item)
{
	libtrace_list_node_t *new;

	if (l == NULL || item == NULL)
		return;

	/* Create the new node */
	new = (libtrace_list_node_t *)malloc(sizeof(libtrace_list_node_t));
	if (!new) {
		fprintf(stderr, "Unable to allocate memory for node in libtrace_list_push_back()\n");
		return;
	}
	if (l->alignment) {
		if (posix_memalign(&new->data, l->alignment, l->element_size) != 0) {
			new->data = NULL;
		}
	} else {
		new->data = malloc(l->element_size);
	}
	if (!new->data) {
		free(new);
		fprintf(stderr, "Unable to allocate memory for node data in libtrace_list_push_back()\n");
		return;
	}
	new->next = NULL;
	memcpy(new->data, item, l->element_size);

	if (l->tail == NULL) {
		if (l->head != NULL || l->size != 0) {
			free(new->data);
			free(new);
			fprintf(stderr, "Error cannot have a NULL tail with a non NULL head and a size of non 0 in libtrace_list_push_back()\n");
			return;
		}
		new->prev = NULL;
		l->head = l->tail = new;
	} else {
		l->tail->next = new;
		new->prev = l->tail;
		l->tail = new;
	}
	l->size++;
}

int libtrace_list_pop_front(libtrace_list_t *l, void *item)
{
	int ret = 0;
	libtrace_list_node_t *n;

	if (l == NULL || item == NULL)
		return -1;

	if (l->head != NULL) {
		n = l->head;
		ret = 1;

		/* Relink the list */
		l->head = l->head->next;
		if (l->head)
			l->head->prev = NULL;
		l->size--;
		if (l->size <= 1)
			l->tail = l->head;
	}

	/* If we managed to pull a node out, copy the data and free the
	 * node */
	if (ret) {
		memcpy(item, n->data, l->element_size);
                free(n->data);
		free(n);
	}

	return ret;
}

int libtrace_list_pop_back(libtrace_list_t *l, void *item)
{
	int ret = 0;
	libtrace_list_node_t *n;

	if (l == NULL || item == NULL)
		return -1;

	if (l->tail != NULL) {
		n = l->tail;
		ret = 1;

		/* Relink the list */
		l->tail = l->tail->prev;
		if (l->tail)
			l->tail->next = NULL;
		l->size--;
		if (l->size <= 1)
			l->head = l->tail;
	}

	/* If we managed to pull a node out, copy the data and free the
	 * node */
	if (ret) {
		memcpy(item, n->data, l->element_size);
                free(n->data);
		free(n);
	}

	return ret;
}

libtrace_list_node_t *libtrace_list_get_index(libtrace_list_t *list,
					      size_t index) {
	libtrace_list_node_t *ret = list->head;

	/* Ensure the index is within the list */
	if (index >= list->size) {
		printf("List index out of range\n");
		return NULL;
	}

	/* Scan the list until we get to the desired index. We could be smart
	 * and scan from the top or the bottom depending on which is closer */
	while (index--) {
		ret = ret->next;
		if (!ret) {
			fprintf(stderr, "Error encountered NULL index in libtrace_list_get_index()\n");
			return NULL;
		}
	}

	return ret;
}

size_t libtrace_list_get_size(libtrace_list_t *l)
{
	if (l == NULL)
		return 0;

	return l->size;
}
