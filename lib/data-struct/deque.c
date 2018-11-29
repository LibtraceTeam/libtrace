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
#include "deque.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>


/* Ensure we don't do any reads without locking even if we *know* that 
 * any write will be atomic */
#ifndef RACE_SAFE
#define RACE_SAFE 1
#endif

struct list_node {
	list_node_t * next;
	list_node_t * prev;
	char data[]; // Our item goes here
};

DLLEXPORT void libtrace_deque_init(libtrace_queue_t * q, size_t element_size)
{
	q->head = NULL;
	q->tail = NULL;
	q->size = 0;
	q->element_size = element_size;
	ASSERT_RET(pthread_mutex_init(&q->lock, NULL), == 0);
}

DLLEXPORT void libtrace_deque_push_back(libtrace_queue_t *q, void *d)
{
	// Do as much work as possible outside the lock
	list_node_t * new_node = (list_node_t *) malloc(sizeof(list_node_t) + q->element_size);
	new_node->next = NULL;
	// Fill it
	memcpy(&new_node->data, d, q->element_size);
	// Only ->prev is unknown at this stage to be completed in lock
	ASSERT_RET(pthread_mutex_lock(&q->lock), == 0);
	if (q->head == NULL) {
		if (q->tail != NULL || q->size != 0) {
			fprintf(stderr, "Error deque head cannot be NULL with a non NULL tail and size of more than 0 in libtrace_deque_push_back()\n");
			return;
		}
		new_node->prev = NULL;
		q->head = q->tail = new_node;
	} else {
		if (q->tail == NULL) {
			fprintf(stderr, "Error deque tail cannot be NULL if it contains a head in libtrace_deque_push_back()\n");
			return;
		}
		q->tail->next = new_node;
		new_node->prev = q->tail; // Done the double link
		q->tail = new_node; // Relink tail
	}
	q->size++;
	ASSERT_RET(pthread_mutex_unlock(&q->lock), == 0);
}

DLLEXPORT void libtrace_deque_push_front(libtrace_queue_t *q, void *d)
{
	// Do as much work as possible outside the lock
	list_node_t * new_node = (list_node_t *) malloc(sizeof(list_node_t) + q->element_size);
	new_node->prev = NULL;
	// Fill it
	memcpy(&new_node->data, d, q->element_size);
	// Only ->next is unknown at this stage to be completed in lock
	ASSERT_RET(pthread_mutex_lock(&q->lock), == 0);
	if (q->head == NULL) {
		if (q->tail != NULL || q->size != 0) {
			fprintf(stderr, "Error deque head cannot be NULL with a non NULL tail and size of more than 0 in libtrace_deque_push_front()\n");
			return;
		}
		new_node->next = NULL;
		q->head = q->tail = new_node;
	} else {
		q->head->prev = new_node;
		new_node->next = q->head; // Done the double link
		q->head = new_node; // Relink head
		// Void out the other things
	}
	q->size++;
	ASSERT_RET(pthread_mutex_unlock(&q->lock), == 0);
}

DLLEXPORT int libtrace_deque_peek_front(libtrace_queue_t *q, void *d)
{
	int ret = 1;
	ASSERT_RET(pthread_mutex_lock(&q->lock), == 0);
	if (q->head == NULL)
		ret = 0;
	else
		memcpy(d, &q->head->data, q->element_size);
	ASSERT_RET(pthread_mutex_unlock(&q->lock), == 0);
	return ret;
}

DLLEXPORT int libtrace_deque_peek_tail(libtrace_queue_t *q, void *d)
{
	int ret = 1;
	ASSERT_RET(pthread_mutex_lock(&q->lock), == 0);
	if (q->tail == NULL)
		ret = 0;
	else
		memcpy(d, &q->tail->data, q->element_size);
	ASSERT_RET(pthread_mutex_unlock(&q->lock), == 0);
	return ret;
}

DLLEXPORT int libtrace_deque_pop_front(libtrace_queue_t *q, void *d)
{
	int ret = 0;
	list_node_t * n = NULL;
	ASSERT_RET(pthread_mutex_lock(&q->lock), == 0);
	if (q->head != NULL) {
		n = q->head;
		ret = 1;
		q->head = n->next;
		if (q->head)
			q->head->prev = NULL;
		q->size--;
		if (q->size <= 1) // Either 1 or 0 items
			q->tail = q->head;
	}
	ASSERT_RET(pthread_mutex_unlock(&q->lock), == 0);
	// Unlock once we've removed it :)
	if (ret) {
		memcpy(d, &n->data, q->element_size);
		free(n);
	}
	return ret;
}

DLLEXPORT int libtrace_deque_pop_tail(libtrace_queue_t *q, void *d)
{
	int ret = 0;
	list_node_t * n=NULL;
	ASSERT_RET(pthread_mutex_lock(&q->lock), == 0);
	if (q->tail != NULL) {
		n = q->tail;
		ret = 1;
		q->tail = n->prev;
		if (q->tail)
			q->tail->next = NULL;
		q->size--;
		if (q->size <= 1) // Either 1 or 0 items
			q->head = q->tail;
	}
	ASSERT_RET(pthread_mutex_unlock(&q->lock), == 0);
	if (ret) {
		memcpy(d, &n->data, q->element_size);
		free(n);
	}
	return ret;
}

DLLEXPORT size_t libtrace_deque_get_size(libtrace_queue_t *q)
{
#if RACE_SAFE
	size_t ret;
	ASSERT_RET(pthread_mutex_lock(&q->lock), == 0);
	ret = q->size;
	ASSERT_RET(pthread_mutex_unlock(&q->lock), == 0);
	return ret;
#else
	return q->size;
#endif
}

DLLEXPORT void libtrace_zero_deque(libtrace_queue_t *q)
{
	q->head = q->tail = NULL;
	q->size = q->element_size = 0;
}

DLLEXPORT void libtrace_deque_apply_function(libtrace_queue_t *q, deque_data_fn fn)
{
	list_node_t *n;
	ASSERT_RET(pthread_mutex_lock(&q->lock), == 0);
	n = q->head;
	for (n = q->head; n != NULL; n = n->next) {
		(*fn)(&n->data);
	}
	ASSERT_RET(pthread_mutex_unlock(&q->lock), == 0);
}
