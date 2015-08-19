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
		assert(q->tail == NULL && q->size == 0);
		new_node->prev = NULL;
		q->head = q->tail = new_node;
	} else {
		assert (q->tail != NULL);
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
		assert(q->tail == NULL && q->size == 0);
		new_node->next = NULL;
		q->head = q->tail = new_node;
	} else {
		assert (q->head != NULL);
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
	list_node_t * n;
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
