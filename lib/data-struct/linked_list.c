#include "linked_list.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

libtrace_list_t *libtrace_list_init(size_t element_size)
{
	libtrace_list_t *l = (libtrace_list_t *)malloc(sizeof(libtrace_list_t));
	if (l == NULL)
		return NULL;

	memset(l, 0, sizeof(libtrace_list_t));
	l->element_size = element_size;

	return l;
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
	assert(new != NULL);
	new->data = malloc(l->element_size);
	assert(new->data != NULL);

	new->prev = NULL;
	memcpy(new->data, item, l->element_size);

	if (l->head == NULL) {
		assert(l->tail == NULL && l->size == 0);
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
	assert(new != NULL);
	new->data = malloc(l->element_size);
	assert(new->data != NULL);

	new->next = NULL;
	memcpy(new->data, item, l->element_size);

	if (l->tail == NULL) {
		assert(l->head == NULL && l->size == 0);
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
		assert(ret != NULL);
	}

	return ret;
}

size_t libtrace_list_get_size(libtrace_list_t *l)
{
	if (l == NULL)
		return 0;

	return l->size;
}
