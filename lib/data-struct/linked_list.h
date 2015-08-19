#include "../libtrace.h"

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
