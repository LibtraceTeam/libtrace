#include <pthread.h>
#include "../libtrace.h"

#ifndef LIBTRACE_DEQUE_H
#define LIBTRACE_DEQUE_H

typedef struct list_node list_node_t;
typedef void (*deque_data_fn)(void *data);
typedef struct libtrace_queue {
	list_node_t * head;
	list_node_t * tail;
	pthread_mutex_t lock;
	size_t size;
	size_t element_size;
} libtrace_queue_t;

DLLEXPORT void libtrace_deque_init(libtrace_queue_t * q, size_t element_size);
DLLEXPORT void libtrace_deque_push_back(libtrace_queue_t *q, void *d);
DLLEXPORT void libtrace_deque_push_front(libtrace_queue_t *q, void *d);
DLLEXPORT size_t libtrace_deque_get_size(libtrace_queue_t *q);

DLLEXPORT int libtrace_deque_peek_front(libtrace_queue_t *q, void *d);
DLLEXPORT int libtrace_deque_peek_tail(libtrace_queue_t *q, void *d);
DLLEXPORT int libtrace_deque_pop_front(libtrace_queue_t *q, void *d);
DLLEXPORT int libtrace_deque_pop_tail(libtrace_queue_t *q, void *d);
DLLEXPORT void libtrace_zero_deque(libtrace_queue_t *q);

// Apply a given function to every data item, while keeping the entire
// structure locked from external modifications
DLLEXPORT void libtrace_deque_apply_function(libtrace_queue_t *q, deque_data_fn fn);

#endif
