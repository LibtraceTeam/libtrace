#include <pthread.h>

#ifndef DEQUE_H
#define DEQUE_H

typedef struct list_node list_node_t;
typedef struct libtrace_queue {
	list_node_t * head;
	list_node_t * tail;
	pthread_mutex_t lock;
	int size;
	int element_size;
} libtrace_queue_t;

void libtrace_deque_init(libtrace_queue_t * q, int element_size);
inline void libtrace_deque_push_back(libtrace_queue_t *q, void *d);
inline void libtrace_deque_push_front(libtrace_queue_t *q, void *d);
inline int libtrace_deque_get_size(libtrace_queue_t *q);

inline int libtrace_deque_peek_front(libtrace_queue_t *q, void *d);
inline int libtrace_deque_peek_tail(libtrace_queue_t *q, void *d);
inline int libtrace_deque_pop_front(libtrace_queue_t *q, void *d);
inline int libtrace_deque_pop_tail(libtrace_queue_t *q, void *d);
inline void libtrace_zero_deque(libtrace_queue_t *q);

#endif
