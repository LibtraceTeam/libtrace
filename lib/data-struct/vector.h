#include <pthread.h>
/* Need libtrace.h for DLLEXPORT defines */
#include "../libtrace.h"

#ifndef LIBTRACE_VECTOR_H
#define LIBTRACE_VECTOR_H

typedef struct libtrace_vector {
	int max_size;
	int size;
	int element_size;
	char *elements; // Means we can use array indexing
	pthread_mutex_t lock;
} libtrace_vector_t;

DLLEXPORT inline void libtrace_vector_init(libtrace_vector_t *v, int element_size);
DLLEXPORT inline void libtrace_vector_push_back(libtrace_vector_t *v, void *d);
DLLEXPORT inline int libtrace_vector_get_size(libtrace_vector_t *v);
DLLEXPORT inline int libtrace_vector_get(libtrace_vector_t *v, int location, void *d);
DLLEXPORT inline void libtrace_vector_append(libtrace_vector_t *dest, libtrace_vector_t *src);
DLLEXPORT inline void libtrace_vector_destroy(libtrace_vector_t *v);
DLLEXPORT inline void libtrace_zero_vector(libtrace_vector_t *v);
DLLEXPORT inline int libtrace_vector_remove_front(libtrace_vector_t *v);
DLLEXPORT inline void libtrace_vector_empty(libtrace_vector_t *v);
#endif
