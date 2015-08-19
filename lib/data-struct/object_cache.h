#ifndef LIBTRACE_OBJECT_CACHE_H
#define LIBTRACE_OBJECT_CACHE_H

#include "ring_buffer.h"
#include "vector.h"


struct local_cache;
typedef struct libtrace_ocache {
	libtrace_ringbuffer_t rb;
	void *(*alloc)(void);
	void (*free)(void *);
	size_t thread_cache_size;
	size_t max_allocations;
	size_t current_allocations;
	pthread_spinlock_t spin;
	size_t nb_thread_list;
	size_t max_nb_thread_list;
	struct local_cache **thread_list;
} libtrace_ocache_t;

DLLEXPORT int libtrace_ocache_init(libtrace_ocache_t *oc, void *(*alloc)(void), void (*free)(void*),
                                    size_t thread_cache_size, size_t buffer_size, bool limit_size);
DLLEXPORT int libtrace_ocache_destroy(libtrace_ocache_t *oc);
DLLEXPORT size_t libtrace_ocache_alloc(libtrace_ocache_t *oc, void *values[], size_t nb_buffers, size_t min_nb_buffers);
DLLEXPORT size_t libtrace_ocache_free(libtrace_ocache_t *oc, void *values[], size_t nb_buffers, size_t min_nb_buffers);
DLLEXPORT void libtrace_zero_ocache(libtrace_ocache_t *oc);
DLLEXPORT void libtrace_ocache_unregister_thread(libtrace_ocache_t *oc);
#endif // LIBTRACE_OBJECT_CACHE_H
