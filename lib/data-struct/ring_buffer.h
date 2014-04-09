#include <pthread.h>
#include <semaphore.h>
#include "../libtrace.h"

#ifndef LIBTRACE_RINGBUFFER_H
#define LIBTRACE_RINGBUFFER_H

#define LIBTRACE_RINGBUFFER_BLOCKING 0
#define LIBTRACE_RINGBUFFER_POLLING 1

// All of start, elements and end must be accessed in the listed order
// if LIBTRACE_RINGBUFFER_POLLING is to work.
typedef struct libtrace_ringbuffer {
	volatile size_t start;
	size_t size;
	int mode;
	void *volatile*elements;
	pthread_mutex_t wlock;
	pthread_mutex_t rlock;
	pthread_spinlock_t swlock;
	pthread_spinlock_t srlock;
	sem_t semrlock;
	sem_t semwlock;
	sem_t emptys;
	sem_t fulls;
	// Aim to get this on a separate cache line to start - important if spinning
	volatile size_t end;
} libtrace_ringbuffer_t;

DLLEXPORT void libtrace_ringbuffer_init(libtrace_ringbuffer_t * rb, size_t size, int mode);
DLLEXPORT void libtrace_zero_ringbuffer(libtrace_ringbuffer_t * rb);
DLLEXPORT void libtrace_ringbuffer_destroy(libtrace_ringbuffer_t * rb);
DLLEXPORT int libtrace_ringbuffer_is_empty(const libtrace_ringbuffer_t * rb);
DLLEXPORT int libtrace_ringbuffer_is_full(const libtrace_ringbuffer_t * rb);

DLLEXPORT void libtrace_ringbuffer_write(libtrace_ringbuffer_t * rb, void* value);
DLLEXPORT int libtrace_ringbuffer_try_write(libtrace_ringbuffer_t * rb, void* value);
DLLEXPORT void libtrace_ringbuffer_swrite(libtrace_ringbuffer_t * rb, void* value);
DLLEXPORT int libtrace_ringbuffer_try_swrite(libtrace_ringbuffer_t * rb, void* value);
DLLEXPORT int libtrace_ringbuffer_try_swrite_bl(libtrace_ringbuffer_t * rb, void* value);

DLLEXPORT void* libtrace_ringbuffer_read(libtrace_ringbuffer_t *rb) ;
DLLEXPORT int libtrace_ringbuffer_try_read(libtrace_ringbuffer_t *rb, void ** value);
DLLEXPORT void * libtrace_ringbuffer_sread(libtrace_ringbuffer_t *rb);
DLLEXPORT int libtrace_ringbuffer_try_sread(libtrace_ringbuffer_t *rb, void ** value);
DLLEXPORT int libtrace_ringbuffer_try_sread_bl(libtrace_ringbuffer_t *rb, void ** value);

#endif
