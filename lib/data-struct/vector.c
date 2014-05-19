#include "vector.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

DLLEXPORT void libtrace_vector_init(libtrace_vector_t *v, size_t element_size) {
	v->element_size = element_size;
	v->size = 0; // Starts empty
	v->max_size = 128; // Pick a largish size to begin with
	v->elements = malloc(v->max_size * v->element_size);
	assert(pthread_mutex_init(&v->lock, NULL) == 0);
}

DLLEXPORT void libtrace_vector_destroy(libtrace_vector_t *v) {
	assert(pthread_mutex_destroy(&v->lock) == 0);
	free(v->elements);
	// Be safe make sure we wont work any more
	v->elements = NULL;
	v->size = 0;
	v->max_size = 0;
	v->element_size = 0;
}

DLLEXPORT void libtrace_vector_push_back(libtrace_vector_t *v, void *d) {
	assert(pthread_mutex_lock(&v->lock) == 0);
	if (v->size >= v->max_size) {
		/* Resize */
		v->max_size *= 2;
		v->elements = realloc(v->elements, v->max_size * v->element_size);
		assert(v->elements);
	}
	memcpy(&v->elements[v->size*v->element_size], d, v->element_size);
	v->size++;
	assert(pthread_mutex_unlock(&v->lock) == 0);
}

DLLEXPORT size_t libtrace_vector_get_size(libtrace_vector_t *v) {
	return v->size;
}

DLLEXPORT int libtrace_vector_get(libtrace_vector_t *v, size_t location, void *d) {
	assert(pthread_mutex_lock(&v->lock) == 0);
	if (location >= v->size) {
		assert(pthread_mutex_unlock(&v->lock) == 0);
		return 0;
	}
	memcpy(d, &v->elements[location*v->element_size], v->element_size);
	assert(pthread_mutex_unlock(&v->lock) == 0);
	return 1;
}

DLLEXPORT int libtrace_vector_remove_front(libtrace_vector_t *v) {
	size_t i;
	assert(pthread_mutex_lock(&v->lock) == 0);
	if (!v->size) {
		assert(pthread_mutex_unlock(&v->lock) == 0);
		return 0;
	}
	v->size--;
	// Of coarse this is mega slow 
	for (i = 0; i < v->size * v->element_size; i++)
		v->elements[i] = v->elements[i+v->element_size];
	assert(pthread_mutex_unlock(&v->lock) == 0);
	return 1;
}

static inline void memswap(void *a, void *b, size_t size) {
	char c;
	size_t i;
	for (i=0; i<size; i++) {
		c = ((char *)a)[i];
		((char *)a)[i] = ((char *)b)[i];
		((char *)b)[i] = c;
	}
}
// Note elements must be the same size
// This also empties the second source array
DLLEXPORT void libtrace_vector_append(libtrace_vector_t *dest, libtrace_vector_t *src)
{
	assert(dest->element_size == src->element_size);
	if (src->size == 0) // Nothing to do if this is the case
		return;
	assert(pthread_mutex_lock(&dest->lock) == 0);
	assert(pthread_mutex_lock(&src->lock) == 0);
	if (src->size == 0) // Double check now we've got the locks - Nothing to do if this is the case
		goto unlock;
	if (dest->size == 0) {
		memswap(&dest->max_size, &src->max_size, sizeof(src->max_size));
		memswap(&dest->size, &src->size, sizeof(src->size));
		memswap(&dest->element_size, &src->element_size, sizeof(src->element_size));
		memswap(&dest->elements, &src->elements, sizeof(src->elements));
	} else {
		size_t oldmax = dest->max_size;
		while (dest->max_size - dest->size < src->size) dest->max_size *= 2;
		if (oldmax != dest->max_size)
			dest->elements = realloc(dest->elements, dest->max_size * dest->element_size);
		// Now do the move
		memcpy(&dest->elements[dest->element_size * dest->size], src->elements, src->element_size * src->size);
		// Update the dest size
		dest->size += src->size;
		// Wipe the src
		src->size = 0;
	}
unlock:
	assert(pthread_mutex_unlock(&src->lock) == 0);
	assert(pthread_mutex_unlock(&dest->lock) == 0);
}

DLLEXPORT void libtrace_zero_vector(libtrace_vector_t *v)
{
	v->max_size = 0;
	v->size = 0;
	v->element_size = 0;
	v->elements = NULL;
}

DLLEXPORT void libtrace_vector_empty(libtrace_vector_t *v) {
	assert(pthread_mutex_lock(&v->lock) == 0);
	v->size = 0;
	assert(pthread_mutex_unlock(&v->lock) == 0);
}


DLLEXPORT void libtrace_vector_apply_function(libtrace_vector_t *v, vector_data_fn fn)
{
	size_t cur;
	assert(pthread_mutex_lock(&v->lock) == 0);
	for (cur = 0; cur < v->size; cur++) {
		(*fn)(&v->elements[cur*v->element_size]);
	}
	assert(pthread_mutex_unlock(&v->lock) == 0);
}