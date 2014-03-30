/**
 * A ring or circular buffer, very useful
 */

#include "trace_ringbuffer.h"
#include <stdlib.h>
#include <assert.h>
#include <xmmintrin.h> // This will break stuff on non x86x64 systems

#define LOCK_TYPE_MUTEX 0 // Default if not defined
#define LOCK_TYPE_SPIN 1
#define LOCK_TYPE_SEMAPHORE 2
#define LOCK_TYPE_NONE 3

// No major difference noticed here between mutex and spin, both have there
// downsides.

#define USE_MODULUS 1
#define USE_CHECK_EARLY 1

#define USE_LOCK_TYPE LOCK_TYPE_SPIN
#if USE_LOCK_TYPE == LOCK_TYPE_SPIN
#	define LOCK(dir) assert(pthread_spin_lock(&rb->s ## dir ## lock) == 0)
#	define UNLOCK(dir) assert(pthread_spin_unlock(&rb->s ## dir ## lock) == 0)
#	define TRY_LOCK(dir, action) if(pthread_spin_lock(&rb->s ## dir ## lock) != 0) { \
								action }
#elif USE_LOCK_TYPE == LOCK_TYPE_SEMAPHORE
#	define LOCK(dir) assert(sem_wait(&rb->sem ## dir ## lock) == 0)
#	define UNLOCK(dir) assert(sem_post(&rb->sem ## dir ## lock) == 0)
#	define TRY_LOCK(dir, action) if(sem_trywait(&rb->sem ## dir ## lock) != 0) { \
								action }
#elif USE_LOCK_TYPE == LOCK_TYPE_NONE
#	define LOCK(dir) 
#	define UNLOCK(dir)
#	define TRY_LOCK(dir, action)
#else // Mutex
#	define LOCK(dir) assert(pthread_mutex_lock(&rb-> dir ## lock) == 0)
#	define UNLOCK(dir) assert(pthread_mutex_unlock(&rb-> dir ## lock) == 0)
#	define TRY_LOCK(dir, action) if(pthread_mutex_lock(&rb-> dir ## lock) != 0) {\
								action }
#endif


/**
 * Implements a FIFO queue via a ring buffer, this is a fixed size
 * and all methods are no clobber i.e. will not overwrite old items
 * with new ones.
 * 
 * @param rb A pointer to a ringbuffer structure.
 * @param size The maximum size of the ring buffer. (NOTE: one extra slot is allocated so use -1 if attempting memory alignment)
 * @param mode The mode allows selection to use semaphores to signal when data
 * 				becomes available. LIBTRACE_RINGBUFFER_BLOCKING or LIBTRACE_RINGBUFFER_POLLING.
 * 				NOTE: this mainly applies to the blocking functions
 */
inline void libtrace_ringbuffer_init(libtrace_ringbuffer_t * rb, int size, int mode) {
	size = size + 1;
	assert (size > 1);
	rb->size = size; // Only this -1 actually usable :)
	rb->start = 0;
	rb->end = 0;
	rb->elements = calloc(rb->size, sizeof(void*));
	assert(rb->elements);
	rb->mode = mode;
	if (mode == LIBTRACE_RINGBUFFER_BLOCKING) {
		/* The signaling part - i.e. release when data's ready to read */
		assert(sem_init(&rb->fulls, 0, 0) == 0);
		assert(sem_init(&rb->emptys, 0, size - 1) == 0); // REMEMBER the -1 here :) very important
	}
	/* The mutual exclusion part */
#if USE_LOCK_TYPE == LOCK_TYPE_SPIN
#warning "using spinners"
	assert(pthread_spin_init(&rb->swlock, 0) == 0);
	assert(pthread_spin_init(&rb->srlock, 0) == 0);
#elif USE_LOCK_TYPE == LOCK_TYPE_SEMAPHORE
#warning "using semaphore"
	assert(sem_init(&rb->semrlock, 0, 1) != -1);
	assert(sem_init(&rb->semwlock, 0, 1) != -1);
#elif USE_LOCK_TYPE == LOCK_TYPE_NONE
#warning "No locking used"
#else /* USE_LOCK_TYPE == LOCK_TYPE_MUTEX */
	assert(pthread_mutex_init(&rb->wlock, NULL) == 0);
	assert(pthread_mutex_init(&rb->rlock, NULL) == 0);
#endif
}

/**
 * Destroys the ring buffer along with any memory allocated to it
 * @param rb The ringbuffer to destroy
 */
inline void libtrace_ringbuffer_destroy(libtrace_ringbuffer_t * rb) {
#if USE_LOCK_TYPE == LOCK_TYPE_SPIN
	assert(pthread_spin_destroy(&rb->swlock) == 0);
	assert(pthread_spin_destroy(&rb->srlock) == 0);
#elif USE_LOCK_TYPE == LOCK_TYPE_SEMAPHORE
	assert(sem_destroy(&rb->semrlock) != -1);
	assert(sem_destroy(&rb->semwlock) != -1);
#elif USE_LOCK_TYPE == LOCK_TYPE_NONE
#else /* USE_LOCK_TYPE == LOCK_TYPE_MUTEX */
	assert(pthread_mutex_destroy(&rb->wlock) == 0);
	assert(pthread_mutex_destroy(&rb->rlock) == 0);
#endif
	if (rb->mode == LIBTRACE_RINGBUFFER_BLOCKING) {
		assert(sem_destroy(&rb->fulls) == 0);
		assert(sem_destroy(&rb->emptys) == 0);
	}
	rb->size = 0;
	rb->start = 0;
	rb->end = 0;
	free((void *)rb->elements);
	rb->elements = NULL;
}

/**
 * Tests to see if ringbuffer is empty, when using multiple threads
 * this doesn't guarantee that the next operation wont block. Use
 * write/read try instead.
 */
inline int libtrace_ringbuffer_is_empty(const libtrace_ringbuffer_t * rb) {
	return rb->start == rb->end;
}

/**
 * Tests to see if ringbuffer is empty, when using multiple threads
 * this doesn't guarantee that the next operation wont block. Use
 * write/read try instead.
 */
inline int libtrace_ringbuffer_is_full(const libtrace_ringbuffer_t * rb) {
#if USE_MODULUS
	return rb->start == ((rb->end + 1) % rb->size);
#else
	return rb->start == ((rb->end + 1 < rb->size) ? rb->end + 1 : 0);
#endif
}

/**
 * Performs a blocking write to the buffer, upon return the value will be
 * stored. This will not clobber old values.
 * 
 * This assumes only one thread writing at once. Use 
 * libtrace_ringbuffer_swrite for a thread safe version.
 * 
 * @param rb a pointer to libtrace_ringbuffer structure
 * @param value the value to store
 */
inline void libtrace_ringbuffer_write(libtrace_ringbuffer_t * rb, void* value) {
	/* Need an empty to start with */
	if (rb->mode == LIBTRACE_RINGBUFFER_BLOCKING)
		assert(sem_wait(&rb->emptys) == 0);
	else 
		while (libtrace_ringbuffer_is_full(rb))
			/* Yield our time, why?, we tried and failed to write an item
			 * to the buffer - so we should give up our time in the hope
			 * that the reader thread can empty the buffer giving us a good
			 * burst to write without blocking */
			sched_yield();//_mm_pause();

	rb->elements[rb->end] = value;
#if USE_MODULUS
	rb->end = (rb->end + 1) % rb->size;
#else
	rb->end = (rb->end + 1 < rb->size) ? rb->end + 1 : 0;
#endif
	/* This check is bad we can easily lose our time slice, and the reader
	 * can catch up before it should, in this case spin locking is used */
	//if (libtrace_ringbuffer_is_empty(rb))
	//	assert(0 == 1);
	/* Now we've made another full */
	if (rb->mode == LIBTRACE_RINGBUFFER_BLOCKING)
		assert(sem_post(&rb->fulls) == 0);
}

/**
 * Performs a non-blocking write to the buffer, if their is no space
 * or the list is locked by another thread this will return immediately 
 * without writing the value. Assumes that only one thread is writing.
 * Otherwise use libtrace_ringbuffer_try_swrite.
 * 
 * @param rb a pointer to libtrace_ringbuffer structure
 * @param value the value to store
 * @return 1 if a object was written otherwise 0.
 */
inline int libtrace_ringbuffer_try_write(libtrace_ringbuffer_t * rb, void* value) {
	if (libtrace_ringbuffer_is_full(rb))
		return 0;
	libtrace_ringbuffer_write(rb, value);
	return 1;
}

/**
 * Waits and reads from the supplied buffer, note this will block forever.
 * 
 * @param rb a pointer to libtrace_ringbuffer structure
 * @param out a pointer to a memory address where the returned item would be placed
 * @return The object that was read
 */
inline void* libtrace_ringbuffer_read(libtrace_ringbuffer_t *rb) {
	void* value;
	
	/* We need a full slot */
	if (rb->mode == LIBTRACE_RINGBUFFER_BLOCKING)
		assert(sem_wait(&rb->fulls) == 0);
	else
		while (libtrace_ringbuffer_is_empty(rb)) 
			/* Yield our time, why?, we tried and failed to read an item
			 * from the buffer - so we should give up our time in the hope
			 * that the writer thread can fill the buffer giving us a good
			 * burst to read without blocking etc */
			sched_yield();//_mm_pause();
	
	value = rb->elements[rb->start];
#if USE_MODULUS
	rb->start = (rb->start + 1) % rb->size;
#else
	rb->start = (rb->start + 1 < rb->size) ? rb->start + 1 : 0;
#endif
	/* Now that's a empty slot */
	if (rb->mode == LIBTRACE_RINGBUFFER_BLOCKING)
		assert(sem_post(&rb->emptys) == 0);
	return value;
}

/**
 * Tries to read from the supplied buffer if it fails this and returns
 * 0 to indicate nothing was read.
 * 
 * @param rb a pointer to libtrace_ringbuffer structure
 * @param out a pointer to a memory address where the returned item would be placed
 * @return 1 if a object was received otherwise 0, in this case out remains unchanged
 */
inline int libtrace_ringbuffer_try_read(libtrace_ringbuffer_t *rb, void ** value) {
	if (libtrace_ringbuffer_is_empty(rb))
		return 0;
	*value = libtrace_ringbuffer_read(rb);
	return 1;
}

/**
 * A thread safe version of libtrace_ringbuffer_write
 */
inline void libtrace_ringbuffer_swrite(libtrace_ringbuffer_t * rb, void* value) {
	LOCK(w);
	libtrace_ringbuffer_write(rb, value);
	UNLOCK(w);
}

/**
 * A thread safe version of libtrace_ringbuffer_try_write
 */
inline int libtrace_ringbuffer_try_swrite(libtrace_ringbuffer_t * rb, void* value) {
	int ret;
#if USE_CHECK_EARLY
	if (libtrace_ringbuffer_is_full(rb)) // Check early, drd issues
		return 0;
#endif
	TRY_LOCK(w, return 0;);
	ret = libtrace_ringbuffer_try_write(rb, value);
	UNLOCK(w);
	return ret;
}

/**
 * A thread safe version of libtrace_ringbuffer_try_write
 * Unlike libtrace_ringbuffer_try_swrite this will block on da lock just 
 * not the data. This will block for a long period of time if libtrace_ringbuffer_sread
 * is holding the lock. However will not block for long if only libtrace_ringbuffer_try_swrite_bl
 * and libtrace_ringbuffer_try_swrite are being used.
 */
inline int libtrace_ringbuffer_try_swrite_bl(libtrace_ringbuffer_t * rb, void* value) {
	int ret;
#if USE_CHECK_EARLY
	if (libtrace_ringbuffer_is_full(rb)) // Check early
		return 0;
#endif
	LOCK(w);
	ret = libtrace_ringbuffer_try_write(rb, value);
	UNLOCK(w);
	return ret;
}

/**
 * A thread safe version of libtrace_ringbuffer_read
 */
inline void * libtrace_ringbuffer_sread(libtrace_ringbuffer_t *rb) {
	void* value;
	LOCK(r);
	value = libtrace_ringbuffer_read(rb);
	UNLOCK(r);
	return value;
}

/**
 * A thread safe version of libtrace_ringbuffer_try_write
 */
inline int libtrace_ringbuffer_try_sread(libtrace_ringbuffer_t *rb, void ** value) {
	int ret;
#if USE_CHECK_EARLY
	if (libtrace_ringbuffer_is_empty(rb)) // Check early
		return 0;
#endif
	TRY_LOCK(r, return 0;);
	ret = libtrace_ringbuffer_try_read(rb, value);
	UNLOCK(r);
	return ret;
}

/**
 * A thread safe version of libtrace_ringbuffer_try_wread
 * Unlike libtrace_ringbuffer_try_sread this will block on da lock just 
 * not the data. This will block for a long period of time if libtrace_ringbuffer_sread
 * is holding the lock. However will not block for long if only libtrace_ringbuffer_try_sread_bl
 * and libtrace_ringbuffer_try_sread are being used.
 */
inline int libtrace_ringbuffer_try_sread_bl(libtrace_ringbuffer_t *rb, void ** value) {
	int ret;
#if USE_CHECK_EARLY
	if (libtrace_ringbuffer_is_empty(rb)) // Check early
		return 0;
#endif
	LOCK(r);
	ret = libtrace_ringbuffer_try_read(rb, value);
	UNLOCK(r);
	return ret;
}

inline void libtrace_zero_ringbuffer(libtrace_ringbuffer_t * rb)
{
	rb->start = 0;
	rb->end = 0;
	rb->size = 0;
	rb->elements = NULL;
}
