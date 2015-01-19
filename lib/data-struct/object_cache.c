#include "object_cache.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// pthread tls is most likely slower than __thread, but they have destructors so
// we use a combination of the two here!!
struct local_cache {
	libtrace_ocache_t *oc;
	size_t total;
	size_t used;
	void **cache;
	bool invalid;
};

struct mem_stats {
	struct memfail {
	   uint64_t cache_hit;
	   uint64_t ring_hit;
	   uint64_t miss;
	   uint64_t recycled;
	} readbulk, read, write, writebulk;
};

extern __thread struct mem_stats mem_hits;
static __thread size_t t_mem_caches_used = 0;
static __thread size_t t_mem_caches_total = 0;
static __thread struct local_cache *t_mem_caches = NULL;
static pthread_key_t memory_destructor_key;
static pthread_once_t memory_destructor_once = PTHREAD_ONCE_INIT;

/**
 * @brief unregister_thread assumes we DONT hold spin
 */
static inline void unregister_thread(struct local_cache *lc) {
	size_t i;
	if (lc->invalid)
		fprintf(stderr, "Already free'd the thread cache!!\n");
	pthread_spin_lock(&lc->oc->spin);
	// Remove it from our thread list
	for (i=0; i < lc->oc->nb_thread_list; ++i) {
		if (lc->oc->thread_list[i] == lc) {
			--lc->oc->nb_thread_list;
			lc->oc->thread_list[i] = lc->oc->thread_list[lc->oc->nb_thread_list];
			lc->oc->thread_list[lc->oc->nb_thread_list] = NULL;
			i = ~0U;
			break;
		}
	}
	if (i != ~0U) {
		fprintf(stderr, "Umm this wasn't registered with us in the first place!!!!IGNORGING!!!!ANGRY\n");
		pthread_spin_unlock(&lc->oc->spin);
		return;
	}
	lc->invalid = true;

	if (lc->oc->max_allocations) {
		libtrace_ringbuffer_swrite_bulk(&lc->oc->rb, lc->cache, lc->used, lc->used);
	} else {
		size_t i;
		// We just run the free these
		for(i = 0; i < lc->used; ++i) {
			lc->oc->free(lc->cache[i]);
		}
	}
	pthread_spin_unlock(&lc->oc->spin);
}

/**
 * @brief register_thread assumes we DONT hold spin
 */
static inline void register_thread(libtrace_ocache_t *oc, struct local_cache *lc) {
	lc->invalid = false;
	pthread_spin_lock(&oc->spin);
	if (oc->nb_thread_list == oc->max_nb_thread_list) {
		oc->max_nb_thread_list += 0x10;
		oc->thread_list = realloc(oc->thread_list, sizeof(void*) * oc->max_nb_thread_list);
	}
	oc->thread_list[oc->nb_thread_list] = lc;
	++oc->nb_thread_list;
	pthread_spin_unlock(&oc->spin);
}

static void destroy_memory_cache(void *tlsaddr) {
	assert(tlsaddr == t_mem_caches);
	size_t a;

	for (a = 0; a < t_mem_caches_used; ++a) {
		unregister_thread(&t_mem_caches[a]);
		// Write these all back to the main buffer, this might have issues we would want to free these
		free(t_mem_caches[a].cache);
	}
	free(t_mem_caches);
	t_mem_caches = NULL;
}

static void once_memory_cache_key_init() {
	ASSERT_RET(pthread_key_create(&memory_destructor_key, &destroy_memory_cache), == 0);
}

/**
 * Adds more space to our mem_caches
 */
static void resize_memory_caches() {
	if (t_mem_caches == NULL) {
		pthread_once(&memory_destructor_once, &once_memory_cache_key_init);
		t_mem_caches_total = 0x10;
		t_mem_caches = calloc(0x10, sizeof(struct local_cache));
		pthread_setspecific(memory_destructor_key, (void *) t_mem_caches);
	} else {
		t_mem_caches += 0x10;
		t_mem_caches = realloc(t_mem_caches, t_mem_caches_total * sizeof(struct local_cache));
		pthread_setspecific(memory_destructor_key, t_mem_caches);
	}
}

static inline struct local_cache * find_cache(libtrace_ocache_t *oc) {
	struct local_cache *lc = NULL;
	size_t i;

	for (i = 0; i < t_mem_caches_used; ++i) {
		if (t_mem_caches[i].oc == oc) {
			lc = &t_mem_caches[i];
			break;
		}
	}

	if (!oc->thread_cache_size)
		return 0;

	// Create a cache
	if (!lc) {
		if (t_mem_caches_used == t_mem_caches_total)
			resize_memory_caches();
		t_mem_caches[t_mem_caches_used].oc = oc;
		t_mem_caches[t_mem_caches_used].used = 0;
		t_mem_caches[t_mem_caches_used].total = oc->thread_cache_size;
		t_mem_caches[t_mem_caches_used].cache = malloc(sizeof(void*) * oc->thread_cache_size);
		t_mem_caches[t_mem_caches_used].invalid = false;
		lc = &t_mem_caches[t_mem_caches_used];
		// Register it with the underlying ring_buffer
		register_thread(lc->oc, lc);
		++t_mem_caches_used;
	}

	assert(!lc->invalid);
	return lc;
}

/**
  * Creates a object cache, that is a pool of dynamically allocated and recycled
  * objects of a fixed size. This should be faster than malloc and free.
  * The alloc and free methods are supplied by the user and are used when no
  * recycled objects are available, or to tidy the final results.
  *
  * The performance of these pools will decrease if thread caches are used
  * as this results in a list to lookup per thread. The pool is added when
  * to this list when first encountered, these persist untill the thread exits.
  *
  * NOTE: If limit_size is true do not attempt to 'free' any objects that were
  * not created by this pool back otherwise the 'free' might deadlock. Also
  * be cautious when picking the buffer size, upto thread_cache_size*(threads-1)
  * could be unusable at any given time if these are stuck in thread local caches.
  *
  * @param oc A pointer to the object cache structure which is to be initialised.
  * @param alloc The allocation method, must not be NULL. [void *alloc()]
  * @param free The free method used to destroy packets. [void free(void * obj)]
  * @param thread_cache_size A small cache kept on a per thread basis, this can be 0
  *		however should only be done if bulk reads of packets are being performed
  *		or contention is minimal.
  * @param buffer_size The number of packets to be stored in the main buffer.
  * @param limit_size If true no more objects than buffer_size will be allocated,
  *		reads will block (free never should).Otherwise packets can be freely
  *     allocated upon requested and are free'd if there is not enough space for them.
  * @return If successful returns 0 otherwise -1.
  */
DLLEXPORT int libtrace_ocache_init(libtrace_ocache_t *oc, void *(*alloc)(void),
                                    void (*free)(void *),
                                    size_t thread_cache_size,
                                    size_t buffer_size, bool limit_size) {

	assert(buffer_size);
	assert(alloc);
	assert(free);
	if (libtrace_ringbuffer_init(&oc->rb, buffer_size, LIBTRACE_RINGBUFFER_BLOCKING) != 0) {
		return -1;
	}
	oc->alloc = alloc;
	oc->free = free;
	oc->current_allocations = 0;
	oc->thread_cache_size = thread_cache_size;
	oc->nb_thread_list = 0;
	oc->max_nb_thread_list = 0x10;
	oc->thread_list = calloc(0x10, sizeof(void*));
	if (oc->thread_list == NULL) {
		libtrace_ringbuffer_destroy(&oc->rb);
		return -1;
	}
	pthread_spin_init(&oc->spin, 0);
	if (limit_size)
		oc->max_allocations = buffer_size;
	else
		oc->max_allocations = 0;
	return 0;
}

/**
  * Destroys the object cache. Call this only once all memory has
  * been free'd back and no more accesses will be made.
  *
  * @return Returns the number of packets outstanding, or extra object recevied
  *		Ideally this should be zero (0) otherwise some form of memory leak
  *		is likely present. Currenty only implemented in the case limit_size
  *     is true.
  */
DLLEXPORT int libtrace_ocache_destroy(libtrace_ocache_t *oc) {
	void *ele;

	while (oc->nb_thread_list)
		unregister_thread(oc->thread_list[0]);

	pthread_spin_lock(&oc->spin);
	while (libtrace_ringbuffer_try_read(&oc->rb, &ele)) {
		oc->free(ele);
		if (oc->max_allocations)
			--oc->current_allocations;
	}
	pthread_spin_unlock(&oc->spin);

	// Make sure we haven't lost too many packets
	if (oc->current_allocations)
		fprintf(stderr, "!!OCache closing lost, %d packets!!\n", (int) oc->current_allocations);
	else
		/* This is clearly a bug, but I don't know what to replace it with... */
		fprintf(stderr, "!!OCache closing lost, %d packets!!\n", (int) oc->current_allocations);
	libtrace_ringbuffer_destroy(&oc->rb);
	pthread_spin_destroy(&oc->spin);
	free(oc->thread_list);
	libtrace_zero_ocache(oc);
	if (oc->current_allocations)
		return (int) oc->current_allocations;
	else
		return 0;
}

static inline size_t libtrace_ocache_alloc_cache(libtrace_ocache_t *oc, void *values[], size_t nb_buffers, size_t min_nb_buffers,
										 struct local_cache *lc) {
	libtrace_ringbuffer_t *rb = &oc->rb;
	size_t i;

	// We have enough cached!! Yay
	if (nb_buffers <= lc->used) {
		// Copy all from cache
		memcpy(values, &lc->cache[lc->used - nb_buffers], sizeof(void *) * nb_buffers);
		lc->used -= nb_buffers;
		mem_hits.read.cache_hit += nb_buffers;
		mem_hits.readbulk.cache_hit += 1;
		return nb_buffers;
	}
	// Cache is not big enough try read all from ringbuffer
	else if (nb_buffers > lc->total) {
		i = libtrace_ringbuffer_sread_bulk(rb, values, nb_buffers, min_nb_buffers);
		if (i)
			mem_hits.readbulk.ring_hit += 1;
		else
			mem_hits.readbulk.miss += 1;
		mem_hits.read.ring_hit += i;
	} else { // Not enough cached
		// Empty the cache and re-fill it and then see what we're left with
		i = lc->used;
		memcpy(values, lc->cache, sizeof(void *) * lc->used);
		mem_hits.read.cache_hit += i;

		// Make sure we still meet the minimum requirement
		if (i < min_nb_buffers)
			lc->used = libtrace_ringbuffer_sread_bulk(rb, lc->cache, lc->total, min_nb_buffers - i);
		else
			lc->used = libtrace_ringbuffer_sread_bulk(rb, lc->cache, lc->total, 0);

		if (lc->used == lc->total)
			mem_hits.readbulk.ring_hit += 1;
		else
			mem_hits.readbulk.miss += 1;
		mem_hits.read.ring_hit += lc->used;
	}

	// Try fill the remaining
	if (i < nb_buffers && lc->used) {
		size_t remaining;
		remaining = MIN(lc->used, nb_buffers - i);
		memcpy(&values[i], &lc->cache[lc->used - remaining], sizeof(void *) * remaining);
		lc->used -= remaining;
		i += remaining;
	}
	mem_hits.read.miss += nb_buffers - i;
	assert(i >= min_nb_buffers);
	return i;
}

DLLEXPORT size_t libtrace_ocache_alloc(libtrace_ocache_t *oc, void *values[], size_t nb_buffers, size_t min_nb_buffers) {
	struct local_cache *lc = find_cache(oc);
	size_t i;
	size_t min;
	bool try_alloc = !(oc->max_allocations && oc->max_allocations <= oc->current_allocations);

	assert(oc->max_allocations ? nb_buffers < oc->max_allocations : 1);
	min = try_alloc ? 0: min_nb_buffers;
	if (lc)
		i = libtrace_ocache_alloc_cache(oc, values, nb_buffers, min,  lc);
	else
		i = libtrace_ringbuffer_sread_bulk(&oc->rb, values, nb_buffers, min);

	if (try_alloc) {
		size_t nb;

		// Try alloc the rest
		if (oc->max_allocations) {
			pthread_spin_lock(&oc->spin);
			nb = MIN(oc->max_allocations - oc->current_allocations, nb_buffers - i);
			oc->current_allocations += nb;
			pthread_spin_unlock(&oc->spin);
			nb += i;
		} else {
			nb = nb_buffers;
		}

		for (;i < nb; ++i) {
			values[i] = (*oc->alloc)();
			assert(values[i]);
		}
		assert (i == nb);
		// Still got to wait for more
		if (nb < min_nb_buffers) {
			if (lc)
				i += libtrace_ocache_alloc_cache(oc, &values[nb], nb_buffers - nb, min_nb_buffers - nb, lc);
			else
				i += libtrace_ringbuffer_sread_bulk(&oc->rb, &values[nb], nb_buffers - nb, min_nb_buffers - nb);
		}
	}
	assert(i >= min_nb_buffers);
	return i;
}


static inline size_t libtrace_ocache_free_cache(libtrace_ocache_t *oc, void *values[], size_t nb_buffers, size_t min_nb_buffers,
											struct local_cache *lc) {
	libtrace_ringbuffer_t *rb = &oc->rb;
	size_t i;

	// We have enough cached!! Yay
	if (nb_buffers <= lc->total - lc->used) {
		// Copy all to the cache
		memcpy(&lc->cache[lc->used], values, sizeof(void *) * nb_buffers);
		lc->used += nb_buffers;
		mem_hits.write.cache_hit += nb_buffers;
		mem_hits.writebulk.cache_hit += 1;
		return nb_buffers;
	}
	// Cache is not big enough try write all to the ringbuffer
	else if (nb_buffers > lc->total) {
		i = libtrace_ringbuffer_swrite_bulk(rb, values, nb_buffers, min_nb_buffers);
		if (i)
			mem_hits.writebulk.ring_hit += 1;
		else
			mem_hits.writebulk.miss += 1;
		mem_hits.write.ring_hit += i;
	} else { // Not enough cache space but there might later
		// Fill the cache and empty it and then see what we're left with
		i = (lc->total - lc->used);
		memcpy(&lc->cache[lc->used], values, sizeof(void *) * i);
		mem_hits.write.cache_hit += i;

		// Make sure we still meet the minimum requirement
		if (i < min_nb_buffers)
			lc->used = lc->total - libtrace_ringbuffer_swrite_bulk(rb, lc->cache, lc->total, min_nb_buffers - i);
		else
			lc->used = lc->total - libtrace_ringbuffer_swrite_bulk(rb, lc->cache, lc->total, 0);

		// Re originise fulls to the front
		if (lc->used)
			memmove(lc->cache, &lc->cache[lc->total - lc->used], sizeof(void *) * lc->used);

		if (lc->used)
			mem_hits.writebulk.miss += 1;
		else
			mem_hits.writebulk.ring_hit += 1;
		mem_hits.write.ring_hit += lc->total - lc->used;
	}

	// Try empty the remaining
	if (i < nb_buffers && lc->used != lc->total) {
		size_t remaining;
		remaining = MIN(lc->total - lc->used, nb_buffers - i);
		memcpy(&lc->cache[lc->used], &values[i], sizeof(void *) * remaining);
		lc->used += remaining;
		i += remaining;
	}
	mem_hits.write.miss += nb_buffers - i;
	return i;
}

DLLEXPORT size_t libtrace_ocache_free(libtrace_ocache_t *oc, void *values[], size_t nb_buffers, size_t min_nb_buffers) {
	struct local_cache *lc = find_cache(oc);
	size_t i;
	size_t min;

	assert(oc->max_allocations ? nb_buffers < oc->max_allocations : 1);
	min = oc->max_allocations ? min_nb_buffers : 0;
	if (lc)
		i = libtrace_ocache_free_cache(oc, values, nb_buffers, min, lc);
	else
		i = libtrace_ringbuffer_swrite_bulk(&oc->rb, values, nb_buffers, min);

	if (!oc->max_allocations) {
		// Free these normally
		for (;i < min_nb_buffers; ++i) {
			oc->free(values[i]);
		}
	}
	return i;
}

DLLEXPORT void libtrace_zero_ocache(libtrace_ocache_t *oc) {
	libtrace_zero_ringbuffer(&oc->rb);
	oc->thread_cache_size = 0;
	oc->alloc = NULL;
	oc->free = NULL;
	oc->current_allocations = 0;
	oc->max_allocations = 0;
	oc->nb_thread_list = 0;
	oc->max_nb_thread_list = 0;
	oc->thread_list = NULL;
}

/**
 * @brief ocache_unregister_thread removes a thread from an ocache.
 * @param The ocache to remove this thread, this will free any packets in the TLS cache
 */
DLLEXPORT void libtrace_ocache_unregister_thread(libtrace_ocache_t *oc) {
	size_t i;
	struct local_cache *lc = find_cache(oc);

	if (lc) {
		for (i = 0; i < t_mem_caches_used; ++i) {
			if (&t_mem_caches[i] == lc) {
				// Free the cache against the ocache
				unregister_thread(&t_mem_caches[i]);
				free(t_mem_caches[i].cache);
				// And remove it from the thread itself
				--t_mem_caches_used;
				t_mem_caches[i] = t_mem_caches[t_mem_caches_used];
				memset(&t_mem_caches[t_mem_caches_used], 0, sizeof(struct local_cache));
			}
		}
	}
}
