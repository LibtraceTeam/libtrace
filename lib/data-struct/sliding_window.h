#include <stdint.h>
#include <stddef.h>

#ifndef LIBTRACE_SLIDING_WINDOW_H
#define LIBTRACE_SLIDING_WINDOW_H

#define LIBTRACE_SLIDING_WINDOW_BLOCKING 0
#define LIBTRACE_SLIDING_WINDOW_SPINNING 1

// All of start, elements and end must be accessed in the listed order
// if LIBTRACE_RINGBUFFER_SPINNING is to work.
typedef struct libtrace_slidingwindow {
	volatile size_t start;
	size_t size;
	volatile uint64_t start_number; 
	void *volatile*elements;
} libtrace_slidingwindow_t;

void libtrace_slidingwindow_init(libtrace_slidingwindow_t * sw, size_t size, uint64_t start_number);
void libtrace_zero_slidingwindow(libtrace_slidingwindow_t * sw);
void libtrace_slidingwindow_destroy(libtrace_slidingwindow_t * sw);

/*
int libtrace_slidingwindow_is_empty(const libtrace_slidingwindow_t * sw);
int libtrace_slidingwindow_is_full(const libtrace_slidingwindow_t * sw);
*/

/* void libtrace_slidingwindow_write(libtrace_slidingwindow_t * sw, uint64_t number, void* value); */
int libtrace_slidingwindow_try_write(libtrace_slidingwindow_t * sw, uint64_t number, void* value);

/*void* libtrace_slidingwindow_read(libtrace_slidingwindow_t *sw);*/
int libtrace_slidingwindow_try_read(libtrace_slidingwindow_t *sw, void ** value, uint64_t *number);

uint64_t libtrace_slidingwindow_read_ready(libtrace_slidingwindow_t *sw);
/*
void libtrace_slidingwindow_swrite(libtrace_slidingwindow_t * sw, void* value);
int libtrace_slidingwindow_try_swrite(libtrace_slidingwindow_t * sw, void* value);
int libtrace_slidingwindow_try_swrite_bl(libtrace_slidingwindow_t * sw, void* value);
*/
/*
void * libtrace_slidingwindow_sread(libtrace_slidingwindow_t *sw);
int libtrace_slidingwindow_try_sread(libtrace_slidingwindow_t *sw, void ** value);
int libtrace_slidingwindow_try_sread_bl(libtrace_slidingwindow_t *sw, void ** value);
*/
#endif
