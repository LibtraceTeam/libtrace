/**
 * The built-in combiner functions.
 */

#ifndef COMBINERS_H
#define COMBINERS_H
/**
 * Takes unordered (or ordered) input and produces unordered output.
 * Basically you get the result quickly but in no particular order.
 */
extern const libtrace_combine_t combiner_unordered;
/**
 * Takes ordered input and produces ordered output. Perpkt threads
 * the output results must be ordered!!
 * This will likely have to wait for a queue
 */
extern const libtrace_combine_t combiner_ordered;

/**
 * Like classic Google Map/Reduce, the results are sorted
 * in ascending order, this is only done when the trace finishes.
 *
 * This only works with a limited number of results, otherwise
 * we will just run out of memory and crash!! You should always
 * use combiner_ordered if you can.
 */
extern const libtrace_combine_t combiner_sorted;
#endif // COMBINERS_H



