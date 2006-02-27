/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson 
 *          Perry Lorier 
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */

#include "common.h"
#include "config.h"
#include <errno.h>
#include <stdlib.h> /* free */
#include <stdio.h> /* sprintf, printf */
#include <assert.h> /* assert */
#include <string.h> /* bzero */
#include "fifo.h"
#include "libtrace_int.h"

#include <sys/types.h>

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#else
# error "Can't find inttypes.h, this needs to be fixed"
#endif

#ifdef HAVE_STDDEF_H
# include <stddef.h>
#else
# error "Can't find stddef.h - do you define ptrdiff_t elsewhere"
#endif

#include <netinet/in.h>


enum which_t { IN, OUT, ACK };

struct tracefifo_t {
        size_t length;
        size_t datamap[3];
        void *base;
};

/* This MIN is more generic but not as portable
 * #define MIN(a,b) ({ int _a = a; int _b = b; (_a < _b) ? _a : _b; })
 */
#define MIN(a,b) ((a)<(b)?(a):(b))

static char *tracefifo_stat_buffer = 0;

static void increment_pointer(struct tracefifo_t *fifo, enum which_t which, int amount);
static void set_pointer(struct tracefifo_t *fifo, enum which_t which, unsigned int location);
static size_t tracefifo_compare(struct tracefifo_t *fifo, enum which_t first, enum which_t second);
static int tracefifo_read_generic(struct tracefifo_t *fifo, void *buffer, size_t len, enum which_t which, char update);

struct tracefifo_t *create_tracefifo(size_t size) 
{
        /* Set up our fifo
        */
        struct tracefifo_t *fifo = malloc(sizeof(struct tracefifo_t));
        assert(size > 0);

        fifo->length = size;

        if ((fifo->base = malloc(fifo->length)) == 0) {
                return 0;
        }

        fifo->datamap[IN] = 0;
        fifo->datamap[OUT] = 0;
        fifo->datamap[ACK] = 0;
        return fifo;
}

void destroy_tracefifo(struct tracefifo_t *fifo)
{
        assert(fifo);
        free(fifo->base);
        free(fifo);
}

static void increment_pointer(struct tracefifo_t *fifo, enum which_t which, int amount) {
        assert(fifo);
        assert(which == IN || which == OUT || which == ACK);
        assert(amount >= 0);

        if ((fifo->datamap[which] + amount) >= fifo->length) {
                fifo->datamap[which] = (fifo->datamap[which] + amount - fifo->length);
        } else {
                fifo->datamap[which] += amount;
        }
}

void tracefifo_flush(struct tracefifo_t *fifo __attribute__((unused))) {
        /* do nothing */
        return;
}

static void set_pointer(struct tracefifo_t *fifo, enum which_t which, unsigned int location) {
        assert(fifo);
        assert(which == IN || which == OUT || which == ACK);

        assert(location <= fifo->length);

        fifo->datamap[which] = location;
}

static size_t tracefifo_compare(struct tracefifo_t *fifo, enum which_t first, enum which_t second) {
        assert(fifo);
        assert(first == IN || first == OUT || first == ACK);
        assert(second == IN || second == OUT || second == ACK);

        if (fifo->datamap[first] == fifo->datamap[second]) {
                return 0;
        }
        if (fifo->datamap[first] > fifo->datamap[second]) {
                return fifo->datamap[first] - fifo->datamap[second];
        } else {
                return fifo->length - (fifo->datamap[second] - fifo->datamap[first]);
        }
}

size_t tracefifo_free(struct tracefifo_t *fifo) {
        assert(fifo);
        return (fifo->length - tracefifo_compare(fifo,IN,ACK));
} 

size_t tracefifo_length(struct tracefifo_t *fifo) {
        assert(fifo);
        return fifo->length;
}

size_t tracefifo_out_available(struct tracefifo_t *fifo) {
        assert(fifo);
        return tracefifo_compare(fifo,IN,OUT);
}

size_t tracefifo_ack_available(struct tracefifo_t *fifo) {
        assert(fifo);
        return tracefifo_compare(fifo,OUT,ACK);
}

void tracefifo_stat_int(struct tracefifo_t *fifo, tracefifo_state_t *state)
{
        assert(fifo);
        assert(state);

        state->in = fifo->datamap[IN];
        state->out = fifo->datamap[OUT];
        state->ack = fifo->datamap[ACK];
        state->length = fifo->length;
        state->used = tracefifo_compare(fifo,IN,ACK);

}
char *tracefifo_stat_str(struct tracefifo_t *fifo, char *desc, int delta)
{
        char *scan = 0;
        assert(fifo);

        if (tracefifo_stat_buffer == 0) 
                tracefifo_stat_buffer = (char *)malloc(513);

        bzero(tracefifo_stat_buffer,513);
        scan = tracefifo_stat_buffer;
        if (desc)
                scan += sprintf(scan,"%s\t",desc);
        scan += sprintf(scan,"in:   %d \t",fifo->datamap[IN]);
        scan += sprintf(scan,"sent: %d\t", fifo->datamap[OUT]);
        scan += sprintf(scan,"ack:  %d\t", fifo->datamap[ACK]);
        if (delta > 0)
                scan += sprintf(scan,"delta: %d\t", delta);
        scan += sprintf(scan,"Size: %d", tracefifo_compare(fifo,IN,ACK));
        scan += sprintf(scan,"\n");
        return tracefifo_stat_buffer;
}
void tracefifo_stat(struct tracefifo_t *fifo, char *desc, int delta)
{
        assert(fifo);

        printf("%s",tracefifo_stat_str(fifo,desc,delta));
}

/* Read a portion from the given section of the fifo. Note that it is the responsibility 
 * of the caller to ensure that there is something to read! This will return len bytes
 * starting at the pointer corresponding to which - if thats bogus data then its not
 * the fault of this function */
static int tracefifo_read_generic(struct tracefifo_t *fifo, void *buffer, size_t len, enum which_t which, char update) {
        size_t oldptr;
        size_t lenleft;
        int size;
        assert(fifo);
        assert(buffer);

        oldptr = fifo->datamap[which];
        lenleft = len;
        while (lenleft > 0) {
                size = MIN( ( fifo->length - fifo->datamap[which]), lenleft);
                memcpy(buffer, 
                                (char *)((ptrdiff_t)fifo->base + fifo->datamap[which]), 
                                size);
                increment_pointer(fifo,which,size);
                buffer = (char*)buffer+size;
                lenleft -= size;
        }

        if (update == 0) {
                set_pointer(fifo,which,oldptr);
        }
        return len;
}

int tracefifo_write(struct tracefifo_t *fifo, void *buffer, size_t len) {
        size_t lenleft;
        int size;
        assert(fifo);
        assert(buffer);

        if (tracefifo_free(fifo) < len) {
                return 0;
        }

        lenleft = len;
        while (lenleft > 0) {
                size = MIN((fifo->length - fifo->datamap[IN]), lenleft );
                memcpy((char *)((ptrdiff_t)fifo->base + fifo->datamap[IN]), 
                                buffer, 
                                size);
                increment_pointer(fifo,IN,size);
                buffer = (char*)buffer+size;
                lenleft -= size;
        }
        return len;
}


int tracefifo_out_read(struct tracefifo_t *fifo, void *buffer, size_t len) {
        assert(fifo);
        assert(buffer);
        if (tracefifo_compare(fifo,IN,OUT) < len) {
                return 0;
        }
        return tracefifo_read_generic(fifo,buffer,len,OUT,0);
}

int tracefifo_ack_read(struct tracefifo_t *fifo, void *buffer, size_t len) {
        assert(fifo);
        assert(buffer);
        if (tracefifo_compare(fifo,OUT,ACK) < len) {
                return 0;
        }
        return tracefifo_read_generic(fifo,buffer,len,ACK,0);
}

int tracefifo_out_update(struct tracefifo_t *fifo, size_t len){
        assert(fifo);
        if (tracefifo_compare(fifo,IN,OUT) < len) {
                return 0;
        }
        increment_pointer(fifo,OUT,len);
        return len;
}

int tracefifo_ack_update(struct tracefifo_t *fifo, size_t len){
        assert(fifo);
        if (tracefifo_compare(fifo,OUT,ACK) < len) {
                return 0;
        }
        increment_pointer(fifo,ACK,len);
        return len;
}

void tracefifo_out_reset(struct tracefifo_t *fifo) {
        /*
         * This will reset the sent pointer back to the ack pointer. This
         * is called from the application when it realises that any data it
         * has sent but not acked will probably have died for some reason
         */
        assert(fifo);
        fifo->datamap[OUT] = fifo->datamap[ACK];
}

