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

#include <errno.h>
#include <stdlib.h> /* free */
#include <stdio.h> /* perror, sprintf, printf */
#include <assert.h> /* assert */
#include <string.h> /* bzero */
#include "fifo.h"

#include <netinet/in.h>


enum which_t { IN, OUT, ACK };

struct fifo_t {
        size_t length;
        size_t datamap[3];
        void *base;
};

#define MIN(a,b) ({ int _a = a; int _b = b; (_a < _b) ? _a : _b; })


static char *fifo_stat_buffer = 0;

static void increment_pointer(struct fifo_t *fifo, enum which_t which, int amount);
static void set_pointer(struct fifo_t *fifo, enum which_t which, int location);
static size_t fifo_compare(struct fifo_t *fifo, enum which_t first, enum which_t second);
static int fifo_read_generic(struct fifo_t *fifo, void *buffer, size_t len, enum which_t which, char update);

struct fifo_t *create_fifo(size_t size) 
{
        /* Set up our fifo
        */
        struct fifo_t *fifo = malloc(sizeof(struct fifo_t));
        assert(size > 0);

        if (fifo_stat_buffer == 0) 
                fifo_stat_buffer = (char *)malloc(513);
        fifo->length = size;

        if ((fifo->base = malloc(fifo->length)) == 0) {
                perror("malloc");
                return 0;
        }

        fifo->datamap[IN] = 0;
        fifo->datamap[OUT] = 0;
        fifo->datamap[ACK] = 0;
        return fifo;
}

void destroy_fifo(struct fifo_t *fifo)
{
        assert(fifo);
        //free(fifo_stat_buffer);
        free(fifo->base);
        free(fifo);
}

static void increment_pointer(struct fifo_t *fifo, enum which_t which, int amount) {
        assert(fifo);
        assert(which == IN || which == OUT || which == ACK);
        assert(amount >= 0);

        if ((fifo->datamap[which] + amount) >= fifo->length) {
                fifo->datamap[which] = (fifo->datamap[which] + amount - fifo->length);
        } else {
                fifo->datamap[which] += amount;
        }
}

void fifo_flush(struct fifo_t *fifo) {
        // do nothing
        return;
}

static void set_pointer(struct fifo_t *fifo, enum which_t which, int location) {
        assert(fifo);
        assert(which == IN || which == OUT || which == ACK);
        assert(location >= 0);

        assert(location <= fifo->length);

        fifo->datamap[which] = location;
}

static size_t fifo_compare(struct fifo_t *fifo, enum which_t first, enum which_t second) {
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

size_t fifo_free(struct fifo_t *fifo) {
        assert(fifo);
        return (fifo->length - fifo_compare(fifo,IN,ACK));
} 

size_t fifo_length(struct fifo_t *fifo) {
        assert(fifo);
        return fifo->length;
}

size_t fifo_out_available(struct fifo_t *fifo) {
        assert(fifo);
        return fifo_compare(fifo,IN,OUT);
}

size_t fifo_ack_available(struct fifo_t *fifo) {
        assert(fifo);
        return fifo_compare(fifo,OUT,ACK);
}

void fifo_stat_int(struct fifo_t *fifo, fifo_state_t *state)
{
        assert(fifo);
        assert(state);

        state->in = fifo->datamap[IN];
        state->out = fifo->datamap[OUT];
        state->ack = fifo->datamap[ACK];
        state->length = fifo->length;
        state->used = fifo_compare(fifo,IN,ACK);

}
char *fifo_stat_str(struct fifo_t *fifo, char *desc, int delta)
{
        char *scan = 0;
        assert(fifo);

        bzero(fifo_stat_buffer,513);
        scan = fifo_stat_buffer;
        if (desc)
                scan += sprintf(scan,"%s\t",desc);
        scan += sprintf(scan,"in:   %d \t",fifo->datamap[IN]);
        scan += sprintf(scan,"sent: %d\t", fifo->datamap[OUT]);
        scan += sprintf(scan,"ack:  %d\t", fifo->datamap[ACK]);
        if (delta > 0)
                scan += sprintf(scan,"delta: %d\t", delta);
        scan += sprintf(scan,"Size: %d", fifo_compare(fifo,IN,ACK));
        scan += sprintf(scan,"\n");
        return fifo_stat_buffer;
}
void fifo_stat(struct fifo_t *fifo, char *desc, int delta)
{
        assert(fifo);

        printf("%s",fifo_stat_str(fifo,desc,delta));
}

/* Read a portion from the given section of the fifo. Note that it is the responsibility 
 * of the caller to ensure that there is something to read! This will return len bytes
 * starting at the pointer corresponding to which - if thats bogus data then its not
 * the fault of this function */
static int fifo_read_generic(struct fifo_t *fifo, void *buffer, size_t len, enum which_t which, char update) {
        size_t oldptr;
        int lenleft;
        int size;
        assert(fifo);
        assert(buffer);
        assert(len >= 0);

        oldptr = fifo->datamap[which];
        lenleft = len;
        while (lenleft > 0) {
                size = MIN( ( fifo->length - fifo->datamap[which]), lenleft);
                memcpy(buffer, 
                                (char *)((int)fifo->base + fifo->datamap[which]), 
                                size);
                increment_pointer(fifo,which,size);
                buffer += size;
                lenleft -= size;
        }

        if (update == 0) {
                set_pointer(fifo,which,oldptr);
        }
        return len;
}

int fifo_write(struct fifo_t *fifo, void *buffer, size_t len) {
        int lenleft;
        int size;
        assert(fifo);
        assert(buffer);
        assert(len >= 0);

        if (fifo_free(fifo) < len) {
                return 0;
        }

        lenleft = len;
        while (lenleft > 0) {
                size = MIN((fifo->length - fifo->datamap[IN]), lenleft );
                memcpy((char *)((int)fifo->base + fifo->datamap[IN]), 
                                buffer, 
                                size);
                increment_pointer(fifo,IN,size);
                buffer += size;
                lenleft -= size;
        }
        return len;
}


int fifo_out_read(struct fifo_t *fifo, void *buffer, size_t len) {
        assert(fifo);
        assert(buffer);
        assert(len >= 0);
        if (fifo_compare(fifo,IN,OUT) < len) {
                return 0;
        }
        return fifo_read_generic(fifo,buffer,len,OUT,0);
}

int fifo_ack_read(struct fifo_t *fifo, void *buffer, size_t len) {
        assert(fifo);
        assert(buffer);
        assert(len >= 0);
        if (fifo_compare(fifo,OUT,ACK) < len) {
                return 0;
        }
        return fifo_read_generic(fifo,buffer,len,ACK,0);
}

int fifo_out_update(struct fifo_t *fifo, size_t len){
        assert(fifo);
        assert(len >= 0);
        if (fifo_compare(fifo,IN,OUT) < len) {
                return 0;
        }
        increment_pointer(fifo,OUT,len);
        return len;
}

int fifo_ack_update(struct fifo_t *fifo, size_t len){
        assert(fifo);
        assert(len >= 0);
        if (fifo_compare(fifo,OUT,ACK) < len) {
                return 0;
        }
        increment_pointer(fifo,ACK,len);
        return len;
}

void fifo_out_reset(struct fifo_t *fifo) {
        /*
         * This will reset the sent pointer back to the ack pointer. This
         * is called from the application when it realises that any data it
         * has sent but not acked will probably have died for some reason
         */
        assert(fifo);
        fifo->datamap[OUT] = fifo->datamap[ACK];
}

