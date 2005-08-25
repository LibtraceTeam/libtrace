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


#ifndef _FIFO_H_
#define _FIFO_H_

struct tracefifo_t;

typedef struct tracefifo_state {
        long long int in;
        long long int out;
        long long int ack;
        long long int length;
        long long int used;
} tracefifo_state_t;


struct tracefifo_t *create_tracefifo(size_t size);
void destroy_tracefifo(struct tracefifo_t *fifo);


void tracefifo_stat(struct tracefifo_t *fifo, char *desc, int delta);
char *tracefifo_stat_str(struct tracefifo_t *fifo, char *desc, int delta);
void tracefifo_stat_int(struct tracefifo_t *fifo, tracefifo_state_t *state);

size_t tracefifo_out_available(struct tracefifo_t *fifo);
size_t tracefifo_ack_available(struct tracefifo_t *fifo);
size_t tracefifo_free(struct tracefifo_t *fifo);
size_t tracefifo_length(struct tracefifo_t *fifo);

int tracefifo_write(struct tracefifo_t *fifo, void *buffer, size_t len);

int tracefifo_out_read(struct tracefifo_t *fifo, void *buffer, size_t len);
int tracefifo_ack_read(struct tracefifo_t *fifo, void *buffer, size_t len);
int tracefifo_out_update(struct tracefifo_t *fifo, size_t len);
int tracefifo_ack_update(struct tracefifo_t *fifo, size_t len);

void tracefifo_out_reset(struct tracefifo_t *fifo);

void tracefifo_flush(struct tracefifo_t *fifo);



#endif // _FIFO_H_
