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

struct fifo_t;

typedef struct fifo_state {
        long long int in;
        long long int out;
        long long int ack;
        long long int length;
        long long int used;
} fifo_state_t;


struct fifo_t *create_fifo(size_t size);
void destroy_fifo(struct fifo_t *fifo);


void fifo_stat(struct fifo_t *fifo, char *desc, int delta);
char *fifo_stat_str(struct fifo_t *fifo, char *desc, int delta);
void fifo_stat_int(struct fifo_t *fifo, fifo_state_t *state);

size_t fifo_out_available(struct fifo_t *fifo);
size_t fifo_ack_available(struct fifo_t *fifo);
size_t fifo_free(struct fifo_t *fifo);
size_t fifo_length(struct fifo_t *fifo);

int fifo_write(struct fifo_t *fifo, void *buffer, size_t len);

int fifo_out_read(struct fifo_t *fifo, void *buffer, size_t len);
int fifo_ack_read(struct fifo_t *fifo, void *buffer, size_t len);
int fifo_out_update(struct fifo_t *fifo, size_t len);
int fifo_ack_update(struct fifo_t *fifo, size_t len);

void fifo_out_reset(struct fifo_t *fifo);

void fifo_flush(struct fifo_t *fifo);



#endif // _FIFO_H_
