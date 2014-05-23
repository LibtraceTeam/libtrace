/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock 
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


#include "config.h"
#include "wandio_internal.h"
#include "wandio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

/* Libtrace IO module implementing a threaded reader.
 *
 * This module enables another IO reader, called the "parent", to perform its
 * reading using a separate thread. The reading thread reads data into a
 * series of 1MB buffers. Once all the buffers are full, it waits for the
 * main thread to free up some of the buffers by consuming data from them. The 
 * reading thread also uses a pthread condition to indicate to the main thread
 * that there is data available in the buffers. 
 */

/* 1MB Buffer */
#define BUFFERSIZE (1024*1024)

extern io_source_t thread_source;

/* This structure defines a single buffer or "slice" */
struct buffer_t {
	char buffer[BUFFERSIZE];	/* The buffer itself */
	int len;			/* The size of the buffer */
	enum { EMPTY = 0, FULL = 1 } state;	/* Is the buffer in use? */
};

struct state_t {
	/* The collection of buffers (or slices) */
	struct buffer_t *buffer;
	/* The index of the buffer to read into next */
	int in_buffer;
	/* The read offset into the current buffer */
	off_t offset;
	/* The reading thread */
	pthread_t producer;
	/* Indicates that there is a free buffer to read into */
	pthread_cond_t space_avail;
	/* Indicates that there is data in one of the buffers */
	pthread_cond_t data_ready;
	/* The mutex for the read buffers */
	pthread_mutex_t mutex;
	/* The parent reader */
	io_t *io;
	/* Indicates whether the main thread is concluding */
	bool closing;
};

#define DATA(x) ((struct state_t *)((x)->data))
#define INBUFFER(x) (DATA(x)->buffer[DATA(x)->in_buffer])
#define min(a,b) ((a)<(b) ? (a) : (b))

/* The reading thread */
static void *thread_producer(void* userdata)
{
	io_t *state = (io_t*) userdata;
	int buffer=0;
	bool running = true;

#ifdef PR_SET_NAME
	char namebuf[17];
	if (prctl(PR_GET_NAME, namebuf, 0,0,0) == 0) {
		namebuf[16] = '\0'; /* Make sure it's NUL terminated */
		/* If the filename is too long, overwrite the last few bytes */
		if (strlen(namebuf)>9) {
			strcpy(namebuf+10,"[ior]");
		}
		else {
			strncat(namebuf," [ior]",16);
		}
		prctl(PR_SET_NAME, namebuf, 0,0,0);
	}
#endif

	pthread_mutex_lock(&DATA(state)->mutex);
	do {
		/* If all the buffers are full, we need to wait for one to
		 * become free otherwise we have nowhere to write to! */
		while (DATA(state)->buffer[buffer].state == FULL) {
			if (DATA(state)->closing)
				break;
			pthread_cond_wait(&DATA(state)->space_avail, &DATA(state)->mutex);
		}

		/* Don't bother reading any more data if we are shutting up
		 * shop */
		if (DATA(state)->closing) {
			break;
		}
		pthread_mutex_unlock(&DATA(state)->mutex);

		/* Get the parent reader to fill the buffer */
		DATA(state)->buffer[buffer].len=wandio_read(
				DATA(state)->io,
				DATA(state)->buffer[buffer].buffer,
				sizeof(DATA(state)->buffer[buffer].buffer));

		pthread_mutex_lock(&DATA(state)->mutex);

		DATA(state)->buffer[buffer].state = FULL;

		/* If we've not reached the end of the file keep going */
		running = (DATA(state)->buffer[buffer].len > 0 );

		/* Signal that there is data available for the main thread */
		pthread_cond_signal(&DATA(state)->data_ready);

		/* Move on to the next buffer */
		buffer=(buffer+1) % max_buffers;

	} while(running);

	/* If we reach here, it's all over so start tidying up */
	wandio_destroy(DATA(state)->io);

	pthread_cond_signal(&DATA(state)->data_ready);
	pthread_mutex_unlock(&DATA(state)->mutex);

	return NULL;
}

io_t *thread_open(io_t *parent)
{
	io_t *state;

	if (!parent) {
		return NULL;
	}
	

	state = malloc(sizeof(io_t));
	state->data = calloc(1,sizeof(struct state_t));
	state->source = &thread_source;

	DATA(state)->buffer = (struct buffer_t *)malloc(sizeof(struct buffer_t) * max_buffers);
	memset(DATA(state)->buffer, 0, sizeof(struct buffer_t) * max_buffers);
	DATA(state)->in_buffer = 0;
	DATA(state)->offset = 0;
	pthread_mutex_init(&DATA(state)->mutex,NULL);
	pthread_cond_init(&DATA(state)->data_ready,NULL);
	pthread_cond_init(&DATA(state)->space_avail,NULL);

	DATA(state)->io = parent;
	DATA(state)->closing = false;

	/* Create the reading thread */
	pthread_create(&DATA(state)->producer,NULL,thread_producer,state);

	return state;
}

static off_t thread_read(io_t *state, void *buffer, off_t len)
{
	int slice;
	int copied=0;
	int newbuffer;

	while(len>0) {
		pthread_mutex_lock(&DATA(state)->mutex);
		
		/* Wait for the reader thread to provide us with some data */
		while (INBUFFER(state).state == EMPTY) {
			++read_waits;
			pthread_cond_wait(&DATA(state)->data_ready, &DATA(state)->mutex);

		}
		
		/* Check for errors and EOF */
		if (INBUFFER(state).len <1) {

			if (copied<1) {
				errno=EIO; /* FIXME: Preserve the errno from the other thread */
				copied = INBUFFER(state).len;
			}

			pthread_mutex_unlock(&DATA(state)->mutex);
			return copied;
		}

		/* Copy the next available slice into the main buffer */
		slice=min( INBUFFER(state).len-DATA(state)->offset,len);

		pthread_mutex_unlock(&DATA(state)->mutex);
				
		memcpy(
			buffer,
			INBUFFER(state).buffer+DATA(state)->offset,
			slice
			);

		buffer+=slice;
		len-=slice;
		copied+=slice;

		pthread_mutex_lock(&DATA(state)->mutex);
		DATA(state)->offset+=slice;
		newbuffer = DATA(state)->in_buffer;
		
		/* If we've read everything from the current slice, let the
		 * read thread know that there is now more space available 
		 * and start reading from the next slice */
		if (DATA(state)->offset >= INBUFFER(state).len) {
			INBUFFER(state).state = EMPTY;
			pthread_cond_signal(&DATA(state)->space_avail);
			newbuffer = (newbuffer+1) % max_buffers;
			DATA(state)->offset = 0;
		}

		pthread_mutex_unlock(&DATA(state)->mutex);

		DATA(state)->in_buffer = newbuffer;
	}
	return copied;
}

static void thread_close(io_t *io)
{
	pthread_mutex_lock(&DATA(io)->mutex);
	DATA(io)->closing = true;
	pthread_cond_signal(&DATA(io)->space_avail);
	pthread_mutex_unlock(&DATA(io)->mutex);

	/* Wait for the thread to exit */
	pthread_join(DATA(io)->producer, NULL);
	
	pthread_mutex_destroy(&DATA(io)->mutex);
	pthread_cond_destroy(&DATA(io)->space_avail);
	pthread_cond_destroy(&DATA(io)->data_ready);
	
	free(DATA(io)->buffer);
	free(DATA(io));
	free(io);
}

io_source_t thread_source = {
	"thread",
	thread_read,
	NULL,	/* peek */
	NULL,	/* tell */
	NULL,	/* seek */
	thread_close
};
