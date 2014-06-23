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
#include "wandio.h"
#include "wandio_internal.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

/* Libtrace IO module implementing a threaded writer.
 *
 * This module enables another IO writer, called the "child", to perform its
 * writing using a separate thread. The main thread writes data into a series
 * of 1MB buffers. Meanwhile, the writing thread writes out of these buffers
 * using the callback for the child reader. pthread conditions are used to
 * communicate between the two threads, e.g. when there are buffers available
 * for the main thread to copy data into or when there is data available for
 * the write thread to write.
 */

/* 1MB Buffer */
#define BUFFERSIZE (1024*1024)
#define BUFFERS 5

extern iow_source_t thread_wsource;

/* This structure defines a single buffer or "slice" */
struct buffer_t {
	char buffer[BUFFERSIZE];	/* The buffer itself */
	int len;			/* The size of the buffer */
	enum { EMPTY = 0, FULL = 1 } state;	/* Is the buffer in use? */
};

struct state_t {
	/* The collection of buffers (or slices) */
	struct buffer_t buffer[BUFFERS];
	/* The write offset into the current buffer */
	off_t offset;
	/* The writing thread */
	pthread_t consumer;
	/* The child writer */
	iow_t *iow;
	/* Indicates that there is data in one of the buffers */
	pthread_cond_t data_ready;
	/* Indicates that there is a free buffer to write into */
	pthread_cond_t space_avail;
	/* The mutex for the write buffers */
	pthread_mutex_t mutex;
	/* The index of the buffer to write into next */
	int out_buffer;
	/* Indicates whether the main thread is concluding */
	bool closing;
};

#define DATA(x) ((struct state_t *)((x)->data))
#define OUTBUFFER(x) (DATA(x)->buffer[DATA(x)->out_buffer])
#define min(a,b) ((a)<(b) ? (a) : (b))

/* The writing thread */
static void *thread_consumer(void *userdata)
{
	int buffer=0;
	bool running = true;
	iow_t *state = (iow_t *) userdata;

#ifdef PR_SET_NAME
	char namebuf[17];
	if (prctl(PR_GET_NAME, namebuf, 0,0,0) == 0) {
		namebuf[16] = '\0'; /* Make sure it's NUL terminated */
		/* If the filename is too long, overwrite the last few bytes */
		if (strlen(namebuf)>9) {
			strcpy(namebuf+10,"[iow]");
		}
		else {
			strncat(namebuf," [iow]",16);
		}
		prctl(PR_SET_NAME, namebuf, 0,0,0);
	}
#endif

	pthread_mutex_lock(&DATA(state)->mutex);
	do {
		/* Wait for data that we can write */
		while (DATA(state)->buffer[buffer].state == EMPTY) {
			/* Unless, of course, the program is over! */
			if (DATA(state)->closing)
				break;
			pthread_cond_wait(&DATA(state)->data_ready,
					&DATA(state)->mutex);
		}
		
		/* Empty the buffer using the child writer */
		pthread_mutex_unlock(&DATA(state)->mutex);
		wandio_wwrite(
				DATA(state)->iow,
				DATA(state)->buffer[buffer].buffer,
				DATA(state)->buffer[buffer].len);
		pthread_mutex_lock(&DATA(state)->mutex);

		/* If we've not reached the end of the file keep going */
		running = ( DATA(state)->buffer[buffer].len > 0 );
		DATA(state)->buffer[buffer].len = 0;
		DATA(state)->buffer[buffer].state = EMPTY;

		/* Signal that we've freed up another buffer for the main
		 * thread to copy data into */
		pthread_cond_signal(&DATA(state)->space_avail);


		/* Move on to the next buffer */
		buffer=(buffer+1) % BUFFERS;

	} while(running);

	/* If we reach here, it's all over so start tidying up */
	wandio_wdestroy(DATA(state)->iow);

	pthread_mutex_unlock(&DATA(state)->mutex);
	return NULL;
}

iow_t *thread_wopen(iow_t *child)
{
	iow_t *state;

	if (!child) {
		return NULL;
	}
	

	state = malloc(sizeof(iow_t));
	state->data = calloc(1,sizeof(struct state_t));
	state->source = &thread_wsource;

	DATA(state)->out_buffer = 0;
	DATA(state)->offset = 0;
	pthread_mutex_init(&DATA(state)->mutex,NULL);
	pthread_cond_init(&DATA(state)->data_ready,NULL);
	pthread_cond_init(&DATA(state)->space_avail,NULL);

	DATA(state)->iow = child;
	DATA(state)->closing = false;

	/* Start the writer thread */
	pthread_create(&DATA(state)->consumer,NULL,thread_consumer,state);

	return state;
}

static off_t thread_wwrite(iow_t *state, const char *buffer, off_t len)
{
	int slice;
	int copied=0;
	int newbuffer;

	pthread_mutex_lock(&DATA(state)->mutex);
	while(len>0) {

		/* Wait for there to be space available for us to write into */
		while (OUTBUFFER(state).state == FULL) {
			write_waits++;
			pthread_cond_wait(&DATA(state)->space_avail,
					&DATA(state)->mutex);
		}

		/* Copy out of our main buffer into the next available slice */
		slice=min( 
			(off_t)sizeof(OUTBUFFER(state).buffer)-DATA(state)->offset,
			len);
				
		pthread_mutex_unlock(&DATA(state)->mutex);
		memcpy(
			OUTBUFFER(state).buffer+DATA(state)->offset,
			buffer,
			slice
			);
		pthread_mutex_lock(&DATA(state)->mutex);

		DATA(state)->offset += slice;
		OUTBUFFER(state).len += slice;

		buffer += slice;
		len -= slice;
		copied += slice;
		newbuffer = DATA(state)->out_buffer;

		/* If we've filled a buffer, move on to the next one and 
		 * signal to the write thread that there is something for it
		 * to do */
		if (DATA(state)->offset >= (off_t)sizeof(OUTBUFFER(state).buffer)) {
			OUTBUFFER(state).state = FULL;
			pthread_cond_signal(&DATA(state)->data_ready);
			DATA(state)->offset = 0;
			newbuffer = (newbuffer+1) % BUFFERS;
		}

		DATA(state)->out_buffer = newbuffer;
	}

	pthread_mutex_unlock(&DATA(state)->mutex);
	return copied;
}

static void thread_wclose(iow_t *iow)
{
	pthread_mutex_lock(&DATA(iow)->mutex);
	DATA(iow)->closing = true;
	pthread_cond_signal(&DATA(iow)->data_ready);
	pthread_mutex_unlock(&DATA(iow)->mutex);
	pthread_join(DATA(iow)->consumer,NULL);
	
	pthread_mutex_destroy(&DATA(iow)->mutex);
	pthread_cond_destroy(&DATA(iow)->data_ready);
	pthread_cond_destroy(&DATA(iow)->space_avail);
	
	free(iow->data);
	free(iow);
}

iow_source_t thread_wsource = {
	"threadw",
	thread_wwrite,
	thread_wclose
};
