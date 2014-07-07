/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Perry Lorier
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
 * $Id: iow-lzo.c 1521 2010-02-08 22:21:16Z salcock $
 *
 */

/* This writes out lzo files in the same format as lzop does.  It's not as
 * flexible as lzop in an attempt to try and create a very fast method for
 * writing data out.
 *
 * Data is written out in blocks, and the blocks are all compressed in seperate
 * independant threads (if possible), thus letting you use multicore cpu's to
 * get compression for the absolute least amount of walltime while capturing.
 */

#include <lzo/lzo1x.h>
#include "wandio_internal.h"
#include "wandio.h"
#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> /* for mtime */
#include <errno.h>
#include <assert.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h> /* for sysconf */
#include <stdbool.h>
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif


enum { 
	M_LZO1X_1     =     1,
	M_LZO1X_1_15  =     2,
	M_LZO1X_999   =     3,
	M_NRV1A       =  0x1a,
	M_NRV1B       =  0x1b,
	M_NRV2A       =  0x2a,
	M_NRV2B       =  0x2b,
	M_NRV2D       =  0x2d,
	M_ZLIB        =   128,
};

static const int F_OS_UNIX   = 0x03000000L;
static const int F_OS_MASK   = 0xff000000L;

static const int F_CS_NATIVE = 0x00000000L;
static const int F_CS_MASK   = 0x00f00000L;

static const int F_H_CRC32   = 0x00001000L;
static const int F_ADLER32_D = 0x00000001L;
static const int F_ADLER32_C = 0x00000002L;

/* popquiz! You throught "static const int" would be well constant didn't you?
 * You'd be wrong, you can't use them in places where the compiler needs a
 * constant, so you need to use an enum, since enums /are/ constant the compiler
 * will let you use them as such.  Sigh.
 */
enum { MAX_BLOCK_SIZE = 128*1024 }; /* lzop can only decompress blocks 
					this large */

/* According to lzop lzo can increase the data to this size, so save this
 * much space in our buffers 
 */
enum { MAX_BUFFER_SIZE = MAX_BLOCK_SIZE+MAX_BLOCK_SIZE/16+64+3 };

static const unsigned char lzop_magic[9] =
    { 0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };


/* Libtrace IO module implementing a lzo writer */

enum err_t {
	ERR_OK	= 1,
	ERR_EOF = 0,
	ERR_ERROR = -1
};

const int ADLER32_INIT_VALUE = 1;
const int CRC32_INIT_VALUE = 0;

struct buffer_t {
	unsigned int offset;
	char buffer[MAX_BUFFER_SIZE];
};

struct lzothread_t {
	pthread_t thread;
	pthread_cond_t in_ready;
	pthread_cond_t out_ready;
	pthread_mutex_t mutex;
	bool closing;
	enum { EMPTY, WAITING, FULL } state;
	int num;
	struct buffer_t inbuf;
	struct buffer_t outbuf;
};

struct lzow_t {
	iow_t *child;
	enum err_t err;
	int threads;
	int next_thread;
	struct lzothread_t *thread;
};

extern iow_source_t lzo_wsource; 

#define DATA(iow) ((struct lzow_t *)((iow)->data))
#define min(a,b) ((a)<(b) ? (a) : (b))

static void write_buf(struct buffer_t *buffer,const void *data, size_t len)
{
	assert(buffer->offset + len < sizeof(buffer->buffer) && "Exceeded output buffer size in lzo compressor");
	memcpy(&buffer->buffer[buffer->offset], data, len);
	buffer->offset += len;
}

static void write32(struct buffer_t *buffer, uint32_t value)
{
	value = htonl(value);
	write_buf(buffer, &value, sizeof(value));
}

static void write16(struct buffer_t *buffer, uint16_t value)
{
	value = htons(value);
	write_buf(buffer, &value, sizeof(value));
}

static void write8(struct buffer_t *buffer, uint8_t value)
{
	write_buf(buffer, &value, sizeof(value));
}

static int lzo_wwrite_block(const char *buffer, off_t len, struct buffer_t *outbuf)
{
	char b2[MAX_BUFFER_SIZE];
	int err;
	lzo_uint dst_len;
	char scratch[LZO1X_1_MEM_COMPRESS];

	outbuf->offset=0;

	memset(scratch,0,sizeof(scratch));
	err=lzo1x_1_compress((void*)buffer, len, 
			(void*)b2, &dst_len, 
			scratch);

	switch(err) {
		case LZO_E_OK:
			break;
		case LZO_E_ERROR:
			return -EINVAL; /* WTF? */
		case LZO_E_OUT_OF_MEMORY:
			return -ENOMEM; /* Uh oh */
		case LZO_E_NOT_COMPRESSIBLE:
			return -EINVAL; /* Claimed not to be used, dunno what we'll do */
		case LZO_E_INPUT_OVERRUN:
			return -EINVAL;  /* Can't happen on compress? */
		case LZO_E_OUTPUT_OVERRUN:
			return -ENOMEM;
		case LZO_E_LOOKBEHIND_OVERRUN:
			return -EINVAL;
		case LZO_E_EOF_NOT_FOUND:
			return -ENOENT; /* Can't happen on compress? */
		case LZO_E_INPUT_NOT_CONSUMED:
			return -EINVAL;
		case LZO_E_NOT_YET_IMPLEMENTED:
			return -ENOSYS;
		default:
			fprintf(stderr,"Unknown lzo error %d\n",err);
			return -EINVAL;
	}

	write32(outbuf, len); /* Original length */
	write32(outbuf, min((uint32_t)len,(uint32_t)dst_len));
	/* CRC32 of the uncompressed buffer */
#if 0
	write32(outbuf, lzo_crc32(CRC32_INIT_VALUE, (void*)buffer, len));
#endif
	write32(outbuf, 
		lzo_adler32(ADLER32_INIT_VALUE, (const void*)buffer, len));
	write_buf(outbuf, b2, dst_len);

	/* Return the number of bytes compressed */
	return len;
}

/* There is one of these threads per core in a machine.  This compresses 
 * a block of data and returns it, the main thread tehn is responsible to
 * write these back out in the right order.
 */
static void *lzo_compress_thread(void *data)
{
	struct lzothread_t *me = (struct lzothread_t *)data;
	int err;
	char namebuf[17];

#ifdef PR_SET_NAME
	if (prctl(PR_GET_NAME, namebuf, 0,0,0) == 0) {
		char label[16];
		namebuf[16] = '\0'; /* Make sure it's NUL terminated */
		sprintf(label,"[lzo%d]",me->num);
		/* If the filename is too long, overwrite the last few bytes */
		if (strlen(namebuf)>=16-strlen(label)) {
			strcpy(namebuf+15-strlen(label),label);
		}
		else {
			strncat(namebuf," ",16);
			strncat(namebuf,label,16);
		}
		prctl(PR_SET_NAME, namebuf, 0,0,0);
	}
#endif

	pthread_mutex_lock(&me->mutex);
	while (!me->closing) {
		while (me->state != WAITING) {
			if (me->closing)
				break;
			pthread_cond_wait(&me->in_ready, &me->mutex);
		}
		if (me->closing)
			break;

		err=lzo_wwrite_block(
			me->inbuf.buffer, 
			me->inbuf.offset,
			&me->outbuf);

                if (err < 0)
                        break; 
		/* Make sure someone else hasn't clobbered us!*/
		assert(me->state == WAITING);
		me->state = FULL;
		pthread_cond_signal(&me->out_ready);
	}
	pthread_mutex_unlock(&me->mutex);

	return NULL;
}

iow_t *lzo_wopen(iow_t *child, int compress_level)
{
	const int opt_filter = 0;
	int flags;
	iow_t *iow;
	struct buffer_t buffer;
	buffer.offset=0;
	int i;

	if (!child)
		return NULL;

	if (lzo_init() != LZO_E_OK) {
		/* Fail */
		return NULL;
	}

        /* Compress level is useless for LZO, but getting UNUSED into here
         * is more trouble than it is worth so this check will at least
         * stop us from getting warnings about it.
         */
        if (compress_level < 0)
                return NULL;

	iow = malloc(sizeof(iow_t));
	iow->source = &lzo_wsource;
	iow->data = malloc(sizeof(struct lzow_t));

	DATA(iow)->child = child;
	DATA(iow)->err = ERR_OK;

	flags = 0;
	flags |= F_OS_UNIX & F_OS_MASK;	/* Operating System */
	flags |= F_CS_NATIVE & F_CS_MASK;	/* Character Set */
	flags |= F_ADLER32_D; /* We adler32 the uncompressed data */
	/* flags |= F_STDIN; */
	/* flags |= F_STDOUT */
	/* flags |= F_MULTIPART; */
	/* flags |= F_H_CRC32; */

	write_buf(&buffer, lzop_magic, sizeof(lzop_magic));
	write16(&buffer, 0x1010 &0xFFFF); /* version: pretend to be LZOP version 0x1010 from lzop's version.h */
	write16(&buffer, lzo_version() & 0xFFFF); /* libversion */
	write16(&buffer, opt_filter ? 0x0950 : 0x0940); /* version needed to extract */
	write8(&buffer, M_LZO1X_1);	/* method */
	write8(&buffer, 5); /* level */
	write32(&buffer, flags); /* flags */
	/* if (flags & F_H_FILTER) 
		write32(iow, opt_filter); 
	*/ 
	write32(&buffer, 0x600); /* mode: We assume traces may be sensitive */
	write32(&buffer, time(NULL)); /* mtime */
	write32(&buffer, 0); /* GMTdiff */

	/* Length, filename */
	write8(&buffer, strlen("compresseddata"));
	write_buf(&buffer, "compresseddata",strlen("compresseddata"));

	if (flags & F_H_CRC32) {
		write32(&buffer, 
			lzo_crc32(CRC32_INIT_VALUE, 
				(const void*)buffer.buffer+sizeof(lzop_magic), 
				buffer.offset-sizeof(lzop_magic)));
	}
	else {
		uint32_t chksum=lzo_adler32(
			ADLER32_INIT_VALUE, 
			(const void *)buffer.buffer+sizeof(lzop_magic), 
			buffer.offset-sizeof(lzop_magic));
		write32(&buffer, chksum);
	}

	wandio_wwrite(DATA(iow)->child,
		buffer.buffer,
		buffer.offset);

	/* Set up the thread pool -- one thread per core */
	DATA(iow)->threads = min((uint32_t)sysconf(_SC_NPROCESSORS_ONLN),
			use_threads);
	DATA(iow)->thread = malloc(
			sizeof(struct lzothread_t) * DATA(iow)->threads);
	DATA(iow)->next_thread = 0;
	for(i=0; i<DATA(iow)->threads; ++i) {
		pthread_cond_init(&DATA(iow)->thread[i].in_ready, NULL);
		pthread_cond_init(&DATA(iow)->thread[i].out_ready, NULL);
		pthread_mutex_init(&DATA(iow)->thread[i].mutex, NULL);
		DATA(iow)->thread[i].closing = false;
		DATA(iow)->thread[i].num = i;
		DATA(iow)->thread[i].state = EMPTY;
		DATA(iow)->thread[i].inbuf.offset = 0;

		pthread_create(&DATA(iow)->thread[i].thread, 
				NULL,
				lzo_compress_thread,
				(void*)&DATA(iow)->thread[i]);
	}

	return iow;
}

static struct lzothread_t *get_next_thread(iow_t *iow)
{
	return &DATA(iow)->thread[DATA(iow)->next_thread];
}

static off_t lzo_wwrite(iow_t *iow, const char *buffer, off_t len)
{
	off_t ret = 0;
	while (len>0) {
		off_t size = len;
		off_t err;
		struct buffer_t outbuf;

		if (!DATA(iow)->threads) {
			size = min(len, MAX_BLOCK_SIZE);
			err=lzo_wwrite_block(buffer, size, &outbuf);
			/* Flush the data out */
			wandio_wwrite(DATA(iow)->child,
					outbuf.buffer,
					outbuf.offset);

			if (err < 0) {/* Error */
				if (ret == 0)
					return err;
				/* If we've written some data, return that fact now, let them call back
				 * and try and write more data, fail again then. 
				 */
				return ret;
			}
			else {
				assert(err == size);
				buffer += size;
				len -= size;
			}
		}
		else {
			off_t space;

			pthread_mutex_lock(&get_next_thread(iow)->mutex);
			/* If this thread is still compressing, wait for it to finish */
			while (get_next_thread(iow)->state == WAITING) {
				pthread_cond_wait(
					&get_next_thread(iow)->out_ready, 
					&get_next_thread(iow)->mutex);
			}

			/* Flush any data out thats there */
			if (get_next_thread(iow)->state == FULL) {
				assert(get_next_thread(iow)->outbuf.offset 
						< sizeof(get_next_thread(iow)->outbuf.buffer));
				wandio_wwrite(DATA(iow)->child,
						get_next_thread(iow)->outbuf.buffer,
						get_next_thread(iow)->outbuf.offset);
				get_next_thread(iow)->state = EMPTY;
				get_next_thread(iow)->inbuf.offset = 0;
			}

			assert(get_next_thread(iow)->state == EMPTY);

			/* Figure out how much space we can copy into this buffer */
			assert(MAX_BLOCK_SIZE <= sizeof(get_next_thread(iow)->inbuf.buffer));
			space = MAX_BLOCK_SIZE-get_next_thread(iow)->inbuf.offset;
			size = min(space, size);
			assert(size>0);
			assert(size <= MAX_BLOCK_SIZE);
			assert(get_next_thread(iow)->inbuf.offset + size <= MAX_BLOCK_SIZE);

			/* Move our data in */
			memcpy(&get_next_thread(iow)->inbuf.buffer[get_next_thread(iow)->inbuf.offset], 
				buffer, 
				size);
			get_next_thread(iow)->inbuf.offset += size;

			/* If the buffer is now full Trigger the thread to start compressing this block,
			 * and move onto the next block.
			 */
			if (get_next_thread(iow)->inbuf.offset >= sizeof(get_next_thread(iow)->inbuf.buffer)
			  ||get_next_thread(iow)->inbuf.offset >= MAX_BLOCK_SIZE) {
			  	assert(get_next_thread(iow)->state == EMPTY);
				get_next_thread(iow)->state = WAITING;
				pthread_cond_signal(&get_next_thread(iow)->in_ready);

				pthread_mutex_unlock(&get_next_thread(iow)->mutex);

				DATA(iow)->next_thread = 
						(DATA(iow)->next_thread+1) % DATA(iow)->threads;
			}
			else 
				pthread_mutex_unlock(&get_next_thread(iow)->mutex);

			/* Update the lengths */
			buffer += size;
			len -= size;
		}
	}
	return len;
}

static void shutdown_thread(iow_t *iow, struct lzothread_t *thread)
{
	pthread_mutex_lock(&thread->mutex);

	/* If this buffer is empty it shouldn't have any data in it, we should have taken
         * care of that before.
	 */
	/* thread->state == EMPTY implies thread->inbuf.offset == 0 */
	assert(!(thread->state == EMPTY) || thread->inbuf.offset == 0);

	while (thread->state == WAITING) {
		pthread_cond_wait(
			&thread->out_ready,
			&thread->mutex);
	}
	if (thread->state == FULL) {
		wandio_wwrite(DATA(iow)->child,
				thread->outbuf.buffer,
				thread->outbuf.offset);
		thread->state = EMPTY;
		thread->inbuf.offset = 0;
	}
	/* Now the thread should be empty, so ask it to shut down */
	assert(thread->state == EMPTY && thread->inbuf.offset == 0);
	thread->closing = true;
	pthread_cond_signal(&thread->in_ready);
	pthread_mutex_unlock(&thread->mutex);
	/* And wait for it to die */
	pthread_join(thread->thread,NULL);
}

static void lzo_wclose(iow_t *iow)
{
	const uint32_t zero = 0;
	int i;

	/* Flush the last buffer */
	pthread_mutex_lock(&get_next_thread(iow)->mutex);
	if (get_next_thread(iow)->state == EMPTY && get_next_thread(iow)->inbuf.offset != 0) {
		get_next_thread(iow)->state = WAITING;
		pthread_cond_signal(&get_next_thread(iow)->in_ready);
	}
	pthread_mutex_unlock(&get_next_thread(iow)->mutex);

	DATA(iow)->next_thread = 
			(DATA(iow)->next_thread+1) % DATA(iow)->threads;

	/* Right, now we have to shutdown all our threads -- in order */
	for(i=DATA(iow)->next_thread; i<DATA(iow)->threads; ++i) {
		shutdown_thread(iow,&DATA(iow)->thread[i]);
	}
	for(i=0; i<DATA(iow)->next_thread; ++i) {
		shutdown_thread(iow,&DATA(iow)->thread[i]);
	}

	/* Write out an end of file marker */
	wandio_wwrite(DATA(iow)->child,
		&zero,
		sizeof(zero));

	/* And clean everything up */
	wandio_wdestroy(DATA(iow)->child);
	free(DATA(iow)->thread);
	free(iow->data);
	free(iow);
}

iow_source_t lzo_wsource = {
	"lzo",
	lzo_wwrite,
	lzo_wclose
};

