/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton,
 * New Zealand.
 *
 * Authors: Daniel Lawson
 *          Perry Lorier
 *          Shane Alcock
 *          Alistair King
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * This code has been adapted from kurl:
 * https://github.com/attractivechaos/klib
 * (released under the MIT/X11 license)
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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>
#include <assert.h>

/* Libtrace IO module implementing an HTTP reader (using libcurl)
 */

/* we lock calls to curl_global_init because it does non-thread-safe things, but
   this is still a little sketchy because apparently it calls a bunch of
   non-curl functions that are also not thread safe
   (http://curl.haxx.se/mail/lib-2008-02/0126.html) and so users of libwandio
   could be calling those when we call curl_global_init :( */
static pthread_mutex_t cg_lock = PTHREAD_MUTEX_INITIALIZER;
static int cg_init_cnt = 0;

struct http_t {
         /* cURL multi handler */
        CURLM *multi;

        /* cURL easy handle */
        CURL *curl;

        /* buffer */
        uint8_t *buf;

        /* offset of the first byte in the buffer; the actual file offset equals
           off0 + p_buf */
        off_t off0;

        /* max buffer size; CURL_MAX_WRITE_SIZE*2 is recommended */
	int m_buf;

        /* length of the buffer; l_buf == 0 iff the input read entirely;
           l_buf <= m_buf */
	int l_buf;

        /* file position in the buffer; p_buf <= l_buf */
	int p_buf;

        /* true if we can read nothing from the file; buffer may not be empty
           even if done_reading is set */
	int done_reading;
};

extern io_source_t http_source;

#define DATA(io) ((struct http_t *)((io)->data))

#define HTTP_DEF_BUFLEN   0x8000
#define HTTP_MAX_SKIP     (HTTP_DEF_BUFLEN<<1)

io_t *http_open(const char *filename);
static off_t http_read(io_t *io, void *buffer, off_t len);
static off_t http_tell(io_t *io);
static off_t http_seek(io_t *io, off_t offset, int whence);
static void http_close(io_t *io);

/* callback required by cURL */
static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *data)
{
	io_t *io = (io_t*)data;
	ssize_t nbytes = size * nmemb;
	if (nbytes + DATA(io)->l_buf > DATA(io)->m_buf)
		return CURL_WRITEFUNC_PAUSE;
	memcpy(DATA(io)->buf + DATA(io)->l_buf, ptr, nbytes);
	DATA(io)->l_buf += nbytes;
	return nbytes;
}

static int prepare(io_t *io)
{
        int rc;
        rc = curl_multi_remove_handle(DATA(io)->multi, DATA(io)->curl);
        rc = curl_easy_setopt(DATA(io)->curl,
                              CURLOPT_RESUME_FROM,
                              DATA(io)->off0);
        rc = curl_multi_add_handle(DATA(io)->multi, DATA(io)->curl);
	DATA(io)->p_buf = DATA(io)->l_buf = 0; // empty the buffer
	return rc;
}

/* fill the buffer */
static int fill_buffer(io_t *io)
{
        /* buffer is always used up when fill_buffer() is called */
	assert(DATA(io)->p_buf == DATA(io)->l_buf);
	DATA(io)->off0 += DATA(io)->l_buf;
	DATA(io)->p_buf = DATA(io)->l_buf = 0;
	if (DATA(io)->done_reading) return 0;

        int n_running, rc;
        fd_set fdr, fdw, fde;
        do {
                int maxfd = -1;
                long curl_to = -1;
                struct timeval to;
                // the following is adaped from docs/examples/fopen.c
                to.tv_sec = 10, to.tv_usec = 0; // 10 seconds
                curl_multi_timeout(DATA(io)->multi, &curl_to);
                if (curl_to >= 0) {
                        to.tv_sec = curl_to / 1000;
                        if (to.tv_sec > 1) to.tv_sec = 1;
                        else to.tv_usec = (curl_to % 1000) * 1000;
                }
                FD_ZERO(&fdr); FD_ZERO(&fdw); FD_ZERO(&fde);

                /* FIXME: check return code */
                curl_multi_fdset(DATA(io)->multi, &fdr, &fdw, &fde, &maxfd);
                if (maxfd >= 0 &&
                    (rc = select(maxfd+1, &fdr, &fdw, &fde, &to)) < 0) break;

                /* check curl_multi_fdset.3 about why we wait for 100ms here */
                if (maxfd < 0) {
                        struct timespec req, rem;
                        req.tv_sec = 0; req.tv_nsec = 100000000; // 100ms
                        nanosleep(&req, &rem);
                }
                curl_easy_pause(DATA(io)->curl, CURLPAUSE_CONT);
                /* FIXME: check return code */
                rc = curl_multi_perform(DATA(io)->multi, &n_running);
        } while (n_running &&
                 DATA(io)->l_buf < DATA(io)->m_buf - CURL_MAX_WRITE_SIZE);

        if (DATA(io)->l_buf < DATA(io)->m_buf - CURL_MAX_WRITE_SIZE)
                DATA(io)->done_reading = 1;

	return DATA(io)->l_buf;
}

io_t *http_open(const char *filename)
{
	io_t *io = malloc(sizeof(io_t));
        if (!io) return NULL;
	io->data = malloc(sizeof(struct http_t));
        if (!io->data) {
                free(io);
                return NULL;
        }
        memset(io->data, 0, sizeof(struct http_t));

        io->source = &http_source;

        /* set up global curl structures (see note above) */
        pthread_mutex_lock(&cg_lock);
        if (!cg_init_cnt) {
                curl_global_init(CURL_GLOBAL_DEFAULT);
        }
        cg_init_cnt++;
        pthread_mutex_unlock(&cg_lock);

        DATA(io)->multi = curl_multi_init();
        DATA(io)->curl  = curl_easy_init();
        curl_easy_setopt(DATA(io)->curl, CURLOPT_URL, filename);
        curl_easy_setopt(DATA(io)->curl, CURLOPT_WRITEDATA, io);
        curl_easy_setopt(DATA(io)->curl, CURLOPT_VERBOSE, 0L);
        curl_easy_setopt(DATA(io)->curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(DATA(io)->curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(DATA(io)->curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(DATA(io)->curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(DATA(io)->curl, CURLOPT_FOLLOWLOCATION, 1L);

        /* for remote files, the buffer set to 2*CURL_MAX_WRITE_SIZE */
        DATA(io)->m_buf = CURL_MAX_WRITE_SIZE * 2;
	DATA(io)->buf = (uint8_t*)calloc(DATA(io)->m_buf, 1);

	if (prepare(io) < 0 || fill_buffer(io) <= 0) {
		http_close(io);
		return NULL;
	}

	return io;
}

static off_t http_read(io_t *io, void *buffer, off_t len)
{
	ssize_t rest = len;
	if (DATA(io)->l_buf == 0) return 0; // end-of-file
	while (rest) {
		if (DATA(io)->l_buf - DATA(io)->p_buf >= rest) {
			if (buffer) {
                                memcpy((uint8_t*)buffer + (len - rest),
                                       DATA(io)->buf + DATA(io)->p_buf,
                                       rest);
                        }
			DATA(io)->p_buf += rest;
			rest = 0;
		} else {
			int ret;
			if (buffer && DATA(io)->l_buf > DATA(io)->p_buf) {
				memcpy((uint8_t*)buffer + (len - rest),
                                       DATA(io)->buf + DATA(io)->p_buf,
                                       DATA(io)->l_buf - DATA(io)->p_buf);
                        }
			rest -= DATA(io)->l_buf - DATA(io)->p_buf;
			DATA(io)->p_buf = DATA(io)->l_buf;
			ret = fill_buffer(io);
			if (ret <= 0) break;
		}
	}
	return len - rest;
}

static off_t http_tell(io_t *io)
{
        if (DATA(io) == 0) return -1;
	return DATA(io)->off0 + DATA(io)->p_buf;
}

static off_t http_seek(io_t *io, off_t offset, int whence)
{
        off_t new_off = -1, cur_off;
	int failed = 0, seek_end = 0;
	assert(io);
	cur_off = DATA(io)->off0 + DATA(io)->p_buf;
	if (whence == SEEK_SET) new_off = offset;
	else if (whence == SEEK_CUR) new_off += cur_off + offset;
        /* not supported whence */
	else {
		return -1;
	}
        /* negtive absolute offset */
	if (new_off < 0) {
		return -1;
	}
	if (!seek_end &&
            new_off >= cur_off &&
            new_off - cur_off + DATA(io)->p_buf < DATA(io)->l_buf) {
		DATA(io)->p_buf += new_off - cur_off;
		return DATA(io)->off0 + DATA(io)->p_buf;
	}
        /* if jump is large, do actual seek */
	if (seek_end || new_off < cur_off ||
            new_off - cur_off > HTTP_MAX_SKIP) {
		DATA(io)->off0 = new_off;
		DATA(io)->done_reading = 0;
		if (prepare(io) < 0 || fill_buffer(io) <= 0)
                        failed = 1;
	} else { /* if jump is small, read through */
		off_t r;
		r = http_read(io, 0, new_off - cur_off);
		if (r + cur_off != new_off) failed = 1; // out of range
	}
	if (failed) {
                DATA(io)->l_buf = DATA(io)->p_buf = 0;
                new_off = -1;
        }
	return new_off;
}

static void http_close(io_t *io)
{
        curl_multi_remove_handle(DATA(io)->multi, DATA(io)->curl);
        curl_easy_cleanup(DATA(io)->curl);
        curl_multi_cleanup(DATA(io)->multi);

        /* clean up global curl structures (see note above) */
        pthread_mutex_lock(&cg_lock);
        assert(cg_init_cnt);
        cg_init_cnt--;
        if (!cg_init_cnt)
                curl_global_cleanup();
        pthread_mutex_unlock(&cg_lock);

	free(DATA(io)->buf);
	free(io->data);
	free(io);
}

io_source_t http_source = {
	"http",
	http_read,
	NULL,
	http_tell,
	http_seek,
	http_close
};
