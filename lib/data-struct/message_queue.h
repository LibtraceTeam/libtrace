/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */
#include <pthread.h>
#include <limits.h>
#include "libtrace.h"
#include "pthread_spinlock.h"

#ifndef LIBTRACE_MESSAGE_QUEUE
#define LIBTRACE_MESSAGE_QUEUE

#define LIBTRACE_MQ_FAILED INT_MIN
typedef struct libtrace_message_queue_t {
	int pipefd[2];
	volatile int message_count;
	size_t message_len;
	pthread_spinlock_t spin;
} libtrace_message_queue_t;

DLLEXPORT void libtrace_message_queue_init(libtrace_message_queue_t *mq,
        size_t message_len);
DLLEXPORT int libtrace_message_queue_put(libtrace_message_queue_t *mq,
        const void *message);
DLLEXPORT int libtrace_message_queue_count(const libtrace_message_queue_t *mq);
DLLEXPORT int libtrace_message_queue_get(libtrace_message_queue_t *mq,
        void *message);
DLLEXPORT int libtrace_message_queue_try_get(libtrace_message_queue_t *mq,
        void *message);
DLLEXPORT void libtrace_message_queue_destroy(libtrace_message_queue_t *mq);
DLLEXPORT int libtrace_message_queue_get_fd(libtrace_message_queue_t *mq);

#endif
