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
#ifndef LIBTRACE_BUCKET_H_
#define LIBTRACE_BUCKET_H_

#include <pthread.h>
#include "linked_list.h"

typedef struct bucket_node {
        uint64_t startindex;
        uint8_t *released;
        uint16_t activemembers;
        uint16_t slots;
        void *buffer;
} libtrace_bucket_node_t;

typedef struct buckets {
        uint64_t nextid;
        libtrace_bucket_node_t *node;
        libtrace_bucket_node_t **packets;
        libtrace_list_t *nodelist;
        pthread_mutex_t lock;
        pthread_cond_t cond;
} libtrace_bucket_t;

libtrace_bucket_t *libtrace_bucket_init(void);
void libtrace_bucket_destroy(libtrace_bucket_t *b);
void libtrace_create_new_bucket(libtrace_bucket_t *b, void *buffer);
uint64_t libtrace_push_into_bucket(libtrace_bucket_t *b);
void libtrace_release_bucket_id(libtrace_bucket_t *b, uint64_t id);

#endif
