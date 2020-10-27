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

#include <stdlib.h>
#include <string.h>
#include "buckets.h"

#define MAX_OUTSTANDING (200000)

static void clear_bucket_node(void *node) {

        libtrace_bucket_node_t *bnode = (libtrace_bucket_node_t *)node;
        if (bnode->buffer)
                free(bnode->buffer);
        if (bnode->released)
                free(bnode->released);
}

DLLEXPORT libtrace_bucket_t *libtrace_bucket_init() {

        libtrace_bucket_t *b = (libtrace_bucket_t *) malloc(sizeof(libtrace_bucket_t));

        b->packets = (libtrace_bucket_node_t **)calloc(MAX_OUTSTANDING + 1,
                        sizeof(libtrace_bucket_node_t *));

        b->nextid = 199999;
        b->node = NULL;
        b->nodelist = libtrace_list_init(sizeof(libtrace_bucket_node_t));

        pthread_mutex_init(&b->lock, NULL);
        pthread_cond_init(&b->cond, NULL);

        return b;

}

DLLEXPORT void libtrace_bucket_destroy(libtrace_bucket_t *b) {

        pthread_mutex_lock(&b->lock);
        if (b->node) {
                clear_bucket_node(b->node);
                free(b->node);
        }

        libtrace_list_deinit(b->nodelist);
        free(b->packets);
        pthread_mutex_unlock(&b->lock);
        pthread_mutex_destroy(&b->lock);
        pthread_cond_destroy(&b->cond);
        free(b);
}

DLLEXPORT void libtrace_create_new_bucket(libtrace_bucket_t *b, void *buffer) {

        libtrace_bucket_node_t tmp;
        libtrace_bucket_node_t *bnode = (libtrace_bucket_node_t *)malloc(
                        sizeof(libtrace_bucket_node_t));

        /* If the last node was never used, i.e. all packets within that node
         * buffer were filtered, we need to make sure we free the buffer
         * before we lose track of it.
         */
        pthread_mutex_lock(&b->lock);
        if (b->node && b->node->startindex == 0) {
                clear_bucket_node(b->node);
                libtrace_list_pop_back(b->nodelist, &tmp);
                free(b->node);
        }
        pthread_mutex_unlock(&b->lock);


        bnode->startindex = 0;
        bnode->buffer = buffer;
        bnode->activemembers = 0;
        bnode->slots = 10;
        bnode->released = (uint8_t *)malloc(bnode->slots * sizeof(uint8_t));

        memset(bnode->released, 0, bnode->slots * sizeof(uint8_t));

        pthread_mutex_lock(&b->lock);
        b->node = bnode;

        libtrace_list_push_back(b->nodelist, &bnode);
        pthread_mutex_unlock(&b->lock);

}

DLLEXPORT uint64_t libtrace_push_into_bucket(libtrace_bucket_t *b) {

        uint16_t s;
        uint64_t ret;

        pthread_mutex_lock(&b->lock);
        if (b->node == NULL) {
                pthread_mutex_unlock(&b->lock);
                return 0;
        }

        if (b->nextid >= MAX_OUTSTANDING)
                b->nextid = 1;
        if (b->node->startindex == 0) {

                while (b->packets[b->nextid] != NULL) {
                        /* No more packet slots available! */
                        pthread_cond_wait(&b->cond, &b->lock);
                        pthread_mutex_unlock(&b->lock);

                }
                b->node->startindex = b->nextid;
                b->node->activemembers = 1;
                b->node->released[0] = 1;

                b->packets[b->nextid] = b->node;
                b->nextid ++;
                ret = b->node->startindex;

                pthread_mutex_unlock(&b->lock);
                return ret;
        }

        if (b->nextid < b->node->startindex) {
                s = (MAX_OUTSTANDING - b->node->startindex) + b->nextid - 1;
        } else {
                s = b->nextid - b->node->startindex;
        }

        if (s >= b->node->slots) {
                b->node->slots += 10;
                b->node->released = (uint8_t *)realloc(b->node->released,
                                b->node->slots * sizeof(uint8_t));

                memset((b->node->released +
                                (b->node->slots - 10) * sizeof(uint8_t)), 0,
                                (10 * sizeof(uint8_t)));
        }

        while (b->packets[b->nextid] != NULL) {
                /* No more packet slots available! */
                pthread_cond_wait(&b->cond, &b->lock);
                pthread_mutex_unlock(&b->lock);

        }
        b->packets[b->nextid] = b->node;
        b->node->activemembers ++;
        b->node->released[s] = 1;
        b->nextid ++;
        ret = b->nextid - 1;
        pthread_mutex_unlock(&b->lock);

        return ret;

}

DLLEXPORT void libtrace_release_bucket_id(libtrace_bucket_t *b, uint64_t id) {

        uint16_t s, i;
        libtrace_bucket_node_t *bnode, *front;
        libtrace_list_node_t *lnode;
        libtrace_bucket_node_t tmp;

	if (id == 0) {
		fprintf(stderr, "bucket ID cannot be 0 in libtrace_release_bucket_id()\n");
		return;
	}

        pthread_mutex_lock(&b->lock);
        bnode = b->packets[id];
	if (!bnode) {
		fprintf(stderr, "bucket ID %lu is NULL in libtrace_release_bucket_id()\n", id);
		return;
	}


        /* Find the right slot */
        if (id < bnode->startindex) {
                s = (MAX_OUTSTANDING - bnode->startindex) + id - 1;
        } else {
                s = id - bnode->startindex;
        }
	if (s >= bnode->slots) {
		fprintf(stderr, "Error in libtrace_release_bucket_id()\n");
		return;
	}
	if (bnode->released[s] == 0) {
		fprintf(stderr, "Error in libtrace_release_bucket_id()\n");
		return;
	}


        if (bnode->released[s] == 1) {
                uint64_t previd = b->nextid - 1;
                if (b->nextid == 1)
                        previd = MAX_OUTSTANDING - 1;

                if (bnode == b->node && id == previd) {
                        b->packets[id] = NULL;
                        b->nextid = previd;
                        bnode->released[s] = 0;
                        if (id == bnode->startindex)
                                bnode->startindex = 0;
                } else {
                        bnode->released[s] = 2;
                }
                bnode->activemembers -= 1;
        }

        while (libtrace_list_get_size(b->nodelist) > 1) {
                lnode = libtrace_list_get_index(b->nodelist, 0);

                front = *(libtrace_bucket_node_t **)lnode->data;

                if (front->activemembers > 0) {
                        break;
                }
                if (front == b->node)
                        break;

		if (!lnode->next) {
			fprintf(stderr, "Error in libtrace_release_bucket_id()\n");
			return;
		}
                for (i = 0; i < front->slots; i++) {
                        if (front->released[i] == 2) {
                                int index = i + front->startindex;
                                if (index >= MAX_OUTSTANDING) {
                                        index -= (MAX_OUTSTANDING - 1);
                                }
                                b->packets[index] = NULL;
                        }
                }

                clear_bucket_node(front);
                libtrace_list_pop_front(b->nodelist, &tmp);
                free(front);
                pthread_cond_signal(&b->cond);

        }
        pthread_mutex_unlock(&b->lock);

}
