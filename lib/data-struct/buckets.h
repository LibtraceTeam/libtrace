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
