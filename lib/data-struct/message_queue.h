#include <pthread.h>
#include <limits.h>

#ifndef LIBTRACE_MESSAGE_QUEUE
#define LIBTRACE_MESSAGE_QUEUE

#define LIBTRACE_MQ_FAILED INT_MIN
typedef struct libtrace_message_queue_t {
	int pipefd[2];
	volatile int message_count;
	size_t message_len;
	pthread_spinlock_t spin;
} libtrace_message_queue_t;

void libtrace_message_queue_init(libtrace_message_queue_t *mq, size_t message_len);
int libtrace_message_queue_put(libtrace_message_queue_t *mq, const void *message);
int libtrace_message_queue_count(const libtrace_message_queue_t *mq);
int libtrace_message_queue_get(libtrace_message_queue_t *mq, void *message);
int libtrace_message_queue_try_get(libtrace_message_queue_t *mq, void *message);
void libtrace_message_queue_destroy(libtrace_message_queue_t *mq);
int libtrace_message_queue_get_fd(libtrace_message_queue_t *mq);

#endif
