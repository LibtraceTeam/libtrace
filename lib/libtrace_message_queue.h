#include <pthread.h>
#include <assert.h>
#include <limits.h>

#ifndef LIBTRACE_MESSAGE_QUEUE
#define LIBTRACE_MESSAGE_QUEUE

#define LIBTRACE_MQ_FAILED INT_MIN
typedef struct libtrace_thread_t libtrace_thread_t;
typedef struct libtrace_message_queue_t {
		int pipefd[2];
		volatile int message_count;
		size_t message_len;
		pthread_spinlock_t spin;
} libtrace_message_queue_t;

typedef struct libtrace_message_t {
	int code;
	void *additional;
	libtrace_thread_t *sender;
} libtrace_message_t;

inline void libtrace_message_queue_init(libtrace_message_queue_t *mq, size_t message_len);
inline int libtrace_message_queue_put(libtrace_message_queue_t *mq, const void *message);
inline int libtrace_message_queue_count(const libtrace_message_queue_t *mq);
inline int libtrace_message_queue_get(libtrace_message_queue_t *mq, void *message);
inline int libtrace_message_queue_try_get(libtrace_message_queue_t *mq, void *message);
inline void libtrace_message_queue_destroy(libtrace_message_queue_t *mq);
inline int libtrace_message_queue_get_fd(libtrace_message_queue_t *mq);

enum libtrace_messages {
	MESSAGE_STARTED,
	MESSAGE_PAUSE,
	MESSAGE_STOP,
	MESSAGE_STOPPED,
	MESSAGE_FIRST_PACKET,
	MESSAGE_MAPPER_ENDED,
	MESSAGE_MAPPER_RESUMED,
	MESSAGE_MAPPER_PAUSED,
	MESSAGE_MAPPER_EOF,
	MESSAGE_POST_REDUCE,
	MESSAGE_POST_RANGE,
	MESSAGE_USER
};
#endif
