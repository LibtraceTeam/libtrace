// $Id$
#ifndef _FIFO_H_
#define _FIFO_H_

struct fifo_t;

typedef struct fifo_state {
        long long int in;
        long long int out;
        long long int ack;
        long long int length;
        long long int used;
} fifo_state_t;


struct fifo_t *create_fifo(size_t size);
void destroy_fifo(struct fifo_t *fifo);


void fifo_stat(struct fifo_t *fifo, char *desc, int delta);
char *fifo_stat_str(struct fifo_t *fifo, char *desc, int delta);
void fifo_stat_int(struct fifo_t *fifo, fifo_state_t *state);

size_t fifo_out_available(struct fifo_t *fifo);
size_t fifo_ack_available(struct fifo_t *fifo);
size_t fifo_free(struct fifo_t *fifo);
size_t fifo_length(struct fifo_t *fifo);

int fifo_write(struct fifo_t *fifo, void *buffer, size_t len);

int fifo_out_read(struct fifo_t *fifo, void *buffer, size_t len);
int fifo_ack_read(struct fifo_t *fifo, void *buffer, size_t len);
int fifo_out_update(struct fifo_t *fifo, size_t len);
int fifo_ack_update(struct fifo_t *fifo, size_t len);

void fifo_out_reset(struct fifo_t *fifo);

void fifo_flush(struct fifo_t *fifo);



#endif // _FIFO_H_
