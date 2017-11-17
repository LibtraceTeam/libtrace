#ifndef LIBTRACE_SCB_H_
#define LIBTRACE_SCB_H_

typedef struct libtracescb {
        uint8_t *address;
        uint32_t count_bytes;
        uint32_t write_offset;
        uint32_t read_offset;
        int fd;
} libtrace_scb_t;


void libtrace_scb_init(libtrace_scb_t *buf, uint32_t size, uint16_t id);
void libtrace_scb_destroy(libtrace_scb_t *buf);
int libtrace_scb_recv_sock(libtrace_scb_t *buf, int sock, int recvflags);
uint8_t *libtrace_scb_get_read(libtrace_scb_t *buf, uint32_t *available);
void libtrace_scb_advance_read(libtrace_scb_t *buf, uint32_t forward);

#endif
