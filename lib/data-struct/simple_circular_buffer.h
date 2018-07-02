#ifndef LIBTRACE_SCB_H_
#define LIBTRACE_SCB_H_

#include "libtrace.h"

typedef struct libtracescb {
        uint8_t *address;
        uint32_t count_bytes;
        uint32_t write_offset;
        uint32_t read_offset;
        int fd;
} libtrace_scb_t;


DLLEXPORT int libtrace_scb_init(libtrace_scb_t *buf, uint32_t size,
                uint16_t id);
DLLEXPORT void libtrace_scb_destroy(libtrace_scb_t *buf);
DLLEXPORT int libtrace_scb_recv_sock(libtrace_scb_t *buf, int sock,
                int recvflags);
DLLEXPORT uint8_t *libtrace_scb_get_read(libtrace_scb_t *buf,
                uint32_t *available);
DLLEXPORT void libtrace_scb_advance_read(libtrace_scb_t *buf, uint32_t forward);

#endif
