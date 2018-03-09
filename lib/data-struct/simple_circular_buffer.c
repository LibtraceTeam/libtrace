#define _GNU_SOURCE

#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include "simple_circular_buffer.h"

DLLEXPORT void libtrace_scb_init(libtrace_scb_t *buf, uint32_t size,
                uint16_t id) {

        char anonname[32];

        if (size % getpagesize() != 0) {
                size = ((size / getpagesize()) + 1) * getpagesize();
        }

        snprintf(anonname, 32, "lt_scb_%u", id);
        buf->fd = syscall(__NR_memfd_create, anonname, 0);
        ftruncate(buf->fd, size);

        buf->address = mmap(NULL, 2 * size, PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        mmap(buf->address, size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_FIXED, buf->fd, 0);
        mmap(buf->address + size, size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_FIXED, buf->fd, 0);
        buf->read_offset = 0;
        buf->write_offset = 0;
        buf->count_bytes = size;
}

DLLEXPORT void libtrace_scb_destroy(libtrace_scb_t *buf) {
        munmap(buf->address, buf->count_bytes * 2);
}

DLLEXPORT int libtrace_scb_recv_sock(libtrace_scb_t *buf, int sock,
                int recvflags) {
        int space = buf->count_bytes - (buf->write_offset - buf->read_offset);
        int ret;

        if (space == 0) {
                return buf->count_bytes;
        }

        ret = recv(sock, buf->address + buf->write_offset, space, recvflags);
        if (ret < 0) {
                return ret;
        }
        buf->write_offset += ret;
        return (buf->write_offset - buf->read_offset);
}

DLLEXPORT uint8_t *libtrace_scb_get_read(libtrace_scb_t *buf,
                uint32_t *available) {

        *available = buf->write_offset - buf->read_offset;
        return buf->address + buf->read_offset;
}

DLLEXPORT void libtrace_scb_advance_read(libtrace_scb_t *buf,
                uint32_t forward) {

        buf->read_offset += forward;
        if (buf->read_offset >= buf->count_bytes) {
                buf->read_offset -= buf->count_bytes;
                buf->write_offset -= buf->count_bytes;
        }
}
