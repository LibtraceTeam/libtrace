#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>

#include "simple_circular_buffer.h"

DLLEXPORT int libtrace_scb_init(libtrace_scb_t *buf, uint32_t size,
                uint16_t id) {

        char anonname[32];

        if (size % getpagesize() != 0) {
                size = ((size / getpagesize()) + 1) * getpagesize();
        }

        /* This SCB has not been cleaned up properly, do so now to
         * try and avoid leaking fds and/or mmapped memory.
         */
        if (buf->fd != -1 || buf->address != NULL) {
                libtrace_scb_destroy(buf);
        }

        snprintf(anonname, 32, "lt_scb_%u_%u", getpid(), id);
#ifdef HAVE_MEMFD_CREATE
        buf->fd = syscall(__NR_memfd_create, anonname, 0);
#else
        buf->fd = shm_open(anonname, O_RDWR | O_CREAT, 0600);
#endif
        if (ftruncate(buf->fd, size) < 0) {
                perror("ftruncate in libtrace_scb_init");
                close(buf->fd);
                buf->fd = -1;
                buf->address = NULL;
        } else {
                buf->address = mmap(NULL, 2 * size, PROT_NONE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                mmap(buf->address, size, PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_FIXED, buf->fd, 0);
                mmap(buf->address + size, size, PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_FIXED, buf->fd, 0);
        }
        buf->read_offset = 0;
        buf->write_offset = 0;
        buf->count_bytes = size;
        buf->shm_file = strdup(anonname);

        if (buf->address) {
                return 0;
        }
        return -1;
}

DLLEXPORT void libtrace_scb_destroy(libtrace_scb_t *buf) {
        /* TODO shm_unlink the file name if we used shm_open? */

        if (buf->address) {
                munmap(buf->address, buf->count_bytes * 2);
                buf->address = NULL;
        }
        if (buf->fd != -1) {
                close(buf->fd);
                buf->fd = -1;
        }
        if (buf->shm_file) {
                shm_unlink(buf->shm_file);
                free(buf->shm_file);
        }

}

DLLEXPORT int libtrace_scb_recv_sock(libtrace_scb_t *buf, int sock,
                int recvflags) {
        int space = buf->count_bytes - (buf->write_offset - buf->read_offset);
        int ret;

        if (buf->address == NULL) {
                return -1;
        }

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

        if (buf->address == NULL) {
                return NULL;
        }
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
