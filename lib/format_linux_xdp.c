#include "config.h"
#include "libtrace.h"
#include "libtrace_int.h"

#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include <bpf/bpf.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <assert.h>

#define FORMAT_DATA ((xdp_format_data_t *)libtrace->format_data)
//#define FORMAT_DATA_OUT ((xdp_format_data_out_t *)libtrace->format_data)

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_config {
    __u32 xdp_flags;
    int ifindex;
    char *ifname;
    char ifname_buf[IF_NAMESIZE];
    char progsec[32];
    bool do_unload;
    __u16 xsk_bind_flags;
};

struct xsk_umem_info {
    struct xsk_ring_cons cq;
    struct xsk_ring_prod fq;
    struct xsk_umem *umem;
    int xsk_if_queue;
    void *buffer;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;
};

struct xsk_per_stream {
    struct xsk_umem_info *umem;
    struct xsk_socket_info *xsk;
    uint64_t prev_pkt_addr;
};

typedef struct xdp_format_data {
    struct xsk_config cfg;
    libtrace_list_t *per_stream;
} xdp_format_data_t;


static int linux_xdp_prepare_packet(libtrace_t *libtrace, libtrace_packet_t *packet,
    void *buffer, libtrace_rt_types_t rt_type, uint32_t flags);
static int linux_xdp_start_stream(libtrace_t *libtrace, struct xsk_per_stream *stream);

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {

    uint64_t frame;
    if (xsk->umem_frame_free == 0) {
        return INVALID_UMEM_FRAME;
    }

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;

    return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame) {
    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}


static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size,
    int interface_queue) {

    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (umem == NULL) {
        return NULL;
    }

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
    if (ret) {
        errno = -ret;
        return NULL;
    }

    umem->buffer = buffer;
    umem->xsk_if_queue = interface_queue;

    return umem;
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_config *cfg,
    struct xsk_umem_info *umem) {

    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    uint32_t idx;
    uint32_t prog_id = 0;
    int i;
    int ret;

    xsk_info = calloc(1, sizeof(*xsk_info));
    if (xsk_info == NULL) {
        return NULL;
    }

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = 0;
    xsk_cfg.xdp_flags = cfg->xdp_flags;
    xsk_cfg.bind_flags = cfg->xsk_bind_flags;

    ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
                             umem->xsk_if_queue, umem->umem,
                             &xsk_info->rx, NULL, &xsk_cfg);
    if (ret) {
        errno = -ret;
        return NULL;
    }

    ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
    if (ret) {
        errno = -ret;
        return NULL;
    }

    /* Initialize umem frame allocation */
    for (i = 0; i < NUM_FRAMES; i++) {
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
    }

    xsk_info->umem_frame_free = NUM_FRAMES;

    /* Stuff the receive path with buffers, we assume we have enough */
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                                 XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                 &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        errno = -ret;
        return NULL;
    }

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++) {
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
            xsk_alloc_umem_frame(xsk_info);
    }

    xsk_ring_prod__submit(&xsk_info->umem->fq,
                          XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;
}

static int linux_xdp_init_input(libtrace_t *libtrace) {

    char *scan = NULL;

    // allocate space for the format data
    libtrace->format_data = (xdp_format_data_t *)calloc(1,
        sizeof(xdp_format_data_t));
    if (libtrace->format_data == NULL) {
        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable "
            "to allocate memory for format data in linux_xdp_init_input()");
        return -1;
    }

    /* setup XDP config */
    FORMAT_DATA->cfg.ifname = (char *)&(FORMAT_DATA->cfg.ifname_buf);
    scan = strchr(libtrace->uridata, ':');
    if (scan == NULL) {
        FORMAT_DATA->cfg.ifname = strdup(libtrace->uridata);
    } else {
        FORMAT_DATA->cfg.ifname = strdup(scan + 1);
    }
    FORMAT_DATA->cfg.ifindex = if_nametoindex(FORMAT_DATA->cfg.ifname);
    if (FORMAT_DATA->cfg.ifindex == -1) {
        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Invalid interface "
            "name.");
        return -1;
    }

    /* setup list to hold the streams */
    FORMAT_DATA->per_stream = libtrace_list_init(sizeof(struct xsk_per_stream));
    if (FORMAT_DATA->per_stream == NULL) {
        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable to create list "
            "for stream data in linux_xdp_init_input()");
        return -1;
    }

    return 0;
}

static int linux_xdp_pstart_input(libtrace_t *libtrace) {

    int i;
    int threads = libtrace->perpkt_thread_count;
    struct xsk_per_stream empty_stream;
    struct xsk_per_stream *stream;

    empty_stream.prev_pkt_addr = 0;

    /* TODO set number of interface queues to the number of threads */

    /* create a stream for each processing thread */
    for (i = 0; i < threads; i++) {
        libtrace_list_push_back(FORMAT_DATA->per_stream, &empty_stream);

        stream = libtrace_list_get_index(FORMAT_DATA->per_stream, i)->data;

        /* TODO setup interface queue here */

        /* start the stream */
        if (linux_xdp_start_stream(libtrace, stream) == -1) {
            trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Failed to start "
                "stream in linux_xdp_pstart_input()");
            return -1;
        }
    }
}

static int linux_xdp_start_input(libtrace_t *libtrace) {

    struct xsk_per_stream empty_stream;
    struct xsk_per_stream *stream;

    empty_stream.prev_pkt_addr = 0;

    /* TODO set number of interface queues to 1 */

    /* insert empty stream into the list */
    libtrace_list_push_back(FORMAT_DATA->per_stream, &empty_stream);

    /* get the stream from the list */
    stream = libtrace_list_get_index(FORMAT_DATA->per_stream, 0)->data;

    /* start the stream */
    return linux_xdp_start_stream(libtrace, stream);
}

static int linux_xdp_start_stream(libtrace_t *libtrace, struct xsk_per_stream *stream) {

    uint64_t pkt_buf_size;
    void *pkt_buf;

    /* Allocate memory for NUM_FRAMES of default XDP frame size */
    pkt_buf_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&pkt_buf, getpagesize(), pkt_buf_size)) {
        fprintf(stderr, "err45\n");
        return -1;
    }

    /* setup umem */
    stream->umem = configure_xsk_umem(pkt_buf, pkt_buf_size, 0);
    if (stream->umem == NULL) {
        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable "
            "to allocate memory for format data in linux_xdp_init_input()");
        return -1;
    }

    /* configure socket */
    stream->xsk = xsk_configure_socket(&FORMAT_DATA->cfg, stream->umem);
    if (stream->xsk == NULL) {
        trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable "
            "to allocate memory for format data in linux_xdp_init_input()");
        return -1;
    }

    return 0;
}

static int linux_xdp_read_stream(libtrace_t *libtrace,
                                 libtrace_packet_t *packet,
                                 struct xsk_per_stream *stream,
                                 libtrace_message_queue_t *queue UNUSED) {

    unsigned int rcvd;
    uint32_t idx_rx = 0;
    uint32_t pkt_len;
    uint64_t pkt_addr;
    uint8_t *pkt_buffer;
    uint32_t flags = 0;

    if (libtrace->format_data == NULL) {
        trace_set_err(libtrace, TRACE_ERR_BAD_FORMAT, "Trace format data missing, "
            "call trace_create() before calling trace_read_packet()");
        return -1;
    }

    /* free the previously read packet */
    if (stream->prev_pkt_addr != 0) {
        xsk_free_umem_frame(stream->xsk, stream->prev_pkt_addr);
        xsk_ring_cons__release(&stream->xsk->rx, 1);
    }

    /* try get a single packet */
readagain:
    rcvd = xsk_ring_cons__peek(&stream->xsk->rx, 1, &idx_rx);
    if (rcvd < 1) {
        usleep(200);
        goto readagain;
    }

    /* got a packet. Get the address and length from the rx descriptor */
    pkt_addr = xsk_ring_cons__rx_desc(&stream->xsk->rx, idx_rx)->addr;
    pkt_len = xsk_ring_cons__rx_desc(&stream->xsk->rx, idx_rx++)->len;
    /* get pointer to its contents */
    pkt_buffer = xsk_umem__get_data(stream->xsk->umem->buffer, pkt_addr);

    /* store pkt address to free next call */
    stream->prev_pkt_addr = pkt_addr;

    if (linux_xdp_prepare_packet(libtrace, packet, pkt_buffer,
        TRACE_RT_DATA_XDP, flags)) {

        return -1;
    }

    return pkt_len;
}

static int linux_xdp_read_packet(libtrace_t *libtrace, libtrace_packet_t *packet) {

    struct xsk_per_stream *stream;
    libtrace_list_node_t *node;

    node = libtrace_list_get_index(FORMAT_DATA->per_stream, 0);
    if (node == NULL) {
        fprintf(stderr, "Unable to get stream\n");
        return -1;
    }

    stream = (struct xsk_per_stream *)node->data;

    return linux_xdp_read_stream(libtrace, packet, stream, NULL);

}

static int linux_xdp_prepare_packet(libtrace_t *libtrace UNUSED, libtrace_packet_t *packet,
    void *buffer, libtrace_rt_types_t rt_type, uint32_t flags UNUSED) {

    packet->type = rt_type;
    packet->buffer = buffer;
    packet->header = buffer;
    packet->payload = buffer;

    return 0;
}

static int linux_xdp_fin_input(libtrace_t *libtrace) {

    size_t i;
    struct xsk_per_stream *stream;

    if (FORMAT_DATA != NULL) {
        for (i = 0; i < libtrace_list_get_size(FORMAT_DATA->per_stream); i++) {
            stream = libtrace_list_get_index(FORMAT_DATA->per_stream, i)->data;

            xsk_socket__delete(stream->xsk->xsk);
            xsk_umem__delete(stream->umem->umem);
        }

        /* destroy per stream list */
        libtrace_list_deinit(FORMAT_DATA->per_stream);

        free(FORMAT_DATA->cfg.ifname);
        free(FORMAT_DATA);
    }

    return 0;
}










static int linux_xdp_link_attach(int ifindex, uint32_t flags, int prog_fd) {

    bpf_set_link_xdp_fd(ifindex, prog_fd, flags);

    return 0;
}

static struct bpf_object *linux_xdp_load_bpf_object_file(const char *filename,
    int ifindex) {

    int prog_fd = -1;
    struct bpf_object *obj;
    int err;

    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .ifindex = ifindex,
    };
    prog_load_attr.file = filename;

    err = bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd);
    if (err) {
        fprintf(stderr, "err loading BPF-OBJ\n");
        return NULL;
    }

    return obj;
}

static struct bpf_object *linux_xdp_load_program(libtrace_t *libtrace) {

    struct bpf_program *bpf_prog;
    struct bpf_object *bpf_obj;
    int offload_index = 0;
    int prog_fd;
    int err;

    /* load BPF object file */
    bpf_obj = linux_xdp_load_bpf_object_file(FORMAT_DATA->cfg.ifname,
        offload_index);
    if (!bpf_obj) {
        fprintf(stderr, "errrrr\n");
        return NULL;
    }

    /* get the first bpf program in the BPF file */
    bpf_prog = bpf_program__next(NULL, bpf_obj);
    if (!bpf_prog) {
        fprintf(stderr, "eerrrrr\n");
        return NULL;
    }

    /* get the file descriptor for the loaded BPF program */
    prog_fd = bpf_program__fd(bpf_prog);

    err = linux_xdp_link_attach(FORMAT_DATA->cfg.ifindex,
        FORMAT_DATA->cfg.xdp_flags, prog_fd);
    if (err) {
        fprintf(stderr, "errrr\n");
        return NULL;
    }

    return bpf_obj;
}


static struct libtrace_format_t xdp = {
        "xdp",
        "$Id$",
        TRACE_FORMAT_XDP,
        NULL,                           /* probe filename */
        NULL,                           /* probe magic */
        linux_xdp_init_input,            /* init_input */
        NULL,			        /* config_input */
        linux_xdp_start_input,           /* start_input */
        NULL,           /* pause */
        NULL,           /* init_output */
        NULL,                           /* config_output */
        NULL,          /* start_output */
        linux_xdp_fin_input,             /* fin_input */
        NULL,            /* fin_output */
        linux_xdp_read_packet,           /* read_packet */
        linux_xdp_prepare_packet,        /* prepare_packet */
        NULL,                           /* fin_packet */
        NULL,          /* write_packet */
        NULL,                           /* flush_output */
        NULL,         /* get_link_type */
        NULL,                           /* get_direction */
        NULL,                           /* set_direction */
        NULL,			        /* get_erf_timestamp */
        NULL,           /* get_timeval */
        NULL,                           /* get_timespec */
        NULL,                           /* get_seconds */
	NULL,				/* get_meta_section */
        NULL,                           /* seek_erf */
        NULL,                           /* seek_timeval */
        NULL,                           /* seek_seconds */
        NULL,    /* get_capture_length */
        NULL,       /* get_wire_length */
        NULL,    /* get_framing_length */
        NULL,                           /* set_capture_length */
        NULL,                           /* get_received_packets */
	NULL,                           /* get_filtered_packets */
        NULL,                           /* get_dropped_packets */
        NULL,                           /* get_statistics */
        NULL,                           /* get_fd */
        NULL,				/* trace_event */
        NULL,                           /* help */
        NULL,                           /* next pointer */
        NON_PARALLEL(true)
};

void linux_xdp_constructor(void) {
    register_format(&xdp);
}
