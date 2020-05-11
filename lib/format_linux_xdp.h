#ifndef FORMAT_LINUX_XDP
#define FORMAT_LINUX_XDP

typedef struct libtrace_xdp_meta {
    uint64_t timestamp;
    uint32_t packet_len;
} PACKED libtrace_xdp_meta_t;

typedef struct libtrace_xdp {
    /* BPF filter */
} libtrace_xdp_t;

#endif
