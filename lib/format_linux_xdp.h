#ifndef FORMAT_LINUX_XDP
#define FORMAT_LINUX_XDP

/* Exit return codes */
#define EXIT_OK              0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL            1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION     2
#define EXIT_FAIL_XDP       30
#define EXIT_FAIL_BPF       40

static const char *xdp_filename = "format_linux_xdp_kern.o";
static const char *xdp_progname = "libtrace_xdp";

typedef struct libtrace_xdp_meta {
    uint64_t timestamp;
    uint32_t packet_len;
} PACKED libtrace_xdp_meta_t;

typedef struct libtrace_xdp {
    /* BPF filter */
    uint64_t accepted_packets;
    uint64_t filtered_packets;
    uint64_t dropped_packets;
} libtrace_xdp_t;

#endif
