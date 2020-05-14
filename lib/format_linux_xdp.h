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

typedef struct libtrace_xdp {
    /* BPF filter */
    __u64 received_packets;
    __u64 accepted_packets;
    __u64 filtered_packets;
    __u64 dropped_packets;
} libtrace_xdp_t;

#endif
