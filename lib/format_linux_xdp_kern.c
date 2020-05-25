/*
 * clang -O2 -emit-llvm -c format_linux_xdp_kern.c -o - | \
 * llc -march=bpf -filetype=obj -o format_linux_xdp_kern
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "format_linux_xdp.h"

struct bpf_map_def SEC("maps") xsks_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

struct bpf_map_def SEC("maps") libtrace_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(libtrace_xdp_t),
    .max_entries = 64,
};

SEC("libtrace_xdp")
int xdp_sock_prog(struct xdp_md *ctx) {

    libtrace_xdp_t *libtrace;
    int ifindex;

    ifindex = ctx->rx_queue_index;

    libtrace = bpf_map_lookup_elem(&libtrace_map, &ifindex);
    if (!libtrace) {
        return XDP_ABORTED;
    }

    libtrace->received_packets += 1;

    /* A set entry here means that the correspnding queue_id
     * has an active AF_XDP socket bound to it. */
    if (bpf_map_lookup_elem(&xsks_map, &ifindex)) {
        libtrace->accepted_packets += 1;

        return bpf_redirect_map(&xsks_map, ifindex, 0);
    }

    libtrace->dropped_packets += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
