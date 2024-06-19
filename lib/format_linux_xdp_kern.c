/*
 * clang -O2 -emit-llvm -c format_linux_xdp_kern.c -o - | \
 * llc -march=bpf -filetype=obj -o format_linux_xdp_kern
 */

#include <stdbool.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "format_linux_xdp.h"

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 64); /* Assume netdev has no more than 64 queues */
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, libtrace_xdp_t);
    __uint(max_entries, 64);
} libtrace_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, libtrace_ctrl_map_t);
    __uint(max_entries, 1);
} libtrace_ctrl_map SEC(".maps");

int libtrace_xdp_sock(struct xdp_md *ctx);

static __always_inline void increment_stats(__u32 ifindex)
{

    /* get the libtrace structure for the destination queue */
    libtrace_xdp_t *libtrace = bpf_map_lookup_elem(&libtrace_map, &ifindex);

    /* increment received packets */
    if (libtrace)
        libtrace->received_packets += 1;

    return;
}

static __always_inline int redirect_map(__u32 ifindex)
{

    /* increment our stats */
    increment_stats(ifindex);

    /* redirect packet to the socket */
    return bpf_redirect_map(&xsks_map, ifindex, 0);
}

SEC("socket/libtrace_xdp")
int libtrace_xdp_sock(struct xdp_md *ctx)
{

    libtrace_ctrl_map_t *queue_ctrl;
    __u32 ifindex = ctx->rx_queue_index;
    __u32 key = 0;

    /* get the libtrace control map */
    queue_ctrl = bpf_map_lookup_elem(&libtrace_ctrl_map, &key);
    if (!queue_ctrl) {
        increment_stats(ifindex);
        return XDP_PASS;
    }

    /* make sure we are in running state */
    if (queue_ctrl->state != XDP_RUNNING) {
        increment_stats(ifindex);
        return XDP_PASS;
    }

    return redirect_map(ifindex);
}

char _license[] SEC("license") = "GPL";
