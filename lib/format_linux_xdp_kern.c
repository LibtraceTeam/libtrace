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
#include "jhash.h"

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

struct bpf_map_def SEC("maps") libtrace_ctrl_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = sizeof(libtrace_ctrl_map_t),
    .max_entries = 1,
};

struct pkt_meta {
    __be32 src;
    __be32 dst;
    __be32 srcv6[4];
    __be32 dstv6[4];
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u8 protocol;
};

int libtrace_xdp_sock(struct xdp_md *ctx);

/* hashing functions sources from
 * https://github.com/Netronome/bpf-samples/blob/master/programmable_rss/rss_kern.c
 */
static __always_inline bool parse_ip4(void *data, __u64 off, void *data_end,
                      struct pkt_meta *pkt)
{
    struct iphdr *iph;

    iph = data + off;
    if ((__u8 *)(iph + 1) > (__u8 *)data_end)
        return false;

    if (iph->ihl != 5)
        return false;

    pkt->src = iph->saddr;
    pkt->dst = iph->daddr;
    pkt->protocol = iph->protocol;

    return true;
}

static __always_inline bool parse_ip6(void *data, __u64 off, void *data_end,
                      struct pkt_meta *pkt)
{
    struct ipv6hdr *ip6h;

    ip6h = data + off;
    if ((__u8 *)(ip6h + 1) > (__u8 *)data_end)
        return false;

    memcpy(pkt->srcv6, ip6h->saddr.s6_addr32, 16);
    memcpy(pkt->dstv6, ip6h->daddr.s6_addr32, 16);
    pkt->protocol = ip6h->nexthdr;

    return true;
}

static __always_inline bool parse_udp(void *data, __u64 off, void *data_end,
                      struct pkt_meta *pkt)
{
    struct udphdr *udp;

    udp = data + off;
    if ((__u8 *)(udp + 1) > (__u8 *)data_end)
        return false;

    pkt->port16[0] = udp->source;
    pkt->port16[1] = udp->dest;

    return true;
}

static __always_inline bool parse_tcp(void *data, __u64 off, void *data_end,
                      struct pkt_meta *pkt)
{
    struct tcphdr *tcp;

    tcp = data + off;
    if ((__u8 *)(tcp + 1) > (__u8 *)data_end)
        return false;

    pkt->port16[0] = tcp->source;
    pkt->port16[1] = tcp->dest;

    return true;
}

static __always_inline __u32 hash_tuples(struct pkt_meta *pkt, bool is_ip6)
{
    __u32 a;
    __u32 b;

    /* hash packet ip and ports to obtain a key for rss indirection tbl */
    if (is_ip6) {
        a = jhash2(pkt->srcv6, 4, 0xc55);
        b = jhash2(pkt->dstv6, 4, 0x1234);
        return jhash_3words(a, b, pkt->ports, 0xeb0f);
    } else {
        return jhash_3words(pkt->src, pkt->dst, pkt->ports, 0xeb0f);
    }
}

static __always_inline void sort_tuple(struct pkt_meta *pkt, bool is_ip6)
{
    __be32 temp_ipv6[4];
    __be32 temp_ip;
    __u16 temp_port;
    __u64 tot_dst;
    __u64 tot_src;

    /* sort tuple to ensure consistency for both flow directions */
    if (is_ip6) {
        tot_src = pkt->srcv6[0] + pkt->srcv6[1]
               + pkt->srcv6[2] + pkt->srcv6[3];
        tot_dst = pkt->dstv6[0] + pkt->dstv6[1]
               + pkt->dstv6[2] + pkt->dstv6[3];

        if (tot_src < tot_dst) {
            memcpy(temp_ipv6, pkt->srcv6, 16);
            memcpy(pkt->srcv6, pkt->dstv6, 16);
            memcpy(pkt->dstv6, temp_ipv6, 16);
        }
    } else {
        if (pkt->src < pkt->dst) {
            temp_ip = pkt->src;
            pkt->src = pkt->dst;
            pkt->dst = temp_ip;
        }
    }

    if (pkt->port16[0] < pkt->port16[1]) {
        temp_port = pkt->port16[0];
        pkt->port16[0] = pkt->port16[1];
        pkt->port16[1] = temp_port;
    }
}

static __always_inline void increment_stats(__u32 ifindex) {

    /* get the libtrace structure for the destination queue */
    libtrace_xdp_t *libtrace = bpf_map_lookup_elem(&libtrace_map, &ifindex);

    /* increment received packets */
    if (libtrace)
        libtrace->received_packets += 1;

    return;
}

static __always_inline int redirect_map(__u32 ifindex) {

    /* increment our stats */
    increment_stats(ifindex);

    /* redirect packet to the socket */
    return bpf_redirect_map(&xsks_map, ifindex, 0);
}


SEC("socket/libtrace_xdp")
int libtrace_xdp_sock(struct xdp_md *ctx) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    libtrace_ctrl_map_t *queue_ctrl;
    struct ethhdr *eth = data;
    struct pkt_meta pkt = {};
    __u32 ifindex = ctx->rx_queue_index;
    bool symmetric = false;
    bool is_ip6 = false;
    bool jhash = false;
    __u32 eth_proto;
    __u32 hash;
    __u32 key = 0;
    __u32 off;

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

    /* set the hasher */
    switch (queue_ctrl->hasher) {
        case XDP_UNIDIRECTIONAL:
            jhash = true;
            symmetric = false;
            break;
        case XDP_BIDIRECTIONAL:
            jhash = true;
            symmetric = true;
            break;
        default: {
            /* not hashing */
            return redirect_map(ifindex);
        }
    }

    /* jump past ethernet header and check enough data remains for the ip header */
    off = sizeof(struct ethhdr);
    if (data + off > data_end) {
        return redirect_map(ifindex);
    }

    eth_proto = eth->h_proto;

    if (eth_proto == bpf_htons(ETH_P_IP)) {

        if (!parse_ip4(data, off, data_end, &pkt)) {
            /* could not parse ip4 data, do not perform any hashing */
            return redirect_map(ifindex);
        }

        off += sizeof(struct iphdr);
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {

        if (!parse_ip6(data, off, data_end, &pkt)) {
            /* could not parse ip6 data, do not perform any hashing */
            return redirect_map(ifindex);
        }

        is_ip6 = true;
        off += sizeof(struct ipv6hdr);
    } else {
        /* not ip4 or ip6 */
        return redirect_map(ifindex);
    }

    /* if IPinIP packet allow for second IP header */
    if (pkt.protocol == IPPROTO_IPIP) {
        off += sizeof(struct iphdr);
    } else if (pkt.protocol == IPPROTO_IPV6) {
        off += sizeof(struct ipv6hdr);
    }

    /* not enough payload for hashing */
    if (data + off > data_end) {
        return redirect_map(ifindex);
    }

    /* obtain port numbers for UDP and TCP traffic */
    if (pkt.protocol == IPPROTO_TCP) {
        /* failed to parse tcp, set ports to 0 and continue */
        if (!parse_tcp(data, off, data_end, &pkt)) {
            pkt.ports = 0;
        }
    } else if (pkt.protocol == IPPROTO_UDP) {
        /* failed to parse udp, set ports to 0 and continue */
        if (!parse_udp(data, off, data_end, &pkt)) {
            pkt.ports = 0;
        }
    } else {
        pkt.ports = 0;
    }

    if (symmetric) {
        sort_tuple(&pkt, is_ip6);
    }

    if (jhash) {
        /* set map lookup key using 4 tuple hash */
        hash = hash_tuples(&pkt, is_ip6);
        key = hash % queue_ctrl->max_queues;
    }

    /* redirect to the correct queue */
    return redirect_map(key);
}

char _license[] SEC("license") = "GPL";
