/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

/*
 * A series of tests to verify, or check the features of a live format
 *
 * Note: not all scenarios tested here are valid libtrace programs
 * Don't follow this code as an example of how to write good libtrace programs!!
 * This code purposely holds packets it shouldn't to test formats.
 *
 */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>

#include "libtrace_parallel.h"
#include "test-nic.h"

#define T_MAX 64 /* The maximum number of threads */

enum scenarios {
        ST_SEQ = 1,
        ST_SEQ_HOLD = 2,
        MT_NO_HASHER = 3,
        MT_UNI_HASHER = 4,
        MT_BI_HASHER = 5,
        MT_BI_HASHER_HOLD = 6,
        ST_DROPPED_PACKETS = 7,
        ST_ERRED_PACKETS = 8,
        ST_NO_SNAPLEN = 9,
        ST_SMALL_SNAPLEN = 10,
        ST_JUMBO_SNAPLEN = 11,
        ST_RATE = 12,
        SCENARIO_MAX
};

static char *scenario_str(enum scenarios scenario) {
        char *ret = "unknown";
        switch (scenario) {
        case ST_SEQ:
                ret = "Single-threaded sanity test";
                break;
        case ST_SEQ_HOLD:
                ret = "Single-threaded test holding first packet";
                break;
        case MT_NO_HASHER:
                ret = "Multi-threaded sanity test";
                break;
        case MT_UNI_HASHER:
                ret = "Unidirectional hasher test";
                break;
        case MT_BI_HASHER:
                ret = "Bidirectional hasher test";
                break;
        case MT_BI_HASHER_HOLD:
                ret = "Bidirectional hasher test holding packets";
                break;
        case ST_DROPPED_PACKETS:
                ret = "Single-threaded, test drop counter";
                break;
        case ST_ERRED_PACKETS:
                ret = "Single-threaded, test erred counter";
                break;
        case ST_NO_SNAPLEN:
                ret = "Single-threaded, no snap len";
                break;
        case ST_JUMBO_SNAPLEN:
                ret = "Single-threaded, snap len 9000";
                break;
        case ST_SMALL_SNAPLEN:
                ret = "Single-threaded, snap len 66";
                break;
        case ST_RATE:
                ret = "Single-threaded, rate";
                break;
        case SCENARIO_MAX:
                break;
        }
        return ret;
}

static char *scenario_desc(enum scenarios scenario) {
        char *ret = "unknown";
        switch (scenario) {
        case ST_SEQ:
                ret = "Sends a single UDP flow, verifies all packets are "
                      "received in order";
                break;
        case ST_SEQ_HOLD:
                ret =
                    "1) + holds the first packet. An invalid libtrace program";
                break;
        case MT_NO_HASHER:
                ret = "Sends multiple UDP flows, and verifies these are "
                      "received in order across multiple threads";
                break;
        case MT_UNI_HASHER:
                ret = "3) + verifies hashing is unidirectional";
                break;
        case MT_BI_HASHER:
                ret = "3) + verifies hashing is bidirectional";
                break;
        case MT_BI_HASHER_HOLD:
                ret = "3) + Gives some packets to reporter thread to delay a "
                      "free. An invalid libtrace program";
                break;
        case ST_DROPPED_PACKETS:
                ret = "Receives first packet, then holds for 10 seconds "
                      "dropping packets";
                break;
        case ST_ERRED_PACKETS:
                ret = "Every second packet has the wrong FCS (use int: to "
                      "send), verifies errors counter";
                break;
        case ST_NO_SNAPLEN:
                ret = "Packets increasing in size, find the maximum frame size "
                      "received";
                break;
        case ST_SMALL_SNAPLEN:
                ret = "9) but snaplen 66 set";
                break;
        case ST_JUMBO_SNAPLEN:
                ret = "9) but with a jumbo snaplen 9000 set, does the format "
                      "increase MTU (optional)";
                break;
        case ST_RATE:
                ret = "Reports packet per second rate each second";
                break;
        case SCENARIO_MAX:
                break;
        }
        return ret;
}

#define PKTGEN_MAGIC 0xbe9be955
/* Let's use the pktgen header as payload */
/* Got 18 bytes of payload in a 64 byte packet */
typedef struct pktgen_hdr {
        uint32_t pgh_magic;
        uint32_t seq_num;
        uint32_t tv_sec;
        uint32_t tv_usec;
        uint64_t packet_count;
} pktgen_hdr_t;

struct libtrace_t *inptrace = NULL;
static volatile bool stop = false;
static volatile uint64_t g_rx_expected_count = -1;

static void cleanup_signal(int signal UNUSED) {
        if (inptrace)
                trace_pstop(inptrace);
        stop = true;
}

/* A keep alive timer */
static int volatile is_alive = 0;

static void keep_alive_handler(int signal) {
        if (!is_alive) {
                printf("\nStopping trace\n");
                cleanup_signal(signal);
        }
        is_alive = 0;
}

static inline void record_alive() {
        if (!is_alive)
                is_alive = 1;
}

static void start_keep_alive_timer() {
        struct sigaction sa = {0};
        struct itimerval timer = {0};
        sa.sa_handler = &keep_alive_handler;
        sigaction(SIGALRM, &sa, NULL);

        timer.it_value.tv_sec = 2;
        timer.it_interval.tv_sec = 2;

        setitimer(ITIMER_REAL, &timer, NULL);
}

static void stop_keep_alive_timer() {
        struct itimerval timer = {0};
        setitimer(ITIMER_REAL, &timer, NULL);
}

static inline void print_keep_alive() {
        static time_t last_time = 0;
        time_t cur_time = time(NULL);
        if (cur_time > last_time) {
                last_time = cur_time;
                printf(".");
                fflush(stdout);
        }
}

/** Report the packet rate each second to stderr */
static inline void report_rate_each_second() {
        static uint64_t count = 0;
        static uint64_t next_check = 0;
        static uint64_t inc = 0;
        static struct timespec last = {0};
        static struct timespec last_report = {0};

        if (next_check == 0) {
                struct timespec cur;
                clock_gettime(CLOCK_MONOTONIC, &cur);
                if (inc == 0) {
                        /* First packet start, but don't count in rate */
                        inc = 1;
                        last_report = cur;
                } else {
                        struct timespec res;
                        count += inc;
                        timespecsub(&cur, &last_report, &res);
                        if (res.tv_sec >= 1) {
                                double time =
                                    (double)((res.tv_sec * 1000000000) +
                                             res.tv_nsec) /
                                    1000000000;
                                fprintf(stderr, "Rate %f pps\n", count / time);
                                last_report = cur;
                                count = 0;
                        }

                        /* Tune to minimise calls to clock_gettime, tune to
                         * every ~5ms */
                        timespecsub(&cur, &last, &res);
                        if (res.tv_sec == 0 && res.tv_nsec <= 5000000) {
                                inc *= 2;
                        }
                }
                last = cur;
                next_check = inc;
        }
        next_check--;
}

typedef struct __attribute__((aligned(64))) thread_data {
        int tid;                 // The thread id
        uint64_t count;          // The number of valid pgh packets
        uint64_t invalid;        // The number of invalid packets
        uint64_t unordered_seq;  // The number of out of order packets
        uint32_t last_seq_num;   // The last_seq observed
        uint32_t first_seq_num;  // The seq number of the first packet observed
        uint64_t unordered_ts;   // The number of packets with unordered
        double last_ts;          // The last timestamp observed
        libtrace_packet_t
            *first_packet;  // The first packet (either held or stored)
        libtrace_packet_t *last_pkt;
        size_t largest_wirelen;  // The wire length of the largest packet seen
        int src_addrs[256];
        int dst_addrs[256];
} tls_t;

/* Using globals for counters and state
 * 1) still assigned to threads in the libtrace way when they start
 * 2) allows for easier debugging if a format gets stuck
 */

static tls_t g_tls[T_MAX] = {[0 ... T_MAX - 1] = {.tid = -1,
                                                  .count = 0,
                                                  .invalid = 0,
                                                  .unordered_seq = 0,
                                                  .last_seq_num = -1U,
                                                  .first_seq_num = -1U,
                                                  .unordered_ts = 0,
                                                  .last_ts = 0,
                                                  .first_packet = NULL,
                                                  .last_pkt = NULL,
                                                  .largest_wirelen = 0,
                                                  .src_addrs = {0},
                                                  .dst_addrs = {0}}};

enum ret_codes {
        RET_FAILED = 1,        /* The test failed */
        RET_DROPPED = 2,       /* Packets were dropped */
        RET_INVALID = 4,       /* Some packets failed validation */
        RET_ERROR = 8,         /* Another error occurred */
        RET_BUFFER_REUSED = 16 /* Detected a packet buffer has been reused */
};

static volatile enum ret_codes exit_code = 0;

#define UDP_UDP_LEN                                                            \
        (sizeof(struct udp_packet) - offsetof(struct udp_packet, udp))
#define UDP_IP_LEN (sizeof(struct udp_packet) - offsetof(struct udp_packet, ip))
#define UDP_UDP_PAYLOAD_SIZE (UDP_UDP_LEN - sizeof(libtrace_udp_t))
#define IP_MIN 0xc0a80000
/* The maximum value of the last octet, i.e cycle .0 -> .240 == 241 values */
#define IP_DIFF 240
#define IP_MAX (IP_MIN + IP_DIFF)

/* crc32() and crc32_for_byte() from http://home.thep.lu.se/~bjorn/crc/
 * public domain implementation */
static uint32_t crc32_for_byte(uint32_t r) {
        for (int j = 0; j < 8; ++j)
                r = (r & 1 ? 0 : (uint32_t)0xEDB88320L) ^ r >> 1;
        return r ^ (uint32_t)0xFF000000L;
}

static void crc32(const void *data, size_t n_bytes, uint32_t *crc) {
        static uint32_t table[0x100];
        if (!*table)
                for (size_t i = 0; i < 0x100; ++i)
                        table[i] = crc32_for_byte(i);
        for (size_t i = 0; i < n_bytes; ++i)
                *crc = table[(uint8_t)*crc ^ ((uint8_t *)data)[i]] ^ *crc >> 8;
}

struct udp_packet {
        libtrace_ether_t eth;
        libtrace_ip_t ip;
        libtrace_udp_t udp;
        pktgen_hdr_t pktgen;
} PACKED;

#define PACKET_PADDING (60 - sizeof(struct udp_packet))
#define MAX_JUMBO_PAYLOAD 10000
struct udp_packet_fcs {
        libtrace_ether_t eth;
        libtrace_ip_t ip;
        libtrace_udp_t udp;
        pktgen_hdr_t pktgen;
        int32_t fcs;
} PACKED;

struct udp_packet_jumbo {
        libtrace_ether_t eth;
        libtrace_ip_t ip;
        libtrace_udp_t udp;
        pktgen_hdr_t pktgen;
        char payload[MAX_JUMBO_PAYLOAD];
} PACKED;

static void fill_fcs(struct udp_packet_fcs *udp) {
        uint32_t crc = 0;
        crc32(udp, sizeof(struct udp_packet), &crc);
        udp->fcs = crc;
}

static libtrace_packet_t *construct_packet(libtrace_packet_t *pkt,
                                           int extra_size,
                                           struct udp_packet **udp_buffer) {
        if (extra_size > MAX_JUMBO_PAYLOAD) {
                fprintf(stderr, "Capping payload size at " TOSTRING(
                                    MAX_JUMBO_PAYLOAD) "\n");
                extra_size = MAX_JUMBO_PAYLOAD;
        }
        struct udp_packet_jumbo base_udp_packet = {
            .eth = {.ether_dhost = {0},
                    .ether_shost = {0},
                    .ether_type = htons(0x0800)},
            .ip = {.ip_v = 4,
                   .ip_hl = 5,
                   .ip_tos = 0,
                   .ip_len = htons(UDP_IP_LEN + extra_size),
                   .ip_id = 0,
                   .ip_off = 0,
                   .ip_ttl = 64,
                   .ip_p = TRACE_IPPROTO_UDP,
                   .ip_sum = 0,
                   .ip_src = {htonl(0x0a000000)},
                   .ip_dst = {htonl(IP_MIN)}},
            .udp = {.source = htons(3000),
                    .dest = htons(6000),
                    .len = htons(UDP_UDP_LEN + extra_size),
                    .check = 0},
            .pktgen = {.pgh_magic = htonl(PKTGEN_MAGIC),
                       .seq_num = 0,
                       .tv_sec = 0,
                       .tv_usec = 0,
                       .packet_count = 0}};
        for (int i = 0; i < extra_size; i++) {
                base_udp_packet.payload[i] = (char)i;
        }
        if (pkt == NULL)
                pkt = trace_create_packet();
        trace_construct_packet(pkt, TRACE_TYPE_ETH, &base_udp_packet,
                               sizeof(struct udp_packet) + extra_size);
        if (udp_buffer) {
                libtrace_linktype_t lt;
                *udp_buffer =
                    (struct udp_packet *)trace_get_layer2(pkt, &lt, NULL);
        }
        return pkt;
}

static libtrace_packet_t *construct_packet_rev(libtrace_packet_t *pkt,
                                               int extra_size,
                                               struct udp_packet **udp_buffer) {
        struct udp_packet *buffer;
        libtrace_packet_t *_pkt;
        uint16_t tmp16;
        uint32_t tmp32;
        if (udp_buffer == NULL) {
                udp_buffer = &buffer;
        }
        _pkt = construct_packet(pkt, extra_size, udp_buffer);
        tmp16 = (*udp_buffer)->udp.source;
        (*udp_buffer)->udp.source = (*udp_buffer)->udp.dest;
        (*udp_buffer)->udp.dest = tmp16;
        tmp32 = (*udp_buffer)->ip.ip_src.s_addr;
        (*udp_buffer)->ip.ip_src.s_addr = (*udp_buffer)->ip.ip_dst.s_addr;
        (*udp_buffer)->ip.ip_dst.s_addr = tmp32;
        return _pkt;
}

/** Verify the packet received has the correct data format
 * pkt: The packet
 * res: The statistics to update either count or invalid, optional
 *
 * return: The pktgen_hdr if valid, otherwise NULL if invalid
 */
static inline pktgen_hdr_t *get_verify_pgh(libtrace_packet_t *pkt, tls_t *tls) {
        libtrace_udp_t *udp = trace_get_udp(pkt);
        if (udp == NULL) {
                fprintf(stderr, "Non-UDP packet received\n");
                exit_code |= RET_INVALID;
                if (tls)
                        tls->invalid++;
                return NULL;
        }
        pktgen_hdr_t *pgh = (pktgen_hdr_t *)(udp + 1);
        if (pgh->pgh_magic != htonl(PKTGEN_MAGIC)) {
                fprintf(stderr, "Invalid packet received\n");
                exit_code |= RET_INVALID;
                if (tls)
                        tls->invalid++;
                return NULL;
        }
        if (tls)
                tls->count++;
        return pgh;
}

static inline uint32_t get_seq_num(pktgen_hdr_t *pgh) {
        return ntohl(pgh->seq_num);
}

/** Verify the timestamp of this packet is strictly greater than the last seen
 * packet [in]: The packet
 * tls [in,out]: Updated with the result (last_ts and the unordered_ts counter)
 */
inline static void verify_timestamp_increases(libtrace_packet_t *pkt,
                                              tls_t *tls) {
        double ts = trace_get_seconds(pkt);

        if (tls->last_ts != 0 && tls->last_ts >= ts) {
                /* Only print once during - don't spam */
                if (!tls->unordered_ts) {
                        fprintf(stderr, "Packet timestamps out of order\n");
                }
                tls->unordered_ts++;
        }
        tls->last_ts = ts;
}

/** Verify the sequence number of this packet is strictly greater than the last
 * seen pgh [in]: The packet gen header tls [in,out]: Updated with the result
 * (last_seq_num and the unordered_seq counter)
 */
inline static void verify_sequence_num_increases(pktgen_hdr_t *pgh,
                                                 tls_t *tls) {
        uint32_t seq_num = htonl(pgh->seq_num);

        if (tls->last_seq_num != -1U && tls->last_seq_num >= seq_num) {
                /* Only print once during - don't spam */
                if (!tls->unordered_seq) {
                        fprintf(stderr,
                                "Packets sequence out of order found %d, last "
                                "was: %d\n",
                                seq_num, tls->last_seq_num);
                }
                tls->unordered_seq++;
        }
        tls->last_seq_num = seq_num;
}

/** Verify the sequence number increments by 1
 * I.e. for use with a single-thread
 *
 * pgh [in]: The packet gen header
 * tls [in,out]: Updated with the result (last_seq_num and the unordered_seq
 * counter) step [in]: The increment step expected
 */
inline static void verify_sequence_num_increments(pktgen_hdr_t *pgh, tls_t *tls,
                                                  uint32_t step) {
        uint32_t seq_num = htonl(pgh->seq_num);

        if (tls->last_seq_num != -1U && tls->last_seq_num + step != seq_num) {
                /* Only print once during - don't spam */
                fprintf(
                    stderr,
                    "Missing or out of order packets, expected: %u found %u \n",
                    tls->last_seq_num, seq_num);
                tls->unordered_seq++;
        }
        tls->last_seq_num = seq_num;
}

/** Stores the first + information, used later by verify_first_packet to detect
 * corruption Call on every packet valid (pgh header) packet received pkt: The
 * packet pgh: The packet's packet gen header tls: The thread's storage hold: If
 * true hold the first packet, otherwise take a copy
 *
 * return: Either a packet to return from the per-packet function or NULL.
 */
inline static libtrace_packet_t *
handle_first_packet(libtrace_t *trace, libtrace_packet_t *pkt,
                    pktgen_hdr_t *pgh, tls_t *tls, enum scenarios scenario) {
        int seq_num = ntohl(pgh->seq_num);
        if (tls->first_packet == NULL) {
                fprintf(stderr, "Stored first packet %u\n", seq_num);
                if (trace_get_perpkt_threads(trace) == 1 && seq_num != 0) {
                        fprintf(stderr,
                                "Unexpected seq_num in the first packet %d\n",
                                seq_num);
                }
                tls->first_seq_num = seq_num;
                g_rx_expected_count = pgh->packet_count;
                start_keep_alive_timer();

                if (scenario == ST_SEQ_HOLD || scenario == MT_BI_HASHER_HOLD) {
                        tls->first_packet = pkt;
                        return NULL;
                } else {
                        tls->first_packet = trace_copy_packet(pkt);
                        return pkt;
                }
        }
        return pkt;
}

/**
 * Verify that the format hasn't overwritten and reused the first packet that we
 * held onto. Makes the most sense when hold was also called
 */
inline static void verify_first_packet(tls_t *tls) {

        /* Check if the first packet we captured has incorrectly been modified
         */
        uint32_t seq_num = get_seq_num(get_verify_pgh(tls->first_packet, NULL));
        if (seq_num != tls->first_seq_num) {
                fprintf(
                    stderr,
                    "Detected reused packet buffer expected: %u found %" PRIu32
                    "\n",
                    tls->first_seq_num, seq_num);
                tls->first_seq_num = seq_num;  // Prevent console spam
                exit_code |= RET_BUFFER_REUSED;
        }
}

inline static void verify_packet_len(tls_t *tls, libtrace_packet_t *pkt,
                                     pktgen_hdr_t *pktgen,
                                     enum scenarios scenario) {
        size_t cap_len = trace_get_capture_length(pkt);
        size_t wire_len = trace_get_wire_length(pkt);
        size_t seq_num = ntohl(pktgen->seq_num);
        tls->largest_wirelen = MAX(tls->largest_wirelen, wire_len);
        size_t expected_cap_len;
        size_t expected_wire_len;

        switch (scenario) {
        case ST_SEQ:
        case MT_NO_HASHER:
        case MT_UNI_HASHER:
        case MT_BI_HASHER:
        case ST_SEQ_HOLD:
        case MT_BI_HASHER_HOLD:
        case ST_DROPPED_PACKETS:
        case ST_ERRED_PACKETS:
        case ST_RATE:
                expected_cap_len = sizeof(struct udp_packet);
                /* Plus FCS */
                expected_wire_len = expected_cap_len + 4;
                break;
        case ST_NO_SNAPLEN:
                expected_cap_len = seq_num + sizeof(struct udp_packet);
                expected_wire_len = expected_cap_len + 4;
                break;
        case ST_SMALL_SNAPLEN:
                expected_cap_len = sizeof(struct udp_packet);
                expected_wire_len = seq_num + sizeof(struct udp_packet) + 4;
                break;
        case ST_JUMBO_SNAPLEN:
                expected_cap_len =
                    MIN(seq_num + sizeof(struct udp_packet), 9000);
                expected_wire_len = seq_num + sizeof(struct udp_packet) + 4;
                break;
        case SCENARIO_MAX:
                break;
        }

        /* Format returning the FCS in capture is valid, the code below assumes
         * it doesn't */
        if (cap_len == wire_len) {
                cap_len -= 4;
        }

        if (cap_len != expected_cap_len) {
                fprintf(stderr,
                        "Wrong capture length found %" PRIu64
                        " expected %" PRIu64 "\n",
                        cap_len, expected_cap_len);
                exit_code |= RET_FAILED;
        }
        if (wire_len != expected_wire_len) {
                fprintf(stderr,
                        "Wrong wire length found %" PRIu64 " expected %" PRIu64
                        "\n",
                        wire_len, expected_wire_len);
                exit_code |= RET_FAILED;
        }

        if (cap_len > sizeof(struct udp_packet)) {
                char *payload = (char *)(pktgen + 1);
                for (size_t i = 0; i < cap_len - sizeof(struct udp_packet);
                     i++) {
                        if (payload[i] != (char)i) {
                                fprintf(stderr,
                                        "Packet corruption found, "
                                        "payload[%zu]=%c\n",
                                        i, payload[i]);
                        }
                }
        }
}

static libtrace_stat_t *print_statistics(libtrace_t *trace) {

        libtrace_stat_t *stats = NULL;

        stats = trace_get_statistics(trace, NULL);
        if (stats->received_valid)
                fprintf(stderr, "%30s:\t%12" PRIu64 "\n", "Received packets",
                        stats->received);
        if (stats->filtered_valid)
                fprintf(stderr, "%30s:\t%12" PRIu64 "\n", "Filtered packets",
                        stats->filtered);
        if (stats->dropped_valid)
                fprintf(stderr, "%30s:\t%12" PRIu64 "\n", "Dropped packets",
                        stats->dropped);
        if (stats->captured_valid)
                fprintf(stderr, "%30s:\t%12" PRIu64 "\n", "Captured packets",
                        stats->captured);
        if (stats->accepted_valid)
                fprintf(stderr, "%30s:\t%12" PRIu64 "\n", "Accepted packets",
                        stats->accepted);
        if (stats->errors_valid)
                fprintf(stderr, "%30s:\t%12" PRIu64 "\n", "Erred packets",
                        stats->errors);
        return stats;
}

/**
 * trace [in]: The trace
 * total_packets [in]: The total_packets received
 *
 * Identifies the properties of the hash algorithm used
 *
 * return: HASHER_BIDIRECTIONAL or HASHER_UNIDIRECTIONAL, if it meets those
 *         requirements, otherwise, HASHER_BALANCE if nonconformant with both.
 */
static enum hasher_types detect_hasher(libtrace_t *trace,
                                       uint64_t total_packets) {
        /* Verify the correct number of packets are returned */
        int actual_threads = trace_get_perpkt_threads(trace);
        int expected_min;
        int expected_max;
        int threads[T_MAX] = {0};
        int i = 0;
        enum hasher_types hasher_type =
            HASHER_BIDIRECTIONAL;  // Until proven otherwise

        expected_min = total_packets / ((IP_DIFF + 1) * 2);
        expected_max =
            expected_min + ((bool)(total_packets % ((IP_DIFF + 1) * 2)));

        printf("Captured=%" PRIu64 " expected_min=%d expected_max=%d\n",
               total_packets, expected_min, expected_max);

        for (i = 0; i <= IP_DIFF; i++) {
                int dst_accumulated = 0;
                int src_accumulated = 0;
                for (int t = 0; t < T_MAX; t++) {
                        if (g_tls[t].src_addrs[i] && t < actual_threads) {
                                if (src_accumulated) {
                                        hasher_type = HASHER_BALANCE;
                                }
                                src_accumulated += g_tls[t].src_addrs[i];
                                threads[t] += g_tls[t].src_addrs[i];
                        } else if (g_tls[t].src_addrs[i]) {
                                printf("Unexpected non-zero value "
                                       "src_addresses[%d][%d] with %d threads",
                                       t, i, actual_threads);
                                exit_code |= RET_INVALID;
                        }
                        if (g_tls[t].dst_addrs[i] && t < actual_threads) {
                                if (dst_accumulated) {
                                        hasher_type = HASHER_BALANCE;
                                }
                                dst_accumulated += g_tls[t].dst_addrs[i];
                                threads[t] += g_tls[t].dst_addrs[i];
                        } else if (g_tls[t].dst_addrs[i]) {
                                printf("Unexpected non-zero value "
                                       "dst_addresses[%d][%d] with %d threads",
                                       t, i, actual_threads);
                                exit_code |= RET_INVALID;
                        }
                        if (dst_accumulated && !src_accumulated) {
                                // Source and dst are on different threads
                                if (hasher_type == HASHER_BIDIRECTIONAL) {
                                        hasher_type = HASHER_UNIDIRECTIONAL;
                                }
                        }
                }
                if (!IS_BETWEEN_INC(expected_min, expected_max,
                                    src_accumulated)) {
                        printf("Address X.X.X.%d src expected %d only received "
                               "%d\n",
                               i, expected_min, src_accumulated);
                        exit_code |= RET_FAILED;
                }
                if (!IS_BETWEEN_INC(expected_min, expected_max,
                                    dst_accumulated)) {
                        printf("Address X.X.X.%d dst expected %d only received "
                               "%d\n",
                               i, expected_min, dst_accumulated);
                        exit_code |= RET_FAILED;
                }
        }

        for (; i < 256; i++) {
                for (int t = 0; t < T_MAX; t++) {
                        if (g_tls[t].src_addrs[i] || g_tls[t].dst_addrs[i]) {
                                printf(
                                    "Found invalid packets with suffix .%d\n",
                                    i);
                                exit_code |= RET_INVALID;
                        }
                }
        }

        for (int t = 0; t < actual_threads; t++) {
                printf("%d: %d\n", t, threads[t]);
        }

        if (actual_threads <= 1) {
                printf(
                    "Only one thread detected, unable to determine hasher\n");
                exit_code |= RET_INVALID;
        }

        return hasher_type;
}

static void *fn_starting(libtrace_t *trace UNUSED, libtrace_thread_t *t,
                         void *global UNUSED) {
        int tid = trace_get_perpkt_thread_id(t);
        if (tid >= T_MAX || tid < 0) {
                fprintf(stderr, "Invalid thread id %d\n", tid);
                exit_code |= RET_ERROR;
                return NULL;
        }
        g_tls[tid].tid = tid;

        return (void *)&g_tls[tid];
}

static inline libtrace_packet_t *
_fn_packet_ip_roll(libtrace_t *trace, libtrace_thread_t *t, void *global UNUSED,
                   void *_tls, libtrace_packet_t *pkt,
                   enum scenarios scenario) {
        tls_t *tls = _tls;
        libtrace_packet_t *to_ret;
        pktgen_hdr_t *pgh = get_verify_pgh(pkt, tls);

        if (!pgh)
                return pkt;

        to_ret = handle_first_packet(trace, pkt, pgh, tls, scenario);

        libtrace_ip_t *ip_hdr = trace_get_ip(pkt);

        if ((ip_hdr->ip_dst.s_addr & htonl(IP_MIN)) == htonl(IP_MIN)) {
                tls->dst_addrs[((uint8_t *)&ip_hdr->ip_dst.s_addr)[3]]++;
        } else {
                if ((ip_hdr->ip_src.s_addr & htonl(IP_MIN)) != htonl(IP_MIN)) {
                        fprintf(stderr, "Bad addresses on packet\n");
                        exit_code |= RET_INVALID;
                        return pkt;
                }
                tls->src_addrs[((uint8_t *)&ip_hdr->ip_src.s_addr)[3]]++;
        }

        record_alive();
        print_keep_alive();
        verify_sequence_num_increases(pgh, tls);
        verify_first_packet(tls);
        verify_timestamp_increases(pkt, tls);
        verify_packet_len(tls, pkt, pgh, scenario);

        if (scenario == MT_BI_HASHER_HOLD && rand() % 2 && to_ret) {
                libtrace_generic_t pub = {.pkt = pkt};
                trace_publish_result(trace, t, 0, pub, RESULT_PACKET);
                return NULL;
        } else {
                return to_ret;
        }
}

static libtrace_packet_t *
fn_packet_ip_roll(libtrace_t *trace, libtrace_thread_t *t, void *global UNUSED,
                  void *tls UNUSED, libtrace_packet_t *pkt) {
        return _fn_packet_ip_roll(trace, t, global, tls, pkt, MT_NO_HASHER);
}

static libtrace_packet_t *fn_packet_ip_roll_hold(libtrace_t *trace,
                                                 libtrace_thread_t *t,
                                                 void *global UNUSED,
                                                 void *tls UNUSED,
                                                 libtrace_packet_t *pkt) {
        return _fn_packet_ip_roll(trace, t, global, tls, pkt,
                                  MT_BI_HASHER_HOLD);
}

static void fn_result_free_packet(libtrace_t *trace,
                                  libtrace_thread_t *sender UNUSED,
                                  void *global UNUSED, void *tls UNUSED,
                                  libtrace_result_t *result) {
        static libtrace_packet_t *mh = 0;

        if (rand() % 1024 == 0) {
                if (mh != NULL) {
                        trace_free_packet(trace, mh);
                }
                mh = result->value.pkt;
        } else {
                trace_free_packet(trace, result->value.pkt);
        }
}

static inline libtrace_packet_t *
_fn_packet_inc_seq(libtrace_t *trace, libtrace_thread_t *t UNUSED,
                   void *global UNUSED, void *_tls, libtrace_packet_t *pkt,
                   enum scenarios scenario) {
        tls_t *tls = (tls_t *)_tls;
        pktgen_hdr_t *pktgen = get_verify_pgh(pkt, tls);
        libtrace_packet_t *to_ret;

        if (pktgen == NULL) {
                return pkt;
        }

        if (scenario == ST_DROPPED_PACKETS && tls->first_packet == NULL) {
                for (int i = 0; i < 11; i++) {
                        // Wait 11 seconds
                        printf("*");
                        fflush(stdout);
                        sleep(1);
                }
        }

        /* If this is the first packet store it and return */
        to_ret = handle_first_packet(trace, pkt, pktgen, tls, scenario);

        /* Check the number has increased or wrapped around */
        verify_sequence_num_increments(pktgen, tls,
                                       scenario == ST_ERRED_PACKETS ? 2 : 1);
        verify_first_packet(tls);
        verify_timestamp_increases(pkt, tls);
        verify_packet_len(tls, pkt, pktgen, scenario);
        record_alive();
        print_keep_alive();

        return to_ret;
}

static inline libtrace_packet_t *fn_packet_rate(libtrace_t *trace,
                                                libtrace_thread_t *t UNUSED,
                                                void *global UNUSED, void *_tls,
                                                libtrace_packet_t *pkt) {
        tls_t *tls = (tls_t *)_tls;

        if (tls->first_packet) {
                record_alive();
                tls->count++;
        } else {
                pktgen_hdr_t *pgh = get_verify_pgh(pkt, tls);
                if (!pgh)
                        return pkt;
                handle_first_packet(trace, pkt, pgh, tls, ST_RATE);
        }

        report_rate_each_second();
        return pkt;
}

static libtrace_packet_t *fn_packet_inc_seq(libtrace_t *trace,
                                            libtrace_thread_t *t, void *global,
                                            void *tls, libtrace_packet_t *pkt) {
        return _fn_packet_inc_seq(trace, t, global, tls, pkt, ST_SEQ);
}

static libtrace_packet_t *fn_packet_inc_seq_hold(libtrace_t *trace,
                                                 libtrace_thread_t *t,
                                                 void *global, void *tls,
                                                 libtrace_packet_t *pkt) {
        return _fn_packet_inc_seq(trace, t, global, tls, pkt, ST_SEQ_HOLD);
}

static libtrace_packet_t *fn_packet_inc_seq_drop(libtrace_t *trace,
                                                 libtrace_thread_t *t,
                                                 void *global, void *tls,
                                                 libtrace_packet_t *pkt) {
        return _fn_packet_inc_seq(trace, t, global, tls, pkt,
                                  ST_DROPPED_PACKETS);
}

static libtrace_packet_t *fn_packet_inc_seq_erred(libtrace_t *trace,
                                                  libtrace_thread_t *t,
                                                  void *global, void *tls,
                                                  libtrace_packet_t *pkt) {
        return _fn_packet_inc_seq(trace, t, global, tls, pkt, ST_ERRED_PACKETS);
}

static libtrace_packet_t *fn_packet_inc_seq_no_snaplen(libtrace_t *trace,
                                                       libtrace_thread_t *t,
                                                       void *global, void *tls,
                                                       libtrace_packet_t *pkt) {
        return _fn_packet_inc_seq(trace, t, global, tls, pkt, ST_NO_SNAPLEN);
}

static libtrace_packet_t *
fn_packet_inc_seq_small_snaplen(libtrace_t *trace, libtrace_thread_t *t,
                                void *global, void *tls,
                                libtrace_packet_t *pkt) {
        return _fn_packet_inc_seq(trace, t, global, tls, pkt, ST_SMALL_SNAPLEN);
}

static libtrace_packet_t *
fn_packet_inc_seq_jumbo_snaplen(libtrace_t *trace, libtrace_thread_t *t,
                                void *global, void *tls,
                                libtrace_packet_t *pkt) {
        return _fn_packet_inc_seq(trace, t, global, tls, pkt, ST_JUMBO_SNAPLEN);
}

inline static void add_destination_ip(libtrace_ip_t *ip_hdr, uint32_t min,
                                      uint32_t max, int32_t amount) {
        uint32_t new_value = ntohl(ip_hdr->ip_dst.s_addr) + amount;
        ip_hdr->ip_dst.s_addr = htonl(WRAP_VALUE(min, max, new_value));
}

inline static void add_source_ip(libtrace_ip_t *ip_hdr, uint32_t min,
                                 uint32_t max, int32_t amount) {
        uint32_t new_value = ntohl(ip_hdr->ip_src.s_addr) + amount;
        ip_hdr->ip_src.s_addr = htonl(WRAP_VALUE(min, max, new_value));
}

/* Enforce packet counts or rates etc.
 */
static void calculate_rate(char *uri, enum scenarios scenario, int *pps,
                           uint64_t *packet_count, struct timespec *offset) {
        uint64_t multiple_of = 1; /* Round packets sent up to a multiple of */

        /* Round the number of packets that we need to send */
        switch (scenario) {
        case MT_NO_HASHER:
        case MT_UNI_HASHER:
        case MT_BI_HASHER:
        case MT_BI_HASHER_HOLD:
                /* Round up to a multiple of 241*2=482 */
                multiple_of = ((IP_DIFF + 1) * 2);
                break;
        case ST_ERRED_PACKETS:
                /* Round up to a multiple of 2 */
                multiple_of = 2;
                break;
        case ST_NO_SNAPLEN:
        case ST_SMALL_SNAPLEN:
        case ST_JUMBO_SNAPLEN:
                if (*packet_count > 10000) {
                        fprintf(stderr, "Limiting packet count to 10000 for "
                                        "snaplen tests\n");
                        *packet_count = 10000;
                }
                break;
        case ST_SEQ:
        case ST_SEQ_HOLD:
        case ST_DROPPED_PACKETS:
                break;
        case ST_RATE:
                if (*pps != 0 || *pps != -1) {
                        fprintf(stderr,
                                "Ignoring packet rate, setting to unlimited\n");
                }
                *pps = 0;
                if (*packet_count == 0) {
                        /* pps @10Gbit x 5 seconds */
                        *packet_count = 14880952 * 5;
                }
                break;
        case SCENARIO_MAX:
                break;
        }

        /* Set the default packet count */
        if (*packet_count == 0) {
                *packet_count = 10000;
        }

        /* Round up to a nice multiple of packets */
        if ((*packet_count % multiple_of) != 0) {
                *packet_count += multiple_of - (*packet_count % multiple_of);
        }

        /* Set the default pps */
        if (*pps < 0) {
                *pps = 1000;
        }
        if (*pps >= 1000000000) {
                *pps = 0;
        }

        if (*pps) {
                offset->tv_nsec = 1000000000 / *pps;
                fprintf(stderr,
                        "%s sending: %" PRIu64
                        " packets @%dpps expected runtime: %.1fs \n",
                        uri, *packet_count, *pps,
                        (double)offset->tv_nsec / 1000000000 * *packet_count);
        } else {
                fprintf(stderr,
                        "%s sending: %" PRIu64
                        " packets as fast as possible \n",
                        uri, *packet_count);
        }
}

static int run_tx_scenario(char *uri, enum scenarios scenario, int pps,
                           uint64_t packet_count) {
        libtrace_out_t *output = trace_create_output(uri);
        libtrace_packet_t *lt_packet = NULL;
        libtrace_packet_t *lt_packet_rev = NULL;
        libtrace_packet_t *lt_packet_fcs = NULL;
        libtrace_packet_t *lt_to_send;
        struct udp_packet *packet = NULL;
        struct udp_packet *packet_rev = NULL;
        struct udp_packet_fcs *packet_fcs = NULL;
        struct udp_packet *to_send;
        uint64_t packets_sent = 0;

        struct timespec wait_until;
        struct timespec cur_time;
        struct timespec offset = {.tv_sec = 0, .tv_nsec = 0};

        calculate_rate(uri, scenario, &pps, &packet_count, &offset);

        if (trace_is_err_output(output)) {
                trace_perror_output(output, "trace_create_output");
                return -1;
        }

        if (trace_start_output(output) == -1) {
                trace_perror_output(output, "trace_start_output");
                return 1;
        }

        lt_packet = construct_packet(NULL, 0, &packet);
        lt_packet_rev = construct_packet_rev(NULL, 0, &packet_rev);
        lt_packet_fcs =
            construct_packet(NULL, 4, (struct udp_packet **)&packet_fcs);

        packet->pktgen.packet_count = packet_count;
        packet_rev->pktgen.packet_count = packet_count;
        packet_fcs->pktgen.packet_count = packet_count;
        fill_fcs(packet_fcs);

        lt_to_send = lt_packet; /* The first packet to send */
        to_send = packet;

        if (scenario == ST_ERRED_PACKETS) {
                /* XXX this is a hack, there is no libtrace API for this
                 * The first free fd (3) will become the socket.
                 * If not, setsockopt() fails and we don't run this test */
                int fd = 3;
                int opt = 1;
                if (setsockopt(fd, SOL_SOCKET, SO_NOFCS, (char *)&opt,
                               sizeof(opt)) < 0) {
                        perror("Kernel does not support SO_NOFCS");
                        fprintf(stderr, "Use int: for the erred scenario\n");
                        return RET_ERROR;
                }
                lt_to_send = lt_packet_fcs;
                to_send = (struct udp_packet *)packet_fcs;
        }

        clock_gettime(CLOCK_MONOTONIC, &wait_until);

        while (!stop && packets_sent < packet_count) {
                if (trace_write_packet(output, lt_to_send) < 0) {
                        trace_perror_output(output, "Failed to write packet:");
                        fprintf(stderr,
                                "Successfully transmitted %" PRIu64
                                " packets\n",
                                packets_sent);
                        break;
                }
                if (offset.tv_nsec != 0 || offset.tv_sec != 0) {
                        trace_flush_output(output);
                }
                packets_sent++;
                report_rate_each_second();

                switch (scenario) {
                case ST_SEQ:
                case ST_SEQ_HOLD:
                case ST_DROPPED_PACKETS:
                case ST_ERRED_PACKETS:
                case ST_RATE:
                        break;
                case MT_NO_HASHER:
                case MT_UNI_HASHER:
                case MT_BI_HASHER:
                case MT_BI_HASHER_HOLD:
                        // Cycle addresses 192.168.0.0 -> 192.168.0.241
                        // Send the other version
                        // packet -> change the destination
                        // packet_rev -> change the source
                        if (to_send == packet) {
                                to_send = packet_rev;
                                lt_to_send = lt_packet_rev;
                                add_source_ip(&packet_rev->ip, IP_MIN, IP_MAX,
                                              1);
                        } else {
                                to_send = packet;
                                lt_to_send = lt_packet;
                                add_destination_ip(&packet->ip, IP_MIN, IP_MAX,
                                                   1);
                        }
                        break;
                case ST_NO_SNAPLEN:
                case ST_SMALL_SNAPLEN:
                case ST_JUMBO_SNAPLEN:
                        construct_packet(lt_to_send, packets_sent, &to_send);
                case SCENARIO_MAX:
                        break;
                }

                /* Set the sequence number */
                to_send->pktgen.seq_num = htonl(packets_sent);

                if (scenario == ST_ERRED_PACKETS) {
                        /* Every second packet will have a valid fcs */
                        if (!(packets_sent % 2)) {
                                /* Update fcs */
                                fill_fcs(packet_fcs);
                        } /* else leave wrong fcs */
                }

                if (offset.tv_nsec != 0 ||
                    offset.tv_sec != 0) { /* fast as possible */
                        /* Delay to send at the required rate */
                        timespecadd(&wait_until, &offset, &wait_until);
                        clock_gettime(CLOCK_MONOTONIC, &cur_time);
                        if (timespeccmp(&cur_time, &wait_until, <)) {
                                struct timespec wait;
                                timespecsub(&wait_until, &cur_time, &wait);
                                nanosleep(&wait, NULL);
                        }
                }
        }

        trace_destroy_packet(lt_packet);
        trace_destroy_packet(lt_packet_rev);
        trace_destroy_packet(lt_packet_fcs);
        trace_destroy_output(output);
        return 0;
}

static tls_t *verify_thread_statistics(libtrace_stat_t *stats,
                                       int num_threads) {
        static tls_t total = {0};
        int i = 0;

        for (; i < num_threads; i++) {
                total.count += g_tls[i].count;
                total.invalid += g_tls[i].invalid;
                total.unordered_seq += g_tls[i].unordered_seq;
                total.unordered_ts += g_tls[i].unordered_ts;
                total.largest_wirelen =
                    MAX(total.largest_wirelen, g_tls[i].largest_wirelen);
        }

        if (stats->accepted_valid && stats->accepted != total.count) {
                fprintf(stderr,
                        "Threads processed %" PRIu64
                        " packets, but trace reports %" PRIu64 " accepted\n",
                        total.count, stats->accepted);
        }

        if (total.invalid) {
                fprintf(stderr, "Received %" PRIu64 " invalid packets\n",
                        total.invalid);
        }
        if (total.unordered_seq) {
                fprintf(stderr, "Received %" PRIu64 " unordered sequence\n",
                        total.unordered_seq);
        }
        if (total.unordered_ts) {
                fprintf(stderr, "Received %" PRIu64 " unordered timestamps\n",
                        total.unordered_ts);
        }

        for (; i < T_MAX; i++) {
                if (g_tls[i].count) {
                        fprintf(stderr,
                                "Non-existent thread %d received %" PRIu64
                                " packets\n",
                                i, g_tls[i].count);
                        exit_code |= RET_ERROR;
                }
                if (g_tls[i].invalid) {
                        fprintf(stderr,
                                "Non-existent thread %d reports %" PRIu64
                                " invalid packets\n",
                                i, g_tls[i].invalid);
                        exit_code |= RET_ERROR;
                }
                if (g_tls[i].unordered_seq) {
                        fprintf(stderr,
                                "Non-existent thread %d reports %" PRIu64
                                " unordered seq packets\n",
                                i, g_tls[i].unordered_seq);
                        exit_code |= RET_ERROR;
                }
                if (g_tls[i].unordered_ts) {
                        fprintf(stderr,
                                "Non-existent thread %d reports %" PRIu64
                                " unordered seq packets\n",
                                i, g_tls[i].unordered_ts);
                        exit_code |= RET_ERROR;
                }
        }
        return &total;
}

/* Configure the trace based on the RX scenario */
static int configure_rx_scenario(libtrace_t *trace, int threadcount,
                                 enum scenarios scenario,
                                 libtrace_callback_set_t *pktcbs,
                                 libtrace_callback_set_t *rescbs) {
        switch (scenario) {
        case ST_SEQ:
                trace_set_packet_cb(pktcbs, fn_packet_inc_seq);
                trace_set_perpkt_threads(inptrace, 1);
                break;
        case ST_SEQ_HOLD:
                trace_set_packet_cb(pktcbs, fn_packet_inc_seq_hold);
                trace_set_perpkt_threads(inptrace, 1);
                break;
        case MT_NO_HASHER:
                trace_set_packet_cb(pktcbs, fn_packet_ip_roll);
                if (threadcount != 0)
                        trace_set_perpkt_threads(trace, threadcount);
                break;
        case MT_UNI_HASHER:
                if (trace_set_hasher(trace, HASHER_UNIDIRECTIONAL, NULL,
                                     NULL) == -1) {
                        trace_perror(trace,
                                     "Failed to set hasher unidirectional");
                        return RET_FAILED;
                }
                trace_set_packet_cb(pktcbs, fn_packet_ip_roll);
                if (threadcount != 0)
                        trace_set_perpkt_threads(trace, threadcount);
                break;
        case MT_BI_HASHER:
                if (trace_set_hasher(trace, HASHER_BIDIRECTIONAL, NULL, NULL) ==
                    -1) {
                        trace_perror(trace,
                                     "Failed to set hasher bidirectional");
                        return RET_FAILED;
                }
                trace_set_packet_cb(pktcbs, fn_packet_ip_roll);
                if (threadcount != 0)
                        trace_set_perpkt_threads(trace, threadcount);
                break;

        case MT_BI_HASHER_HOLD:
                if (trace_set_hasher(inptrace, HASHER_BIDIRECTIONAL, NULL,
                                     NULL) == -1) {
                        trace_perror(inptrace,
                                     "Failed to set hasher bidirectional");
                        return RET_FAILED;
                }
                trace_set_packet_cb(pktcbs, fn_packet_ip_roll_hold);
                trace_set_result_cb(rescbs, fn_result_free_packet);
                if (threadcount != 0)
                        trace_set_perpkt_threads(trace, threadcount);
                break;
        case ST_DROPPED_PACKETS:
                trace_set_packet_cb(pktcbs, fn_packet_inc_seq_drop);
                trace_set_perpkt_threads(trace, 1);
                break;
        case ST_ERRED_PACKETS:
                trace_set_packet_cb(pktcbs, fn_packet_inc_seq_erred);
                trace_set_perpkt_threads(trace, 1);
                break;
        case ST_NO_SNAPLEN:
                trace_set_packet_cb(pktcbs, fn_packet_inc_seq_no_snaplen);
                trace_set_perpkt_threads(trace, 1);
                break;
        case ST_SMALL_SNAPLEN:
                if (trace_set_snaplen(trace, sizeof(struct udp_packet)) == -1) {
                        trace_perror(trace, "Failed to set snaplen  %zu",
                                     sizeof(struct udp_packet));
                        return RET_FAILED;
                }
                trace_set_packet_cb(pktcbs, fn_packet_inc_seq_small_snaplen);
                trace_set_perpkt_threads(trace, 1);
                break;
        case ST_JUMBO_SNAPLEN:
                if (trace_set_snaplen(trace, 9000) == -1) {
                        trace_perror(inptrace, "Failed to set snaplen 9000");
                        return RET_FAILED;
                }
                trace_set_packet_cb(pktcbs, fn_packet_inc_seq_jumbo_snaplen);
                trace_set_perpkt_threads(trace, 1);
                break;
        case ST_RATE:
                trace_set_packet_cb(pktcbs, fn_packet_rate);
                trace_set_perpkt_threads(trace, 1);
                break;
        case SCENARIO_MAX:
                break;
        }
        return 0;
}

static int run_rx_scenario(char *uri, int threadcount,
                           enum scenarios scenario) {
        int ret;

        fprintf(stderr, "%s:\n", uri);
        libtrace_callback_set_t *pktcbs, *rescbs;

        inptrace = trace_create(uri);

        if (trace_is_err(inptrace)) {
                trace_perror(inptrace, "Failed to create trace");
                return -1;
        }

        pktcbs = trace_create_callback_set();
        rescbs = trace_create_callback_set();
        trace_set_starting_cb(pktcbs, fn_starting);

        /* Configure trace options based on the scenario */
        if ((ret = configure_rx_scenario(inptrace, threadcount, scenario,
                                         pktcbs, rescbs)) != 0) {
                return ret;
        }

        /* Start the trace as a parallel trace */
        if (trace_pstart(inptrace, NULL, pktcbs, rescbs) == -1) {
                trace_perror(inptrace, "Failed to start trace");
                return -1;
        }

        /* Wait for all threads to stop */
        trace_join(inptrace);
        stop_keep_alive_timer();
        libtrace_stat_t *stats = print_statistics(inptrace);
        tls_t *t_totals =
            verify_thread_statistics(stats, trace_get_perpkt_threads(inptrace));

        uint64_t rx_expected_accepted = g_rx_expected_count;
        uint64_t rx_expected_received = g_rx_expected_count;
        if (scenario == ST_ERRED_PACKETS) {
                rx_expected_received =
                    g_rx_expected_count / 2 + g_rx_expected_count % 2;
                rx_expected_accepted = rx_expected_received;
        }

        if (stats->received_valid && stats->received != rx_expected_received) {
                fprintf(stderr,
                        "'Received' %" PRIu64 " packets, expected %" PRIu64
                        "\n",
                        stats->received, rx_expected_received);
        }

        if (stats->dropped_valid && stats->dropped) {
                if (scenario != ST_DROPPED_PACKETS) {
                        fprintf(stderr, "Warning test dropped packets, "
                                        "decrease the rate and re-run\n");
                }
                exit_code |= RET_DROPPED;
                rx_expected_accepted -= stats->dropped;
        }

        if (stats->accepted_valid && stats->accepted != rx_expected_accepted) {
                fprintf(stderr,
                        "'Accepted' %" PRIu64 " packets, expected %" PRIu64
                        "\n",
                        stats->accepted, rx_expected_accepted);
        }

        if (scenario == MT_NO_HASHER || scenario == MT_UNI_HASHER ||
            scenario == MT_BI_HASHER || scenario == MT_BI_HASHER_HOLD) {
                enum hasher_types hasher_type =
                    detect_hasher(inptrace, g_rx_expected_count);
                char *hasher_str = NULL;
                switch (hasher_type) {
                case HASHER_BIDIRECTIONAL:
                        hasher_str = "bi-directional";
                        break;
                case HASHER_UNIDIRECTIONAL:
                        hasher_str = "uni-directional";
                        break;
                case HASHER_BALANCE:
                default:
                        hasher_str = "other";
                }

                fprintf(stderr, "Detected hasher type: %s\n", hasher_str);

                if ((scenario == MT_BI_HASHER ||
                     scenario == MT_BI_HASHER_HOLD) &&
                    hasher_type != HASHER_BIDIRECTIONAL) {
                        exit_code |= RET_FAILED;
                }
                if (scenario == MT_UNI_HASHER &&
                    !(hasher_type == HASHER_BIDIRECTIONAL ||
                      hasher_type == HASHER_UNIDIRECTIONAL)) {
                        exit_code |= RET_FAILED;
                }
        }

        switch (scenario) {
        case ST_SEQ:
        case MT_NO_HASHER:
        case MT_UNI_HASHER:
        case MT_BI_HASHER:
                /* Cases where we expect to capture all packets */
                if (exit_code == 0) {
                        fprintf(stderr, "Test result: PASS\n");
                } else if (exit_code == RET_FAILED) {
                        fprintf(stderr, "Test result: FAIL\n");
                } else {
                        fprintf(stderr, "Test result: INCONCLUSIVE\n");
                        fprintf(stderr,
                                "Read suggestions, try a lower-rate etc.\n");
                        fprintf(stderr, "Note: A bug that is not being tested "
                                        "might cause this result.\n");
                }
                break;
        case ST_SEQ_HOLD:
        case MT_BI_HASHER_HOLD:
                /* Cases where not capturing all packets is expected on failure
                 */
                if (exit_code == 0) {
                        fprintf(stderr, "Test result: PASS\n");
                } else if (exit_code | RET_BUFFER_REUSED) {
                        fprintf(stderr, "Test result: FAIL\n");
                } else if (exit_code & RET_DROPPED &&
                           !(exit_code & (RET_FAILED | RET_ERROR))) {
                        fprintf(stderr, "Test result: FAIL\n");
                        /* The buffer size is likely */
                        fprintf(stderr, "Detected buffer size: %" PRIu64 "\n",
                                g_tls[0].count);
                        fprintf(stderr, "This format will block if you hold "
                                        "packets, failure is allowed\n");
                } else {
                        fprintf(stderr, "Test result: INCONCLUSIVE\n");
                        fprintf(stderr,
                                "Read suggestions, try a lower-rate etc.\n");
                        fprintf(stderr, "Note: A bug that is not being tested "
                                        "might cause this result.\n");
                }
                break;
        case ST_DROPPED_PACKETS:
                if (exit_code == 0) {
                        fprintf(stderr, "Test result: INCONCLUSIVE\n");
                        fprintf(stderr,
                                "No packets dropped, try sending more\n");
                } else if (!stats->dropped_valid) {
                        fprintf(stderr, "Test result: INCONCLUSIVE\n");
                        fprintf(stderr, "Format does not report drops\n");
                } else if (stats->dropped + t_totals->count !=
                           rx_expected_received) {
                        fprintf(stderr, "Test result: FAILED\n");
                        fprintf(stderr,
                                "Expected: %" PRIu64 " received %" PRIu64
                                " dropped %" PRIu64 "\n",
                                rx_expected_received, t_totals->count,
                                stats->dropped);
                } else {
                        fprintf(stderr, "Test result: PASS\n");
                        fprintf(stderr,
                                "Detected RX queue(s) size: %" PRIu64 "\n",
                                t_totals->count - 1);
                }
                break;
        case ST_ERRED_PACKETS:
                if (!stats->errors_valid) {
                        fprintf(stderr, "Test result: INCONCLUSIVE\n");
                        fprintf(stderr,
                                "Format does not report erred packets\n");
                } else if (!stats->received_valid) {
                        fprintf(
                            stderr,
                            "Note: Format does not report received packets\n");
                } else if (stats->errors !=
                           (g_rx_expected_count - rx_expected_received)) {
                        fprintf(stderr, "Test result: FAILED\n");
                        fprintf(
                            stderr,
                            "Wrong number of erred packets expected: %" PRIu64
                            "\n",
                            (g_rx_expected_count - rx_expected_received));
                        exit_code |= RET_FAILED;
                } else if (stats->received_valid &&
                           stats->received != rx_expected_received) {
                        fprintf(stderr, "Test result: FAILED\n");
                        fprintf(stderr,
                                "Wrong number of packets received expected: "
                                "%" PRIu64 "\n",
                                rx_expected_received);
                        fprintf(stderr,
                                "Are erred packets included in received?\n");
                        exit_code |= RET_FAILED;
                } else if (exit_code == 0) {
                        fprintf(stderr, "Test result: PASS\n");
                } else if (exit_code == RET_FAILED) {
                        fprintf(stderr, "Test result: FAIL\n");
                } else {
                        fprintf(stderr, "Test result: INCONCLUSIVE\n");
                        fprintf(stderr,
                                "Read suggestions, try a lower-rate etc.\n");
                        fprintf(stderr, "Note: A bug that is not being tested "
                                        "might cause this result.\n");
                }
                break;
        case ST_NO_SNAPLEN:
        case ST_SMALL_SNAPLEN:
        case ST_JUMBO_SNAPLEN:
                /* Once snaplen reached this will break early, don't verify
                 * lost packets */
                fprintf(stderr, "Largest wire length: %zu\n",
                        t_totals->largest_wirelen);
                if (g_rx_expected_count <= 1514 - sizeof(struct udp_packet)) {
                        fprintf(stderr, "Test result: INCONCLUSIVE\n");
                        fprintf(stderr, "Not enough packets sent\n");
                } else if (t_totals->unordered_seq ||
                           (stats->dropped_valid && stats->dropped)) {
                        fprintf(stderr, "Test result: INCONCLUSIVE\n");
                        fprintf(stderr, "Dropped packets??\n");
                } else if (exit_code == 0 && t_totals->largest_wirelen < 1518) {
                        fprintf(stderr, "Test result: FAIL\n");
                        fprintf(stderr,
                                "Trace doesn't accept 1518 byte packets\n");
                } else if (exit_code == 0) {
                        fprintf(stderr, "Test result: PASS\n");
                } else if (exit_code == RET_FAILED) {
                        fprintf(stderr, "Test result: FAIL\n");
                } else {
                        fprintf(stderr, "Test result: INCONCLUSIVE\n");
                        fprintf(stderr,
                                "Read suggestions, try a lower-rate etc.\n");
                        fprintf(stderr, "Note: A bug that is not being tested "
                                        "might cause this result.\n");
                }
                break;
        case ST_RATE:
                if (exit_code == 0) {
                        fprintf(stderr, "Test result: INCONCLUSIVE\n");
                        fprintf(stderr,
                                "No packets dropped, try sending faster\n");
                } else {
                        fprintf(stderr, "Test result: PASS\n");
                        fprintf(stderr, "Check the rate reported\n");
                }
        case SCENARIO_MAX:
                break;
        }

        if (trace_is_err(inptrace))
                trace_perror(inptrace, "%s", uri);

        trace_destroy(inptrace);
        trace_destroy_callback_set(pktcbs);
        trace_destroy_callback_set(rescbs);

        return 0;
}

static void usage(char *argv0) {
        fprintf(stderr,
                "Usage rx: %s [-h|--help] --rx|-r <scenario> [--threads|-t "
                "threads] libtraceuri\n",
                argv0);
        fprintf(stderr,
                "Usage tx: %s [-h|--help] --tx|-t <scenario> [--pps|-p <pps>] "
                "[--count|-c <#pkts>|--time|-T <secs>]  libtraceuri\n",
                argv0);
        fprintf(stderr, "A tool to identify the capabilities of bugs present "
                        "in a live format\n"
                        "\n"
                        "Receive (rx) options:\n"
                        "--rx|-r <receive scenario>\n"
                        "--threads|-t threads - control the number of "
                        "receiving threads [default=8]\n"
                        "\n"
                        "Sending (tx) options:\n"
                        "--tx,-t <send scenario>\n"
                        "--pps|-p [0-1000000000] - tx rate (packets per "
                        "second), 0=unlimited, default=1000\n"
                        "--count|-c <no. packets to send> - This may be "
                        "rounded for some tests, default=10000\n"
                        "\n"
                        "Some tests may override your --pps or --count request "
                        "to work correctly.\n"
                        "\nScenarios (reference by number):\n"
                        "Generally all scenarios verify:\n"
                        " - The correct types of packets are received, "
                        "including our header\n"
                        " - The correct number of packets, and counters report "
                        "this correctly\n"
                        " - The correct order of the packets\n\n");
        for (int i = 1; i < SCENARIO_MAX; i++) {
                fprintf(stderr, "%d) %s\n  %s\n\n", i, scenario_str(i),
                        scenario_desc(i));
        }
}

int main(int argc, char *argv[]) {

        struct sigaction sigact;
        int threadcount = 8;
        int rx = -1;
        int tx = -1;
        int pps = -1;
        uint64_t count = 0;

        while (1) {
                int option_index;
                struct option long_options[] = {
                    {"help", 0, 0, 'h'},   {"threads", 1, 0, 'T'},
                    {"rx", 1, 0, 'r'},     {"tx", 1, 0, 't'},
                    {"pps", 1, 0, 'p'},    {"count", 1, 0, 'c'},
                    {"length", 1, 0, 'l'}, {NULL, 0, 0, 0},
                };

                int c = getopt_long(argc, argv, "hT:r:t:p:c:", long_options,
                                    &option_index);

                if (c == -1)
                        break;

                switch (c) {
                case 'h':
                        usage(argv[0]);
                        return 1;
                case 'T':
                        threadcount = atoi(optarg);
                        if (threadcount <= 0)
                                threadcount = 8;
                        break;
                case 't':
                        tx = atoi(optarg);
                        break;
                case 'r':
                        rx = atoi(optarg);
                        break;
                case 'p':
                        pps = atoi(optarg);
                        break;
                case 'c':
                        count = atoi(optarg);
                        break;
                default:
                        fprintf(stderr, "Unknown option: %c\n", c);
                        usage(argv[0]);
                        return 1;
                }
        }

        if ((rx >= 1 && tx >= 1) || (rx < 1 && tx < 1)) {
                fprintf(stderr,
                        "Please select only either -r or -t (--tx, --rx)\n");
                return -1;
        }

        if (optind >= argc) {
                fprintf(stderr, "Please supply a trace format URI\n");
                return -1;
        }

        sigact.sa_handler = cleanup_signal;
        sigemptyset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;

        sigaction(SIGINT, &sigact, NULL);
        sigaction(SIGTERM, &sigact, NULL);

        if (rx >= 1) {
                if (rx < SCENARIO_MAX) {
                        printf("Running rx scenario: %s\n", scenario_str(rx));
                        return run_rx_scenario(argv[optind], threadcount, rx);
                }
                fprintf(
                    stderr,
                    "Unknown scenario %d; choose a scenario between 1 and %d\n",
                    rx, SCENARIO_MAX - 1);
                return -1;
        }

        if (tx >= 1) {
                if (tx < SCENARIO_MAX) {
                        printf("Running tx scenario: %s\n", scenario_str(tx));
                        return run_tx_scenario(argv[optind], tx, pps, count);
                }
                fprintf(
                    stderr,
                    "Unknown scenario %d; choose a scenario between 1 and %d\n",
                    tx, SCENARIO_MAX - 1);
                return -1;
        }

        return exit_code;
}
