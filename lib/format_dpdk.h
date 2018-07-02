#ifndef LIBTRACE_FORMAT_DPDK_H_
#define LIBTRACE_FORMAT_DPDK_H_

#include <libtrace.h>
#include "libtrace_int.h"

/* We can deal with any minor differences by checking the RTE VERSION
 * Typically DPDK backports some fixes (typically for building against
 * newer kernels) to the older version of DPDK.
 *
 * These get released with the rX suffix. The following macros where added
 * in these new releases.
 *
 * Below this is a log of version that required changes to the libtrace
 * code (that we still attempt to support).
 *
 * DPDK 16.04 or newer is recommended.
 * However 1.6 and newer are still likely supported.
 */
#include <rte_eal.h>
#include <rte_version.h>
#ifndef RTE_VERSION_NUM
#       define RTE_VERSION_NUM(a,b,c,d) ((a) << 24 | (b) << 16 | (c) << 8 | (d))
#endif
#ifndef RTE_VER_PATCH_RELEASE
#       define RTE_VER_PATCH_RELEASE 0
#endif
#ifndef RTE_VERSION
#       define RTE_VERSION RTE_VERSION_NUM(RTE_VER_MAJOR,RTE_VER_MINOR, \
        RTE_VER_PATCH_LEVEL, RTE_VER_PATCH_RELEASE)
#endif

/* 1.6.0r2 :
 *      rte_eal_pci_set_blacklist() is removed
 *      device_list is renamed to pci_device_list
 *      In the 1.7.0 release rte_eal_pci_probe is called by rte_eal_init
 *      as such we do apply the whitelist before rte_eal_init.
 *      This also works correctly with DPDK 1.6.0r2.
 *
 * Replaced by:
 *      rte_devargs (we can simply whitelist)
 */
#if RTE_VERSION <= RTE_VERSION_NUM(1, 6, 0, 1)
#       define DPDK_USE_BLACKLIST 1
#else
#       define DPDK_USE_BLACKLIST 0
#endif

/*
 * 1.7.0 :
 *      rte_pmd_init_all is removed
 *
 * Replaced by:
 *      Nothing, no longer needed
 */
#if RTE_VERSION < RTE_VERSION_NUM(1, 7, 0, 0)
#       define DPDK_USE_PMD_INIT 1
#else
#       define DPDK_USE_PMD_INIT 0
#endif

/* 1.7.0-rc3 :
 *
 * Since 1.7.0-rc3 rte_eal_pci_probe is called as part of rte_eal_init.
 * Somewhere between 1.7 and 1.8 calling it twice broke so we should not call
 * it twice.
 */
#if RTE_VERSION < RTE_VERSION_NUM(1, 7, 0, 3)
#       define DPDK_USE_PCI_PROBE 1
#else
#       define DPDK_USE_PCI_PROBE 0
#endif

/* 1.8.0-rc1 :
 * LOG LEVEL is a command line option which overrides what
 * we previously set it to.
 */
#if RTE_VERSION >= RTE_VERSION_NUM(1, 8, 0, 1)
#       define DPDK_USE_LOG_LEVEL 1
#else
#       define DPDK_USE_LOG_LEVEL 0
#endif

/* 1.8.0-rc2
 * rx/tx_conf thresholds can be set to NULL in rte_eth_rx/tx_queue_setup
 * this uses the default values, which are better tuned per device
 * See issue #26
 */
#if RTE_VERSION >= RTE_VERSION_NUM(1, 8, 0, 2)
#       define DPDK_USE_NULL_QUEUE_CONFIG 1
#else
#       define DPDK_USE_NULL_QUEUE_CONFIG 0
#endif

/* 2.0.0-rc1
 * Unifies RSS hash between cards
 */
#if RTE_VERSION >= RTE_VERSION_NUM(2, 0, 0, 1)
#       define RX_RSS_FLAGS (ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP | \
                             ETH_RSS_SCTP)
#else
#       define RX_RSS_FLAGS (ETH_RSS_IPV4_UDP | ETH_RSS_IPV6 | ETH_RSS_IPV4 | \
                             ETH_RSS_IPV4_TCP | ETH_RSS_IPV6_TCP |\
                             ETH_RSS_IPV6_UDP)
#endif

/* v16.07-rc1 - deprecated
 * rte_mempool_avail_count to replace rte_mempool_count
 * rte_mempool_in_use_count to replace rte_mempool_free_count
 */
#if RTE_VERSION < RTE_VERSION_NUM(16, 7, 0, 1)
#define rte_mempool_avail_count rte_mempool_count
#define rte_mempool_in_use_count rte_mempool_free_count
#endif

/* 17.05-rc1 deprecated, 17.08 removed
 * rte_set_log_level -> rte_log_set_global_level
 */
#if RTE_VERSION < RTE_VERSION_NUM(17, 5, 0, 1)
#define rte_log_set_global_level rte_set_log_level
#endif

/* 17.11-rc1 increases port size from 8 to 16bits
 */
#if RTE_VERSION >= RTE_VERSION_NUM(17, 11, 0, 1)
typedef uint16_t portid_t;
#else
typedef uint8_t portid_t;
#endif


#include <rte_per_lcore.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_cycles.h>
#include <pthread.h>
#ifdef __FreeBSD__
#include <pthread_np.h>
#endif


/* 16.04-rc3 ETH_LINK_SPEED_X are replaced with ETH_SPEED_NUM_X.
 * ETH_LINK_SPEED_ are reused as flags, ugly.
 * We use the new way in this code.
 */
#ifndef ETH_SPEED_NUM_1G
        #define ETH_SPEED_NUM_1G ETH_LINK_SPEED_1000
        #define ETH_SPEED_NUM_10G ETH_LINK_SPEED_10G
        #define ETH_SPEED_NUM_20G ETH_LINK_SPEED_20G
        #define ETH_SPEED_NUM_40G ETH_LINK_SPEED_40G
#endif

/* The default size of memory buffers to use - This is the max size of standard
 * ethernet packet less the size of the MAC CHECKSUM, rounded up to the
 * next power of 2, plus the RTE_PKTMBUF_HEADROOM. */
#define RX_MBUF_SIZE (2048 + RTE_PKTMBUF_HEADROOM)

/* The minimum number of memory buffers per queue tx or rx. Based on
 * the requirement of the memory pool with 128 per thread buffers, needing
 * at least 128*1.5 = 192 buffers. Our code allocates 128*2 to be safe.
 */
#define MIN_NB_BUF 128

/* Number of receive memory buffers to use
 * By default this is limited by driver to 4k and must be a multiple of 128.
 * A modification can be made to the driver to remove this limit.
 * This can be increased in the driver and here.
 * Should be at least MIN_NB_BUF.
 * We choose 2K rather than 4K because it enables the usage of sse vector
 * drivers which are significantly faster than using the larger buffer.
 */
#define NB_RX_MBUF (4096/2)

/* Number of send memory buffers to use.
 * Same limits apply as those to NB_TX_MBUF.
 */
#define NB_TX_MBUF 1024

/* The size of the PCI blacklist needs to be big enough to contain
 * every PCI device address (listed by lspci every bus:device.function tuple).
 */
#define BLACK_LIST_SIZE 50

/* The maximum number of characters the mempool name can be */
#define MEMPOOL_NAME_LEN 20

/* For single threaded libtrace we read packets as a batch/burst
 * this is the maximum size of said burst */
#define BURST_SIZE 32


/* ~~~~~~~~~~~~~~~~~~~~~~ Advance settings ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * THESE MAY REQUIRE MODIFICATIONS TO INTEL DPDK
 *
 * Make sure you understand what these are doing before enabling them.
 * They might make traces incompatible with other builds etc.
 *
 * These are also included to show how to do somethings which aren't
 * obvious in the DPDK documentation.
 */

/* Print verbose messages to stderr */
#define DEBUG 0

/* Use clock_gettime() for nanosecond resolution rather than gettimeofday()
 * only turn on if you know clock_gettime is a vsyscall on your system
 * otherwise could be a large overhead. Again gettimeofday() should be
 * vsyscall also if it's not you should seriously consider updating your
 * kernel.
 */
#ifdef HAVE_CLOCK_GETTIME
/* You can turn this on (set to 1) to prefer clock_gettime */
#define USE_CLOCK_GETTIME 1
#else
/* DON'T CHANGE THIS !!! */
#define USE_CLOCK_GETTIME 0
#endif

/* This is fairly safe to turn on - currently there appears to be a 'bug'
 * in DPDK that will remove the checksum by making the packet appear 4bytes
 * smaller than what it really is. Most formats don't include the checksum
 * hence writing out a port such as int: ring: and dpdk: assumes there
 * is no checksum and will attempt to write the checksum as part of the
 * packet
 */
#define GET_MAC_CRC_CHECKSUM 0

/* This requires a modification of the pmd drivers (inside Intel DPDK)
 * TODO this requires updating (packet sizes are wrong TS most likely also)
 */
#define HAS_HW_TIMESTAMPS_82580 0

#if HAS_HW_TIMESTAMPS_82580
# define TS_NBITS_82580     40
/* The maximum on the +ve or -ve side that we can be, make it half way */
# define MAXSKEW_82580 ((uint64_t) (.5 * (double)(1ull<<TS_NBITS_82580)))
#define WITHIN_VARIANCE(v1,v2,var) (((v1) - (var) < (v2)) && ((v1) + (var) > (v2)))
#endif

/* As per Intel 82580 specification - mismatch in 82580 datasheet
 * it states ts is stored in Big Endian, however its actually Little */
struct hw_timestamp_82580 {
        uint64_t reserved;
        uint64_t timestamp; /* Little Endian only lower 40 bits are valid */
};

enum paused_state {
        DPDK_NEVER_STARTED,
        DPDK_RUNNING,
        DPDK_PAUSED,
};

struct dpdk_per_stream_t
{
        uint16_t queue_id;
        uint64_t ts_last_sys; /* System timestamp of our most recent packet in nanoseconds */
        struct rte_mempool *mempool;
        int lcore;
#if HAS_HW_TIMESTAMPS_82580
        /* Timestamping only relevant to RX */
        uint64_t ts_first_sys; /* Sytem timestamp of the first packet in nanoseconds */
        uint32_t wrap_count; /* Number of times the NIC clock has wrapped around completely */
#endif
} ALIGN_STRUCT(CACHE_LINE_SIZE);

#if HAS_HW_TIMESTAMPS_82580
#define DPDK_EMPTY_STREAM {-1, 0, NULL, -1, 0, 0}
#else
#define DPDK_EMPTY_STREAM {-1, 0, NULL, -1}
#endif

typedef struct dpdk_per_stream_t dpdk_per_stream_t;


libtrace_eventobj_t dpdk_trace_event(libtrace_t *trace,
                libtrace_packet_t *packet);
int dpdk_pstart_input (libtrace_t *libtrace);
int dpdk_start_input (libtrace_t *libtrace);
int dpdk_config_input (libtrace_t *libtrace,
                trace_option_t option, void *data);
int dpdk_init_input (libtrace_t *libtrace);
int dpdk_pause_input(libtrace_t * libtrace);
int dpdk_fin_input(libtrace_t * libtrace);
int dpdk_read_packet (libtrace_t *libtrace, libtrace_packet_t *packet);
int dpdk_pregister_thread(libtrace_t *libtrace, libtrace_thread_t *t,
                bool reading);
void dpdk_punregister_thread(libtrace_t *libtrace, libtrace_thread_t *t);
void dpdk_get_stats(libtrace_t *trace, libtrace_stat_t *stats);
int dpdk_get_framing_length (const libtrace_packet_t *packet) ;
int dpdk_read_packet_stream (libtrace_t *libtrace,
                dpdk_per_stream_t *stream,
                libtrace_message_queue_t *mesg,
                struct rte_mbuf* pkts_burst[],
                size_t nb_packets);
int dpdk_prepare_packet(libtrace_t *libtrace,
                libtrace_packet_t *packet, void *buffer,
                libtrace_rt_types_t rt_type, uint32_t flags);
#endif
