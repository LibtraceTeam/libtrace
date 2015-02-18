
/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton,
 * New Zealand.
 *
 * Author: Richard Sanger
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: format_dpdk.c 1805 2013-03-08 02:01:35Z salcock $
 *
 */

/* This format module deals with using the Intel Data Plane Development
 * Kit capture format.
 *
 * Intel Data Plane Development Kit is a LIVE capture format.
 *
 * This format also supports writing which will write packets out to the
 * network as a form of packet replay. This should not be confused with the
 * RT protocol which is intended to transfer captured packet records between
 * RT-speaking programs.
 */

#define _GNU_SOURCE

#include "config.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "libtrace_arphrd.h"
#include "hash_toeplitz.h"

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
# error "Can't find inttypes.h"
#endif

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <endian.h>
#include <string.h>

#if HAVE_LIBNUMA
#include <numa.h>
#endif

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
 * DPDK v1.7.1 is recommended.
 * However 1.5 to 1.8 are likely supported.
 */
#include <rte_eal.h>
#include <rte_version.h>
#ifndef RTE_VERSION_NUM
#	define RTE_VERSION_NUM(a,b,c,d) ((a) << 24 | (b) << 16 | (c) << 8 | (d))
#endif
#ifndef RTE_VER_PATCH_RELEASE
#	define RTE_VER_PATCH_RELEASE 0
#endif
#ifndef RTE_VERSION
#	define RTE_VERSION RTE_VERSION_NUM(RTE_VER_MAJOR,RTE_VER_MINOR, \
	RTE_VER_PATCH_LEVEL, RTE_VER_PATCH_RELEASE)
#endif

/* 1.6.0r2 :
 *	rte_eal_pci_set_blacklist() is removed
 *	device_list is renamed to pci_device_list
 *	In the 1.7.0 release rte_eal_pci_probe is called by rte_eal_init
 *	as such we do apply the whitelist before rte_eal_init.
 *	This also works correctly with DPDK 1.6.0r2.
 *
 * Replaced by:
 *	rte_devargs (we can simply whitelist)
 */
#if RTE_VERSION <= RTE_VERSION_NUM(1, 6, 0, 1)
#	define DPDK_USE_BLACKLIST 1
#else
#	define DPDK_USE_BLACKLIST 0
#endif

/*
 * 1.7.0 :
 *	rte_pmd_init_all is removed
 *
 * Replaced by:
 *	Nothing, no longer needed
 */
#if RTE_VERSION < RTE_VERSION_NUM(1, 7, 0, 0)
#	define DPDK_USE_PMD_INIT 1
#else
#	define DPDK_USE_PMD_INIT 0
#endif

/* 1.7.0-rc3 :
 *
 * Since 1.7.0-rc3 rte_eal_pci_probe is called as part of rte_eal_init.
 * Somewhere between 1.7 and 1.8 calling it twice broke so we should not call
 * it twice.
 */
#if RTE_VERSION < RTE_VERSION_NUM(1, 7, 0, 3)
#	define DPDK_USE_PCI_PROBE 1
#else
#	define DPDK_USE_PCI_PROBE 0
#endif

/* 1.8.0-rc1 :
 * LOG LEVEL is a command line option which overrides what
 * we previously set it to.
 */
#if RTE_VERSION >= RTE_VERSION_NUM(1, 8, 0, 1)
#	define DPDK_USE_LOG_LEVEL 1
#else
#	define DPDK_USE_LOG_LEVEL 0
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

/* The default size of memory buffers to use - This is the max size of standard
 * ethernet packet less the size of the MAC CHECKSUM */
#define RX_MBUF_SIZE 1514

/* The minimum number of memory buffers per queue tx or rx. Search for
 * _MIN_RING_DESC in DPDK. The largest minimum is 64 for 10GBit cards.
 */
#define MIN_NB_BUF 64

/* Number of receive memory buffers to use
 * By default this is limited by driver to 4k and must be a multiple of 128.
 * A modification can be made to the driver to remove this limit.
 * This can be increased in the driver and here.
 * Should be at least MIN_NB_BUF.
 */
#define NB_RX_MBUF 4096

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
#define BURST_SIZE 50

#define MBUF(x) ((struct rte_mbuf *) x)
/* Get the original placement of the packet data */
#define MBUF_PKTDATA(x) ((char *) x + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define FORMAT(x) ((struct dpdk_format_data_t*)(x->format_data))
#define PERPKT_FORMAT(x) ((struct dpdk_per_lcore_t*)(x->format_data))

#define TV_TO_NS(tv) ((uint64_t) tv.tv_sec*1000000000ull + \
			(uint64_t) tv.tv_usec*1000ull)
#define TS_TO_NS(ts) ((uint64_t) ts.tv_sec*1000000000ull + \
			(uint64_t) ts.tv_nsec)

#if RTE_PKTMBUF_HEADROOM != 128
#warning "RTE_PKT_MBUF_HEADROOM is not set to the default value of 128 - " \
	 "any libtrace instance processing these packet must be have the" \
	 "same RTE_PKTMBUF_HEADROOM set"
#endif

/* ~~~~~~~~~~~~~~~~~~~~~~ Advance settings ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * THESE MAY REQUIRE MODIFICATIONS TO INTEL DPDK
 *
 * Make sure you understand what these are doing before enabling them.
 * They might make traces incompatable with other builds etc.
 *
 * These are also included to show how to do somethings which aren't
 * obvious in the DPDK documentation.
 */

/* Print verbose messages to stderr */
#define DEBUG 0

/* Use clock_gettime() for nanosecond resolution rather than gettimeofday()
 * only turn on if you know clock_gettime is a vsyscall on your system
 * overwise could be a large overhead. Again gettimeofday() should be
 * vsyscall also if it's not you should seriously consider updating your
 * kernel.
 */
#ifdef HAVE_LIBRT
/* You can turn this on (set to 1) to prefer clock_gettime */
#define USE_CLOCK_GETTIME 1
#else
/* DONT CHANGE THIS !!! */
#define USE_CLOCK_GETTIME 1
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

struct dpdk_per_lcore_t
{
	uint16_t queue_id;
	uint8_t port;
	uint64_t ts_last_sys; /* System timestamp of our most recent packet in nanoseconds */
#if HAS_HW_TIMESTAMPS_82580
	/* Timestamping only relevent to RX */
	uint64_t ts_first_sys; /* Sytem timestamp of the first packet in nanoseconds */
	uint32_t wrap_count; /* Number of times the NIC clock has wrapped around completely */
#endif
};

/* Used by both input and output however some fields are not used
 * for output */
struct dpdk_format_data_t {
    int8_t promisc; /* promiscuous mode - RX only */
    uint8_t port; /* Always 0 we only whitelist a single port - Shared TX & RX */
    uint8_t nb_ports; /* Total number of usable ports on system should be 1 */
    uint8_t paused; /* See paused_state */
    uint16_t queue_id; /* Always 0 we use a single queue - Shared TX & RX */
    uint16_t link_speed; /* Link speed 10,100,1000,10000 etc. */
    int snaplen; /* The snap length for the capture - RX only */
    /* We always have to setup both rx and tx queues even if we don't want them */
    int nb_rx_buf; /* The number of packet buffers in the rx ring */
    int nb_tx_buf; /* The number of packet buffers in the tx ring */
    int nic_numa_node; /* The NUMA node that the NIC is attached to */
    struct rte_mempool * pktmbuf_pool; /* Our packet memory pool */
#if DPDK_USE_BLACKLIST
    struct rte_pci_addr blacklist[BLACK_LIST_SIZE]; /* Holds our device blacklist */
	unsigned int nb_blacklist; /* Number of blacklist items in are valid */
#endif
    char mempool_name[MEMPOOL_NAME_LEN]; /* The name of the mempool that we are using */
    uint8_t rss_key[40]; // This is the RSS KEY
    /* To improve performance we always batch reading packets, in a burst */
    struct rte_mbuf* burst_pkts[BURST_SIZE];
    int burst_size; /* The total number read in the burst */
    int burst_offset; /* The offset we are into the burst */
	// DPDK normally seems to have a limit of 8 queues for a given card
	struct dpdk_per_lcore_t per_lcore[RTE_MAX_LCORE];
};

enum dpdk_addt_hdr_flags {
    INCLUDES_CHECKSUM = 0x1,
    INCLUDES_HW_TIMESTAMP = 0x2, /* Used with 82580 driver */
};

/**
 * A structure placed in front of the packet where we can store
 * additional information about the given packet.
 * +--------------------------+
 * |       rte_mbuf (pkt)     | sizeof(rte_mbuf)
 * +--------------------------+
 * |       dpdk_addt_hdr      | sizeof(dpdk_addt_hdr)
 * +--------------------------+
 * |           padding        | RTE_PKTMBUF_HEADROOM-sizeof(dpdk_addt_hdr)
 * +--------------------------+
 * *   hw_timestamp_82580     * 16 bytes Optional
 * +--------------------------+
 * |       Packet data        | Variable Size
 * |                          |
 */
struct dpdk_addt_hdr {
    uint64_t timestamp;
    uint8_t flags;
    uint8_t direction;
    uint8_t reserved1;
    uint8_t reserved2;
    uint32_t cap_len; /* The size to say the capture is */
};

/**
 * We want to blacklist all devices except those on the whitelist
 * (I say list, but yes it is only the one).
 *
 * The default behaviour of rte_pci_probe() will map every possible device
 * to its DPDK driver. The DPDK driver will take the ethernet device
 * out of the kernel (i.e. no longer /dev/ethx) and cannot be used.
 *
 * So blacklist all devices except the one that we wish to use so that
 * the others can still be used as standard ethernet ports.
 *
 * @return 0 if successful, otherwise -1 on error.
 */
#if DPDK_USE_BLACKLIST
static int blacklist_devices(struct dpdk_format_data_t *format_data, struct rte_pci_addr *whitelist)
{
	struct rte_pci_device *dev = NULL;
	format_data->nb_blacklist = 0;

	memset(format_data->blacklist, 0, sizeof (format_data->blacklist));

	TAILQ_FOREACH(dev, &device_list, next) {
	if (whitelist != NULL && whitelist->domain == dev->addr.domain
	    && whitelist->bus == dev->addr.bus
	    && whitelist->devid == dev->addr.devid
	    && whitelist->function == dev->addr.function)
	    continue;
		if (format_data->nb_blacklist >= sizeof (format_data->blacklist)
				/ sizeof (format_data->blacklist[0])) {
			fprintf(stderr, "Warning: too many devices to blacklist consider"
					" increasing BLACK_LIST_SIZE");
			break;
		}
		format_data->blacklist[format_data->nb_blacklist] = dev->addr;
		++format_data->nb_blacklist;
	}

	rte_eal_pci_set_blacklist(format_data->blacklist, format_data->nb_blacklist);
	return 0;
}
#else /* DPDK_USE_BLACKLIST */
#include <rte_devargs.h>
static int whitelist_device(struct dpdk_format_data_t *format_data UNUSED, struct rte_pci_addr *whitelist)
{
	char pci_str[20] = {0};
	snprintf(pci_str, sizeof(pci_str), PCI_PRI_FMT,
		 whitelist->domain,
		 whitelist->bus,
		 whitelist->devid,
		 whitelist->function);
	if (rte_eal_devargs_add(RTE_DEVTYPE_WHITELISTED_PCI, pci_str) < 0) {
		return -1;
	}
	return 0;
}
#endif

/**
 * Parse the URI format as a pci address
 * Fills in addr, note core is optional and is unchanged if
 * a value for it is not provided.
 *
 * i.e. ./libtrace dpdk:0:1:0.0 -> 0:1:0.0
 * or ./libtrace dpdk:0:1:0.1-2 -> 0:1:0.1 (Using CPU core #2)
 */
static int parse_pciaddr(char * str, struct rte_pci_addr * addr, long * core) {
    int matches;
    assert(str);
    matches = sscanf(str, "%4"SCNx16":%2"SCNx8":%2"SCNx8".%2"SCNx8"-%ld",
                     &addr->domain, &addr->bus, &addr->devid, &addr->function, core);
    if (matches >= 4) {
        return 0;
    } else {
        return -1;
    }
}

/**
 * Convert a pci address to the numa node it is
 * connected to.
 *
 * This checks /sys/bus/pci/devices/XXXX:XX:XX.X/numa_node
 * so we can call it before DPDK
 *
 * @return -1 if unknown otherwise a number 0 or higher of the numa node
 */
static int pci_to_numa(struct rte_pci_addr * dev_addr) {
	char path[50] = {0};
	FILE *file;

	/* Read from the system */
	snprintf(path, sizeof(path), "/sys/bus/pci/devices/"PCI_PRI_FMT"/numa_node",
		 dev_addr->domain,
		 dev_addr->bus,
		 dev_addr->devid,
		 dev_addr->function);

	if((file = fopen(path, "r")) != NULL) {
		int numa_node = -1;
		fscanf(file, "%d", &numa_node);
		fclose(file);
		return numa_node;
	}
	return -1;
}

#if DEBUG
/* For debugging */
static inline void dump_configuration()
{
    struct rte_config * global_config;
    long nb_cpu = sysconf(_SC_NPROCESSORS_ONLN);

    if (nb_cpu <= 0) {
	perror("sysconf(_SC_NPROCESSORS_ONLN) failed. Falling back to the first core.");
	nb_cpu = 1; /* fallback to just 1 core */
    }
    if (nb_cpu > RTE_MAX_LCORE)
	nb_cpu = RTE_MAX_LCORE;

    global_config = rte_eal_get_configuration();

    if (global_config != NULL) {
	int i;
	fprintf(stderr, "Intel DPDK setup\n"
	       "---Version      : %s\n"
	       "---Master LCore : %"PRIu32"\n"
	       "---LCore Count  : %"PRIu32"\n",
	       rte_version(),
	       global_config->master_lcore, global_config->lcore_count);

	for (i = 0 ; i < nb_cpu; i++) {
	    fprintf(stderr, "   ---Core %d : %s\n", i,
		   global_config->lcore_role[i] == ROLE_RTE ? "on" : "off");
	}

	const char * proc_type;
	switch (global_config->process_type) {
	    case RTE_PROC_AUTO:
		proc_type = "auto";
		break;
	    case RTE_PROC_PRIMARY:
		proc_type = "primary";
		break;
	    case RTE_PROC_SECONDARY:
		proc_type = "secondary";
		break;
	    case RTE_PROC_INVALID:
		proc_type = "invalid";
		break;
	    default:
		proc_type = "something worse than invalid!!";
	}
	fprintf(stderr, "---Process Type : %s\n", proc_type);
    }

}
#endif

/**
 * Expects to be called from the master lcore and moves it to the given dpdk id
 * @param core (zero indexed) If core is on the physical system affinity is bound otherwise
 *               affinity is set to all cores. Must be less than RTE_MAX_LCORE
 *               and not already in use.
 * @return 0 is successful otherwise -1 on error.
 */
static inline int dpdk_move_master_lcore(size_t core) {
    struct rte_config *cfg = rte_eal_get_configuration();
    cpu_set_t cpuset;
    int i;

    assert (core < RTE_MAX_LCORE);
    assert (rte_get_master_lcore() == rte_lcore_id());

    if (core == rte_lcore_id())
	return 0;

    // Make sure we are not overwriting someone else
    assert(!rte_lcore_is_enabled(core));

    // Move the core
    cfg->lcore_role[rte_lcore_id()] = ROLE_OFF;
    cfg->lcore_role[core] = ROLE_RTE;
    lcore_config[core].thread_id = lcore_config[rte_lcore_id()].thread_id;
    rte_eal_get_configuration()->master_lcore = core;
    RTE_PER_LCORE(_lcore_id) = core;

    // Now change the affinity
    CPU_ZERO(&cpuset);

    if (lcore_config[core].detected) {
	CPU_SET(core, &cpuset);
    } else {
	for (i = 0; i < RTE_MAX_LCORE; ++i) {
	    if (lcore_config[i].detected)
		CPU_SET(i, &cpuset);
	}
    }

    i = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    if (i != 0) {
	// TODO proper libtrace style error here!!
	fprintf(stderr, "pthread_setaffinity_np failed\n");
	return -1;
    }
    return 0;
}


/**
 * XXX This is very bad XXX
 * But we have to do something to allow getopts nesting
 * Luckly normally the format is last so it doesn't matter
 * DPDK only supports modern systems so hopefully this
 * will continue to work
 */
struct saved_getopts {
	char *optarg;
	int optind;
	int opterr;
	int optopt;
};

static void save_getopts(struct saved_getopts *opts) {
	opts->optarg = optarg;
	opts->optind = optind;
	opts->opterr = opterr;
	opts->optopt = optopt;
}

static void restore_getopts(struct saved_getopts *opts) {
	optarg = opts->optarg;
	optind = opts->optind;
	opterr = opts->opterr;
	optopt = opts->optopt;
}

static inline int dpdk_init_environment(char * uridata, struct dpdk_format_data_t * format_data,
					char * err, int errlen) {
    int ret; /* Returned error codes */
    struct rte_pci_addr use_addr; /* The only address that we don't blacklist */
    char cpu_number[10] = {0}; /* The CPU mask we want to bind to */
    char mem_map[20] = {0}; /* The memory name */
    long nb_cpu; /* The number of CPUs in the system */
    long my_cpu; /* The CPU number we want to bind to */
    int i;
    struct rte_config *cfg = rte_eal_get_configuration();
	struct saved_getopts save_opts;

#if DEBUG
    rte_set_log_level(RTE_LOG_DEBUG);
#else
    rte_set_log_level(RTE_LOG_WARNING);
#endif
    /*
     * Using unique file prefixes mean separate memory is used, unlinking
     * the two processes. However be careful we still cannot access a
     * port that already in use.
     *
     * Using unique file prefixes mean separate memory is used, unlinking
     * the two processes. However be careful we still cannot access a
     * port that already in use.
     */
    char* argv[] = {"libtrace",
                    "-c", cpu_number,
                    "-n", "1",
                    "--proc-type", "auto",
                    "--file-prefix", mem_map,
                    "-m", "256",
#if DPDK_USE_LOG_LEVEL
#	if DEBUG
                    "--log-level", "8", /* RTE_LOG_DEBUG */
#	else
                    "--log-level", "5", /* RTE_LOG_WARNING */
#	endif
#endif
                    NULL};
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    /* This initialises the Environment Abstraction Layer (EAL)
     * If we had slave workers these are put into WAITING state
     *
     * Basically binds this thread to a fixed core, which we choose as
     * the last core on the machine (assuming fewer interrupts mapped here).
     * "-c" controls the cpu mask 0x1=1st core 0x2=2nd 0x4=3rd and so on
     * "-n" the number of memory channels into the CPU (hardware specific)
     *      - Most likely to be half the number of ram slots in your machine.
     *        We could count ram slots by "dmidecode -t 17 | grep -c 'Size:'"
     * Controls where in memory packets are stored and should spread across
     * the channels. We just use 1 to be safe.
     */

    /* Get the number of cpu cores in the system and use the last core
     * on the correct numa node */
    nb_cpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (nb_cpu <= 0) {
	perror("sysconf(_SC_NPROCESSORS_ONLN) failed. Falling back to the first core.");
	nb_cpu = 1; /* fallback to the first core */
    }
    if (nb_cpu > RTE_MAX_LCORE)
	nb_cpu = RTE_MAX_LCORE;

    my_cpu = -1;
    /* This allows the user to specify the core - we would try to do this
     * automatically but it's hard to tell that this is secondary
     * before running rte_eal_init(...). Currently we are limited to 1
     * instance per core due to the way memory is allocated. */
    if (parse_pciaddr(uridata, &use_addr, &my_cpu) != 0) {
	snprintf(err, errlen, "Failed to parse URI");
	return -1;
    }

#if HAVE_LIBNUMA
	format_data->nic_numa_node = pci_to_numa(&use_addr);
	if (my_cpu < 0) {
		/* If we can assign to a core on the same numa node */
		fprintf(stderr, "Using pci card on numa_node%d\n", format_data->nic_numa_node);
		if(format_data->nic_numa_node >= 0) {
			int max_node_cpu = -1;
			struct bitmask *mask = numa_allocate_cpumask();
			assert(mask);
			numa_node_to_cpus(format_data->nic_numa_node, mask);
			for (i = 0 ; i < nb_cpu; ++i) {
				if (numa_bitmask_isbitset(mask,i))
					max_node_cpu = i+1;
			}
			my_cpu = max_node_cpu;
		}
	}
#endif
	if (my_cpu < 0) {
		my_cpu = nb_cpu;
	}


    snprintf(format_data->mempool_name, MEMPOOL_NAME_LEN,
		"libtrace_pool_%"PRIu32, (uint32_t) nb_cpu);

    if (!(my_cpu > 0 && my_cpu <= nb_cpu)) {
	snprintf(err, errlen,
	  "Intel DPDK - User defined a bad CPU number %"PRIu32" must be"
	  " between 1 and %"PRIu32, (uint32_t) my_cpu, (uint32_t) nb_cpu);
	return -1;
    }

    /* Make our mask with all cores turned on this is so that DPDK to gets CPU
       info older versions */
    snprintf(cpu_number, sizeof(cpu_number), "%x", ~(UINT32_MAX<<MIN(31, nb_cpu)));
    //snprintf(cpu_number, sizeof(cpu_number), "%x", 0x1 << (my_cpu - 1));

#if !DPDK_USE_BLACKLIST
    /* Black list all ports besides the one that we want to use */
	if ((ret = whitelist_device(format_data, &use_addr)) < 0) {
		snprintf(err, errlen, "Intel DPDK - Whitelisting PCI device failed,"
			 " are you sure the address is correct?: %s", strerror(-ret));
		return -1;
	}
#endif

	/* Give the memory map a unique name */
	snprintf(mem_map, sizeof(mem_map), "libtrace-%d", (int) getpid());
    /* rte_eal_init it makes a call to getopt so we need to reset the
     * global optind variable of getopt otherwise this fails */
	save_getopts(&save_opts);
    optind = 1;
    if ((ret = rte_eal_init(argc, argv)) < 0) {
	snprintf(err, errlen,
	  "Intel DPDK - Initialisation of EAL failed: %s", strerror(-ret));
	return -1;
    }
	restore_getopts(&save_opts);
    // These are still running but will never do anything with DPDK v1.7 we
    // should remove this XXX in the future
    for(i = 0; i < RTE_MAX_LCORE; ++i) {
	    if (rte_lcore_is_enabled(i) && i != (int) rte_get_master_lcore()) {
	    cfg->lcore_role[i] = ROLE_OFF;
	    cfg->lcore_count--;
	}
    }
    // Only the master should be running
    assert(cfg->lcore_count == 1);

    dpdk_move_master_lcore(my_cpu-1);

#if DEBUG
    dump_configuration();
#endif

#if DPDK_USE_PMD_INIT
    /* This registers all available NICs with Intel DPDK
     * These are not loaded until rte_eal_pci_probe() is called.
     */
    if ((ret = rte_pmd_init_all()) < 0) {
	snprintf(err, errlen,
	  "Intel DPDK - rte_pmd_init_all failed: %s", strerror(-ret));
	return -1;
    }
#endif

#if DPDK_USE_BLACKLIST
    /* Blacklist all ports besides the one that we want to use */
	if ((ret = blacklist_devices(format_data, &use_addr)) < 0) {
		snprintf(err, errlen, "Intel DPDK - Whitelisting PCI device failed,"
			 " are you sure the address is correct?: %s", strerror(-ret));
		return -1;
	}
#endif

#if DPDK_USE_PCI_PROBE
    /* This loads DPDK drivers against all ports that are not blacklisted */
	if ((ret = rte_eal_pci_probe()) < 0) {
	snprintf(err, errlen,
	    "Intel DPDK - rte_eal_pci_probe failed: %s", strerror(-ret));
	return -1;
    }
#endif

    format_data->nb_ports = rte_eth_dev_count();

    if (format_data->nb_ports != 1) {
	snprintf(err, errlen,
	    "Intel DPDK - rte_eth_dev_count returned %d but it should be 1",
	    format_data->nb_ports);
	return -1;
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(0, &dev_info);
    fprintf(stderr, "Device port=0\n\tmin_rx_bufsize=%d\n\tmax_rx_pktlen=%d\n\tmax rx queues=%d\n\tmax tx queues=%d",
		(int) dev_info.min_rx_bufsize, (int) dev_info.max_rx_pktlen, (int) dev_info.max_rx_queues, (int) dev_info.max_tx_queues);

    return 0;
}

static int dpdk_init_input (libtrace_t *libtrace) {
    char err[500];
    err[0] = 0;

    libtrace->format_data = (struct dpdk_format_data_t *)
			    malloc(sizeof(struct dpdk_format_data_t));
    FORMAT(libtrace)->port = 0; /* Always assume 1 port loaded */
    FORMAT(libtrace)->queue_id = 0; /* Single queue per port */
    FORMAT(libtrace)->nb_ports = 0;
    FORMAT(libtrace)->snaplen = 0; /* Use default */
    FORMAT(libtrace)->nb_rx_buf = NB_RX_MBUF;
    FORMAT(libtrace)->nb_tx_buf = MIN_NB_BUF;
    FORMAT(libtrace)->nic_numa_node = -1;
    FORMAT(libtrace)->promisc = -1;
    FORMAT(libtrace)->pktmbuf_pool = NULL;
#if DPDK_USE_BLACKLIST
    FORMAT(libtrace)->nb_blacklist = 0;
#endif
    FORMAT(libtrace)->paused = DPDK_NEVER_STARTED;
    FORMAT(libtrace)->mempool_name[0] = 0;
    memset(FORMAT(libtrace)->burst_pkts, 0, sizeof(FORMAT(libtrace)->burst_pkts[0]) * BURST_SIZE);
    FORMAT(libtrace)->burst_size = 0;
    FORMAT(libtrace)->burst_offset = 0;

    if (dpdk_init_environment(libtrace->uridata, FORMAT(libtrace), err, sizeof(err)) != 0) {
	trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err);
	free(libtrace->format_data);
	libtrace->format_data = NULL;
	return -1;
    }
    return 0;
};

static int dpdk_init_output(libtrace_out_t *libtrace)
{
    char err[500];
    err[0] = 0;

    libtrace->format_data = (struct dpdk_format_data_t *)
			    malloc(sizeof(struct dpdk_format_data_t));
    FORMAT(libtrace)->port = 0; /* Always assume 1 port loaded */
    FORMAT(libtrace)->queue_id = 0; /* Single queue per port */
    FORMAT(libtrace)->nb_ports = 0;
    FORMAT(libtrace)->snaplen = 0; /* Use default */
    FORMAT(libtrace)->nb_rx_buf = MIN_NB_BUF;
    FORMAT(libtrace)->nb_tx_buf = NB_TX_MBUF;
    FORMAT(libtrace)->nic_numa_node = -1;
    FORMAT(libtrace)->promisc = -1;
    FORMAT(libtrace)->pktmbuf_pool = NULL;
#if DPDK_USE_BLACKLIST
    FORMAT(libtrace)->nb_blacklist = 0;
#endif
    FORMAT(libtrace)->paused = DPDK_NEVER_STARTED;
    FORMAT(libtrace)->mempool_name[0] = 0;
    memset(FORMAT(libtrace)->burst_pkts, 0, sizeof(FORMAT(libtrace)->burst_pkts[0]) * BURST_SIZE);
    FORMAT(libtrace)->burst_size = 0;
    FORMAT(libtrace)->burst_offset = 0;

    if (dpdk_init_environment(libtrace->uridata, FORMAT(libtrace), err, sizeof(err)) != 0) {
	trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "%s", err);
	free(libtrace->format_data);
	libtrace->format_data = NULL;
	return -1;
    }
    return 0;
};

static int dpdk_pconfig_input (libtrace_t *libtrace,
				trace_parallel_option_t option,
				void *data) {
	switch (option) {
		case TRACE_OPTION_SET_HASHER:
			switch (*((enum hasher_types *) data))
			{
				case HASHER_BALANCE:
				case HASHER_UNIDIRECTIONAL:
					toeplitz_create_unikey(FORMAT(libtrace)->rss_key);
					return 0;
				case HASHER_BIDIRECTIONAL:
					toeplitz_create_bikey(FORMAT(libtrace)->rss_key);
					return 0;
				case HASHER_HARDWARE:
				case HASHER_CUSTOM:
					// We don't support these
					return -1;
			}
	break;
	}
	return -1;
}
/**
 * Note here snaplen excludes the MAC checksum. Packets over
 * the requested snaplen will be dropped. (Excluding MAC checksum)
 *
 * I.e the maximum size of a standard ethernet packet is 1518 (Including MAC checksum)
 * So to allow packets upto 1518 this would be set to 1514 and if GET_MAC_CRC_CHECKSUM
 * is set the maximum size of the returned packet would be 1518 otherwise
 * 1514 would be the largest size possibly returned.
 *
 */
static int dpdk_config_input (libtrace_t *libtrace,
					trace_option_t option,
					void *data) {
    switch (option) {
	case TRACE_OPTION_SNAPLEN:
	    /* Only support changing snaplen before a call to start is
	     * made */
	    if (FORMAT(libtrace)->paused == DPDK_NEVER_STARTED)
		FORMAT(libtrace)->snaplen=*(int*)data;
	    else
		return -1;
	    return 0;
		case TRACE_OPTION_PROMISC:
			FORMAT(libtrace)->promisc=*(int*)data;
	    return 0;
	case TRACE_OPTION_FILTER:
	    /* TODO filtering */
	    break;
	case TRACE_OPTION_META_FREQ:
	    break;
	case TRACE_OPTION_EVENT_REALTIME:
	    break;
	/* Avoid default: so that future options will cause a warning
	 * here to remind us to implement it, or flag it as
	 * unimplementable
	 */
    }

	/* Don't set an error - trace_config will try to deal with the
	 * option and will set an error if it fails */
    return -1;
}

/* Can set jumbo frames/ or limit the size of a frame by setting both
 * max_rx_pkt_len and jumbo_frame. This can be limited to less than
 *
 */
static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_RSS,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.max_rx_pkt_len = 0, /**< Max frame Size if Jumbo enabled */
#if GET_MAC_CRC_CHECKSUM
/* So it appears that if hw_strip_crc is turned off the driver will still
 * take this off. See line 955ish in lib/librte_pmd_e1000/igb_rxtx.c.
 * So if .hw_strip_crc=0 a valid CRC exists 4 bytes after the end of the
 * So lets just add it back on when we receive the packet.
 */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
#else
/* By default strip the MAC checksum because it's a bit of a hack to
 * actually read these. And don't want to rely on disabling this to actualy
 * always cut off the checksum in the future
 */
		.hw_strip_crc   = 1, /**< CRC stripped by hardware */
#endif
	},
	.txmode = {
		.mq_mode = ETH_DCB_NONE,
	},
	.rx_adv_conf = {
		.rss_conf = {
			// .rss_key = &rss_key, // We set this per format
			.rss_hf = ETH_RSS_IPV4_UDP | ETH_RSS_IPV6 | ETH_RSS_IPV4 | ETH_RSS_IPV4_TCP | ETH_RSS_IPV6_TCP | ETH_RSS_IPV6_UDP,
		},
	},
	.intr_conf = {
		.lsc = 1
	}
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = 8,/* RX_PTHRESH prefetch */
		.hthresh = 8,/* RX_HTHRESH host */
		.wthresh = 4,/* RX_WTHRESH writeback */
	},
    .rx_free_thresh = 0,
    .rx_drop_en = 0, /* Drop packets oldest packets if out of space */
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
	/**
	 * TX_PTHRESH prefetch
	 * Set on the NIC, if the number of unprocessed descriptors to queued on
	 * the card fall below this try grab at least hthresh more unprocessed
	 * descriptors.
	 */
		.pthresh = 36,

	/* TX_HTHRESH host
	 * Set on the NIC, the batch size to prefetch unprocessed tx descriptors.
	 */
		.hthresh = 0,

	/* TX_WTHRESH writeback
	 * Set on the NIC, the number of sent descriptors before writing back
	 * status to confirm the transmission. This is done more efficiently as
	 * a bulk DMA-transfer rather than writing one at a time.
	 * Similar to tx_free_thresh however this is applied to the NIC, where
	 * as tx_free_thresh is when DPDK will check these. This is extended
	 * upon by tx_rs_thresh (10Gbit cards) which doesn't write all
	 * descriptors rather only every n'th item, reducing DMA memory bandwidth.
	 */
		.wthresh = 4,
	},

    /* Used internally by DPDK rather than passed to the NIC. The number of
     * packet descriptors to send before checking for any responses written
     * back (to confirm the transmission). Default = 32 if set to 0)
     */
	.tx_free_thresh = 0,

    /* This is the Report Status threshold, used by 10Gbit cards,
     * This signals the card to only write back status (such as
     * transmission successful) after this minimum number of transmit
     * descriptors are seen. The default is 32 (if set to 0) however if set
     * to greater than 1 TX wthresh must be set to zero, because this is kindof
     * a replacement. See the dpdk programmers guide for more restrictions.
     */
	.tx_rs_thresh = 1,
};

/**
 * A callback for a link state change (LSC).
 *
 * Packets may be received before this notification. In fact the DPDK IGXBE
 * driver likes to put a delay upto 5sec before sending this.
 *
 * We use this to ensure the link speed is correct for our timestamp
 * calculations. Because packets might be received before the link up we still
 * update this when the packet is received.
 *
 * @param port The DPDK port
 * @param event The TYPE of event (expected to be RTE_ETH_EVENT_INTR_LSC)
 * @param cb_arg The dpdk_format_data_t structure associated with the format
 */
static void dpdk_lsc_callback(uint8_t port, enum rte_eth_event_type event,
                              void *cb_arg) {
	struct dpdk_format_data_t * format_data = cb_arg;
	struct rte_eth_link link_info;
	assert(event == RTE_ETH_EVENT_INTR_LSC);
	assert(port == format_data->port);

	rte_eth_link_get_nowait(port, &link_info);

	if (link_info.link_status)
		format_data->link_speed = link_info.link_speed;
	else
		format_data->link_speed = 0;

#if DEBUG
	fprintf(stderr, "LSC - link status is %s %s speed=%d\n",
	        link_info.link_status ? "up" : "down",
	        (link_info.link_duplex == ETH_LINK_FULL_DUPLEX) ?
	                                  "full-duplex" : "half-duplex",
	        (int) link_info.link_speed);
#endif

	/* Turns out DPDK drivers might not come back up if the link speed
	 * changes. So we reset the autoneg procedure. This is very unsafe
	 * we have have threads reading packets and we stop the port. */
#if 0
	if (!link_info.link_status) {
		int ret;
		rte_eth_dev_stop(port);
		ret = rte_eth_dev_start(port);
		if (ret < 0) {
			fprintf(stderr, "Resetting the DPDK port failed : %s\n",
			        strerror(-ret));
		}
	}
#endif
}

/* Attach memory to the port and start the port or restart the port.
 */
static int dpdk_start_port (struct dpdk_format_data_t * format_data, char *err, int errlen){
    int ret; /* Check return values for errors */
    struct rte_eth_link link_info; /* Wait for link */
    unsigned cpu_numa_node = rte_lcore_to_socket_id(rte_lcore_id());

    /* Already started */
    if (format_data->paused == DPDK_RUNNING)
	return 0;

    /* First time started we need to alloc our memory, doing this here
     * rather than in environment setup because we don't have snaplen then */
    if (format_data->paused == DPDK_NEVER_STARTED) {
	if (format_data->snaplen == 0) {
	    format_data->snaplen = RX_MBUF_SIZE;
	    port_conf.rxmode.jumbo_frame = 0;
	    port_conf.rxmode.max_rx_pkt_len = 0;
	} else {
	    /* Use jumbo frames */
	    port_conf.rxmode.jumbo_frame = 1;
	    port_conf.rxmode.max_rx_pkt_len = format_data->snaplen;
	}

	/* This is additional overhead so make sure we allow space for this */
#if GET_MAC_CRC_CHECKSUM
	format_data->snaplen += ETHER_CRC_LEN;
#endif
#if HAS_HW_TIMESTAMPS_82580
	format_data->snaplen += sizeof(struct hw_timestamp_82580);
#endif

	/* Create the mbuf pool, which is the place our packets are allocated
	 * from - TODO figure out if there is is a free function (I cannot see one)
	 * NOTE: RX queue requires nb_packets + 1 otherwise it fails to
	 * allocate however that extra 1 packet is not used.
	 * (I assume <= vs < error some where in DPDK code)
	 * TX requires nb_tx_buffers + 1 in the case the queue is full
	 * so that will fill the new buffer and wait until slots in the
	 * ring become available.
	 */
#if DEBUG
    fprintf(stderr, "Creating mempool named %s\n", format_data->mempool_name);
#endif
    format_data->pktmbuf_pool =
	    rte_mempool_create(format_data->mempool_name,
		       (format_data->nb_rx_buf + format_data->nb_tx_buf + 1),
		       format_data->snaplen + sizeof(struct rte_mbuf)
					+ RTE_PKTMBUF_HEADROOM,
		       128, sizeof(struct rte_pktmbuf_pool_private),
		       rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL,
		       cpu_numa_node, 0/*MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET*/);

    if (format_data->pktmbuf_pool == NULL) {
	    snprintf(err, errlen, "Intel DPDK - Initialisation of mbuf"
			"pool failed: %s NODE %u", strerror(rte_errno), cpu_numa_node);
	    return -1;
	}
    }

    /* ----------- Now do the setup for the port mapping ------------ */
    /* Order of calls must be
     * rte_eth_dev_configure()
     * rte_eth_tx_queue_setup()
     * rte_eth_rx_queue_setup()
     * rte_eth_dev_start()
     * other rte_eth calls
     */


    port_conf.rx_adv_conf.rss_conf.rss_key = format_data->rss_key;

    /* This must be called first before another *eth* function
     * 1 rx, 1 tx queue, port_conf sets checksum stripping etc */
    ret = rte_eth_dev_configure(format_data->port, 1, 1, &port_conf);
    if (ret < 0) {
	snprintf(err, errlen, "Intel DPDK - Cannot configure device port"
			    " %"PRIu8" : %s", format_data->port,
			    strerror(-ret));
	return -1;
    }
    /* Initialise the TX queue a minimum value if using this port for
     * receiving. Otherwise a larger size if writing packets.
     */
    ret = rte_eth_tx_queue_setup(format_data->port, format_data->queue_id,
			format_data->nb_tx_buf, SOCKET_ID_ANY, &tx_conf);
    if (ret < 0) {
	snprintf(err, errlen, "Intel DPDK - Cannot configure TX queue on port"
			    " %"PRIu8" : %s", format_data->port,
			    strerror(-ret));
	return -1;
    }
    /* Initialise the RX queue with some packets from memory */
    ret = rte_eth_rx_queue_setup(format_data->port, format_data->queue_id,
                                 format_data->nb_rx_buf, cpu_numa_node,
                                 &rx_conf, format_data->pktmbuf_pool);
    if (ret < 0) {
	snprintf(err, errlen, "Intel DPDK - Cannot configure RX queue on port"
		    " %"PRIu8" : %s", format_data->port,
		    strerror(-ret));
	return -1;
    }

    /* Start device */
    ret = rte_eth_dev_start(format_data->port);
    if (ret < 0) {
	snprintf(err, errlen, "Intel DPDK - rte_eth_dev_start failed : %s",
		    strerror(-ret));
	return -1;
    }

    /* Default promiscuous to on */
    if (format_data->promisc == -1)
	format_data->promisc = 1;

    if (format_data->promisc == 1)
	rte_eth_promiscuous_enable(format_data->port);
    else
	rte_eth_promiscuous_disable(format_data->port);

	/* Register a callback for link state changes */
	ret = rte_eth_dev_callback_register(format_data->port,
	                                    RTE_ETH_EVENT_INTR_LSC,
	                                    dpdk_lsc_callback,
	                                    format_data);
	/* If this fails it is not a show stopper */
#if DEBUG
	fprintf(stderr, "rte_eth_dev_callback_register failed %d : %s\n",
	        ret, strerror(-ret));
#endif

    /* Get the current link status */
    rte_eth_link_get_nowait(format_data->port, &link_info);
    format_data->link_speed = link_info.link_speed;
#if DEBUG
    fprintf(stderr, "Link status is %d %d %d\n", (int) link_info.link_status,
	    (int) link_info.link_duplex, (int) link_info.link_speed);
#endif
    /* We have now successfully started/unpaused */
    format_data->paused = DPDK_RUNNING;

    return 0;
}

/* Attach memory to the port and start (or restart) the port/s.
 */
static int dpdk_start_port_queues (struct dpdk_format_data_t *format_data, char *err, int errlen, uint16_t rx_queues) {
    int ret, i; /* Check return values for errors */
    struct rte_eth_link link_info; /* Wait for link */

    /* Already started */
    if (format_data->paused == DPDK_RUNNING)
	return 0;

    /* First time started we need to alloc our memory, doing this here
     * rather than in environment setup because we don't have snaplen then */
    if (format_data->paused == DPDK_NEVER_STARTED) {
	if (format_data->snaplen == 0) {
	    format_data->snaplen = RX_MBUF_SIZE;
	    port_conf.rxmode.jumbo_frame = 0;
	    port_conf.rxmode.max_rx_pkt_len = 0;
	} else {
	    /* Use jumbo frames */
	    port_conf.rxmode.jumbo_frame = 1;
	    port_conf.rxmode.max_rx_pkt_len = format_data->snaplen;
	}

	/* This is additional overhead so make sure we allow space for this */
#if GET_MAC_CRC_CHECKSUM
	format_data->snaplen += ETHER_CRC_LEN;
#endif
#if HAS_HW_TIMESTAMPS_82580
	format_data->snaplen += sizeof(struct hw_timestamp_82580);
#endif

	/* Create the mbuf pool, which is the place our packets are allocated
	 * from - TODO figure out if there is a free function (I cannot see one)
	 * NOTE: RX queue requires nb_packets + 1 otherwise it fails to
	 * allocate however that extra 1 packet is not used.
	 * (I assume <= vs < error some where in DPDK code)
	 * TX requires nb_tx_buffers + 1 in the case the queue is full
	 * so that will fill the new buffer and wait until slots in the
	 * ring become available.
	 */
#if DEBUG
    fprintf(stderr, "Creating mempool named %s\n", format_data->mempool_name);
#endif
    format_data->pktmbuf_pool =
	    rte_mempool_create(format_data->mempool_name,
		       (format_data->nb_rx_buf * rx_queues + format_data->nb_tx_buf + 1)*2,
		       format_data->snaplen + sizeof(struct rte_mbuf)
					+ RTE_PKTMBUF_HEADROOM,
		       128, sizeof(struct rte_pktmbuf_pool_private),
		       rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL,
		       format_data->nic_numa_node, 0);

	if (format_data->pktmbuf_pool == NULL) {
	    snprintf(err, errlen, "Intel DPDK - Initialisation of mbuf "
			"pool failed: %s", strerror(rte_errno));
	    return -1;
	}
    }

    /* ----------- Now do the setup for the port mapping ------------ */
    /* Order of calls must be
     * rte_eth_dev_configure()
     * rte_eth_tx_queue_setup()
     * rte_eth_rx_queue_setup()
     * rte_eth_dev_start()
     * other rte_eth calls
     */

    /* This must be called first before another *eth* function
     * 1 rx, 1 tx queue, port_conf sets checksum stripping etc */
    ret = rte_eth_dev_configure(format_data->port, rx_queues, 1, &port_conf);
    if (ret < 0) {
	snprintf(err, errlen, "Intel DPDK - Cannot configure device port"
			    " %"PRIu8" : %s", format_data->port,
			    strerror(-ret));
	return -1;
    }
#if DEBUG
    fprintf(stderr, "Doing dev configure\n");
#endif
    /* Initialise the TX queue a minimum value if using this port for
     * receiving. Otherwise a larger size if writing packets.
     */
    ret = rte_eth_tx_queue_setup(format_data->port, format_data->queue_id,
			format_data->nb_tx_buf, SOCKET_ID_ANY, &tx_conf);
    if (ret < 0) {
	snprintf(err, errlen, "Intel DPDK - Cannot configure TX queue on port"
			    " %"PRIu8" : %s", format_data->port,
			    strerror(-ret));
	return -1;
    }

    for (i=0; i < rx_queues; i++) {
#if DEBUG
    fprintf(stderr, "Doing queue configure\n");
#endif

		/* Initialise the RX queue with some packets from memory */
		ret = rte_eth_rx_queue_setup(format_data->port, i,
		                             format_data->nb_rx_buf, format_data->nic_numa_node,
		                             &rx_conf, format_data->pktmbuf_pool);
	/* Init per_thread data structures */
	format_data->per_lcore[i].port = format_data->port;
	format_data->per_lcore[i].queue_id = i;

		if (ret < 0) {
			snprintf(err, errlen, "Intel DPDK - Cannot configure RX queue on port"
						" %"PRIu8" : %s", format_data->port,
						strerror(-ret));
			return -1;
		}
	}

#if DEBUG
    fprintf(stderr, "Doing start device\n");
#endif
    /* Start device */
    ret = rte_eth_dev_start(format_data->port);
#if DEBUG
    fprintf(stderr, "Done start device\n");
#endif
    if (ret < 0) {
	snprintf(err, errlen, "Intel DPDK - rte_eth_dev_start failed : %s",
		    strerror(-ret));
	return -1;
    }


    /* Default promiscuous to on */
    if (format_data->promisc == -1)
	format_data->promisc = 1;

    if (format_data->promisc == 1)
	rte_eth_promiscuous_enable(format_data->port);
    else
	rte_eth_promiscuous_disable(format_data->port);


    /* We have now successfully started/unpased */
    format_data->paused = DPDK_RUNNING;

    // Can use remote launch for all
    /*RTE_LCORE_FOREACH_SLAVE(i) {
		rte_eal_remote_launch(perpkt_threads_entry, (void *)libtrace, i);
	}*/

    /* Register a callback for link state changes */
    ret = rte_eth_dev_callback_register(format_data->port,
                                        RTE_ETH_EVENT_INTR_LSC,
                                        dpdk_lsc_callback,
                                        format_data);
    /* If this fails it is not a show stopper */
#if DEBUG
    fprintf(stderr, "rte_eth_dev_callback_register failed %d : %s\n",
            ret, strerror(-ret));
#endif

    /* Get the current link status */
    rte_eth_link_get_nowait(format_data->port, &link_info);
    format_data->link_speed = link_info.link_speed;
#if DEBUG
    fprintf(stderr, "Link status is %d %d %d\n", (int) link_info.link_status,
	    (int) link_info.link_duplex, (int) link_info.link_speed);
	struct rte_eth_rss_reta reta_conf = {0};
	reta_conf.mask_lo = ~reta_conf.mask_lo;
	reta_conf.mask_hi = ~reta_conf.mask_hi;
	int qew = rte_eth_dev_rss_reta_query(format_data->port, &reta_conf);
	fprintf(stderr, "err=%d", qew);
	for (i = 0; i < ETH_RSS_RETA_NUM_ENTRIES; i++) {
		fprintf(stderr, "[%d] = %d\n", i, (int)reta_conf.reta[i]);
	}

#endif

    return 0;
}

static int dpdk_start_input (libtrace_t *libtrace) {
    char err[500];
    err[0] = 0;

    if (dpdk_start_port(FORMAT(libtrace), err, sizeof(err)) != 0) {
	trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err);
	free(libtrace->format_data);
	libtrace->format_data = NULL;
	return -1;
    }
    return 0;
}

static inline size_t dpdk_get_max_rx_queues (uint8_t port_id) {
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port_id, &dev_info);
    return dev_info.max_rx_queues;
}

static inline size_t dpdk_processor_count () {
    long nb_cpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (nb_cpu <= 0)
	return 1;
    else
	return (size_t) nb_cpu;
}

static int dpdk_pstart_input (libtrace_t *libtrace) {
    char err[500];
    int i=0, phys_cores=0;
    int tot = libtrace->perpkt_thread_count;
    err[0] = 0;

    if (rte_lcore_id() != rte_get_master_lcore())
	fprintf(stderr, "Warning dpdk_pstart_input should be called from the master DPDK thread!\n");

    // If the master is not on the last thread we move it there
    if (rte_get_master_lcore() != RTE_MAX_LCORE - 1) {
	// Consider error handling here
	dpdk_move_master_lcore(RTE_MAX_LCORE - 1);
    }

    // Don't exceed the number of cores in the system/detected by dpdk
    // We don't have to force this but performance wont be good if we don't
    for (i = 0; i < RTE_MAX_LCORE; ++i) {
	if (lcore_config[i].detected) {
	    if (rte_lcore_is_enabled(i))
		fprintf(stderr, "Found core %d already in use!\n", i);
	    else
		phys_cores++;
	}
    }

	tot = MIN(libtrace->perpkt_thread_count, dpdk_get_max_rx_queues(FORMAT(libtrace)->port));
	tot = MIN(tot, phys_cores);

	fprintf(stderr, "Running pstart DPDK tot=%d req=%d phys=%d\n", tot, libtrace->perpkt_thread_count, phys_cores);

    if (dpdk_start_port_queues(FORMAT(libtrace), err, sizeof(err), tot) != 0) {
	trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err);
	free(libtrace->format_data);
	libtrace->format_data = NULL;
	return -1;
    }

    // Make sure we only start the number that we should
    libtrace->perpkt_thread_count = tot;
    return 0;
}


/**
 * Register a thread with the DPDK system,
 * When we start DPDK in parallel libtrace we move the 'main thread' to the
 * MAXIMUM CPU core slot (32) and remove any affinity restrictions DPDK
 * gives it.
 *
 * We then allow a mapper thread to be started on every real core as DPDK would,
 * we also bind these to the corresponding CPU cores.
 *
 * @param libtrace A pointer to the trace
 * @param reading True if the thread will be used to read packets, i.e. will
 *                call pread_packet(), false if thread used to process packet
 *                in any other manner including statistics functions.
 */
static int dpdk_pregister_thread(libtrace_t *libtrace, libtrace_thread_t *t, bool reading)
{
    struct rte_config *cfg = rte_eal_get_configuration();
    int i;
    int new_id = -1;

    // If 'reading packets' fill in cores from 0 up and bind affinity
    // otherwise start from the MAX core (which is also the master) and work backwards
    // in this case physical cores on the system will not exist so we don't bind
    // these to any particular physical core
    pthread_mutex_lock(&libtrace->libtrace_lock);
    if (reading) {
#if HAVE_LIBNUMA
	for (i = 0; i < RTE_MAX_LCORE; ++i) {
		if (!rte_lcore_is_enabled(i) && numa_node_of_cpu(i) == FORMAT(libtrace)->nic_numa_node) {
				new_id = i;
			if (!lcore_config[i].detected)
				new_id = -1;
			break;
		}
	}
#endif
	/* Retry without the the numa restriction */
	if (new_id == -1) {
		for (i = 0; i < RTE_MAX_LCORE; ++i) {
				if (!rte_lcore_is_enabled(i)) {
					new_id = i;
				if (!lcore_config[i].detected)
					fprintf(stderr, "Warning the number of 'reading' threads exceed cores on machine!!\n");
				break;
			}
		}
	}
    } else {
	for (i = RTE_MAX_LCORE-1; i >= 0; --i) {
	    if (!rte_lcore_is_enabled(i)) {
		new_id = i;
		break;
	    }
	}
    }

    if (new_id == -1) {
	assert(cfg->lcore_count == RTE_MAX_LCORE);
	// TODO proper libtrace style error here!!
	fprintf(stderr, "Too many threads for DPDK!!\n");
	pthread_mutex_unlock(&libtrace->libtrace_lock);
	return -1;
    }

    // Enable the core in global DPDK structs
    cfg->lcore_role[new_id] = ROLE_RTE;
    cfg->lcore_count++;
    // Set TLS to reflect our new number
    assert(rte_lcore_id() == 0); // I think new threads are going get a default thread number of 0
    fprintf(stderr, "original id%d", rte_lcore_id());
    RTE_PER_LCORE(_lcore_id) = new_id;
	char name[99];
	pthread_getname_np(pthread_self(),
			      name, sizeof(name));

    fprintf(stderr, "%s new id%d\n", name, rte_lcore_id());

    if (reading) {
	// Set affinity bind to corresponding core
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(rte_lcore_id(), &cpuset);
	i = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
	if (i != 0) {
	    fprintf(stderr, "Warning pthread_setaffinity_np failed\n");
	    pthread_mutex_unlock(&libtrace->libtrace_lock);
	    return -1;
	}
    }

    // Map our TLS to the thread data
    if (reading) {
	if(t->type == THREAD_PERPKT) {
	    t->format_data = &FORMAT(libtrace)->per_lcore[t->perpkt_num];
	} else {
	    t->format_data = &FORMAT(libtrace)->per_lcore[0];
	}
    }
    pthread_mutex_unlock(&libtrace->libtrace_lock);
    return 0;
}


/**
 * Unregister a thread with the DPDK system.
 *
 * Only previously registered threads should be calling this just before
 * they are destroyed.
 */
static void dpdk_punregister_thread(libtrace_t *libtrace UNUSED, libtrace_thread_t *t UNUSED)
{
    struct rte_config *cfg = rte_eal_get_configuration();

    assert(rte_lcore_id() < RTE_MAX_LCORE);
    pthread_mutex_lock(&libtrace->libtrace_lock);
    // Skip if master!!
    if (rte_lcore_id() == rte_get_master_lcore()) {
	fprintf(stderr, "INFO: we are skipping unregistering the master lcore\n");
	pthread_mutex_unlock(&libtrace->libtrace_lock);
	return;
    }

    // Disable this core in global DPDK structs
    cfg->lcore_role[rte_lcore_id()] = ROLE_OFF;
    cfg->lcore_count--;
    RTE_PER_LCORE(_lcore_id) = -1; // Might make the world burn if used again
    assert(cfg->lcore_count >= 1); // We cannot unregister the master LCORE!!
    pthread_mutex_unlock(&libtrace->libtrace_lock);
    return;
}

static int dpdk_start_output(libtrace_out_t *libtrace)
{
    char err[500];
    err[0] = 0;

    if (dpdk_start_port(FORMAT(libtrace), err, sizeof(err)) != 0) {
	trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "%s", err);
	free(libtrace->format_data);
	libtrace->format_data = NULL;
	return -1;
    }
    return 0;
}

static int dpdk_pause_input(libtrace_t * libtrace) {
    /* This stops the device, but can be restarted using rte_eth_dev_start() */
    if (FORMAT(libtrace)->paused == DPDK_RUNNING) {
#if DEBUG
	fprintf(stderr, "Pausing DPDK port\n");
#endif
	rte_eth_dev_stop(FORMAT(libtrace)->port);
	FORMAT(libtrace)->paused = DPDK_PAUSED;
	/* Empty the queue of packets */
	for (; FORMAT(libtrace)->burst_offset < FORMAT(libtrace)->burst_size; ++FORMAT(libtrace)->burst_offset) {
		rte_pktmbuf_free(FORMAT(libtrace)->burst_pkts[FORMAT(libtrace)->burst_offset]);
	}
	FORMAT(libtrace)->burst_offset = 0;
	FORMAT(libtrace)->burst_size = 0;
	/* If we pause it the driver will be reset and likely our counter */

	FORMAT(libtrace)->per_lcore[0].ts_last_sys = 0;
#if HAS_HW_TIMESTAMPS_82580
	FORMAT(libtrace)->per_lcore[0].ts_first_sys = 0;
#endif
    }
    return 0;
}

static int dpdk_write_packet(libtrace_out_t *trace,
		libtrace_packet_t *packet){
    struct rte_mbuf* m_buff[1];

    int wirelen = trace_get_wire_length(packet);
    int caplen = trace_get_capture_length(packet);

    /* Check for a checksum and remove it */
    if (trace_get_link_type(packet) == TRACE_TYPE_ETH &&
					    wirelen == caplen)
	caplen -= ETHER_CRC_LEN;

    m_buff[0] = rte_pktmbuf_alloc(FORMAT(trace)->pktmbuf_pool);
    if (m_buff[0] == NULL) {
	trace_set_err_out(trace, errno, "Cannot get an empty packet buffer");
	return -1;
    } else {
	int ret;
	memcpy(rte_pktmbuf_append(m_buff[0], caplen), packet->payload, caplen);
	do {
	    ret = rte_eth_tx_burst(FORMAT(trace)->queue_id, FORMAT(trace)->port, m_buff, 1);
	} while (ret != 1);
    }

    return 0;
}

static int dpdk_fin_input(libtrace_t * libtrace) {
    /* Free our memory structures */
    if (libtrace->format_data != NULL) {
	/* Close the device completely, device cannot be restarted */
	if (FORMAT(libtrace)->port != 0xFF)
		rte_eth_dev_callback_unregister(FORMAT(libtrace)->port,
		                                RTE_ETH_EVENT_INTR_LSC,
		                                dpdk_lsc_callback,
		                                FORMAT(libtrace));
		rte_eth_dev_close(FORMAT(libtrace)->port);
		/* filter here if we used it */
		free(libtrace->format_data);
	}

    /* Revert to the original PCI drivers */
    /* No longer in DPDK
    rte_eal_pci_exit(); */
    return 0;
}


static int dpdk_fin_output(libtrace_out_t * libtrace) {
    /* Free our memory structures */
    if (libtrace->format_data != NULL) {
	/* Close the device completely, device cannot be restarted */
	if (FORMAT(libtrace)->port != 0xFF)
	    rte_eth_dev_close(FORMAT(libtrace)->port);
	/* filter here if we used it */
		free(libtrace->format_data);
	}

    /* Revert to the original PCI drivers */
    /* No longer in DPDK
    rte_eal_pci_exit(); */
    return 0;
}

/**
 * Get the start of the additional header that we added to a packet.
 */
static inline struct dpdk_addt_hdr * get_addt_hdr (const libtrace_packet_t *packet) {
    assert(packet);
    assert(packet->buffer);
    /* Our header sits straight after the mbuf header */
    return (struct dpdk_addt_hdr *) ((struct rte_mbuf*) packet->buffer + 1);
}

static int dpdk_get_capture_length (const libtrace_packet_t *packet) {
    struct dpdk_addt_hdr * hdr = get_addt_hdr(packet);
    return hdr->cap_len;
}

static size_t dpdk_set_capture_length(libtrace_packet_t *packet, size_t size) {
    struct dpdk_addt_hdr * hdr = get_addt_hdr(packet);
    if (size > hdr->cap_len) {
	/* Cannot make a packet bigger */
		return trace_get_capture_length(packet);
	}

    /* Reset the cached capture length first*/
    packet->capture_length = -1;
    hdr->cap_len = (uint32_t) size;
	return trace_get_capture_length(packet);
}

static int dpdk_get_wire_length (const libtrace_packet_t *packet) {
    struct dpdk_addt_hdr * hdr = get_addt_hdr(packet);
    int org_cap_size; /* The original capture size */
    if (hdr->flags & INCLUDES_HW_TIMESTAMP) {
	org_cap_size = (int) rte_pktmbuf_pkt_len(MBUF(packet->buffer)) -
			    sizeof(struct hw_timestamp_82580);
    } else {
	org_cap_size = (int) rte_pktmbuf_pkt_len(MBUF(packet->buffer));
    }
    if (hdr->flags & INCLUDES_CHECKSUM) {
	return org_cap_size;
    } else {
	/* DPDK packets are always TRACE_TYPE_ETH packets */
	return org_cap_size + ETHER_CRC_LEN;
    }
}
static int dpdk_get_framing_length (const libtrace_packet_t *packet) {
    struct dpdk_addt_hdr * hdr = get_addt_hdr(packet);
    if (hdr->flags & INCLUDES_HW_TIMESTAMP)
	return sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM +
		sizeof(struct hw_timestamp_82580);
    else
	return sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;
}

static int dpdk_prepare_packet(libtrace_t *libtrace UNUSED,
		libtrace_packet_t *packet, void *buffer,
		libtrace_rt_types_t rt_type, uint32_t flags) {
    assert(packet);
    if (packet->buffer != buffer &&
	packet->buf_control == TRACE_CTRL_PACKET) {
	free(packet->buffer);
    }

    if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER) {
	packet->buf_control = TRACE_CTRL_PACKET;
    } else
	packet->buf_control = TRACE_CTRL_EXTERNAL;

    packet->buffer = buffer;
    packet->header = buffer;

    /* Don't use pktmbuf_mtod will fail if the packet is a copy */
    packet->payload = (char *)buffer + dpdk_get_framing_length(packet);
    packet->type = rt_type;
    return 0;
}


/**
 * Given a packet size and a link speed, computes the
 * time to transmit in nanoseconds.
 *
 * @param format_data The dpdk format data from which we get the link speed
 *        and if unset updates it in a thread safe manner
 * @param pkt_size The size of the packet in bytes
 * @return The wire time in nanoseconds
 */
static inline uint32_t calculate_wire_time(struct dpdk_format_data_t* format_data, uint32_t pkt_size) {
	uint32_t wire_time;
	/* 20 extra bytes of interframe gap and preamble */
# if GET_MAC_CRC_CHECKSUM
	wire_time = ((pkt_size + 20) * 8000);
# else
	wire_time = ((pkt_size + 20 + ETHER_CRC_LEN) * 8000);
# endif

	/* Division is really slow and introduces a pipeline stall
	 * The compiler will optimise this into magical multiplication and shifting
	 * See http://ridiculousfish.com/blog/posts/labor-of-division-episode-i.html
	 */
retry_calc_wiretime:
	switch (format_data->link_speed) {
	case ETH_LINK_SPEED_40G:
		wire_time /=  ETH_LINK_SPEED_40G;
		break;
	case ETH_LINK_SPEED_20G:
		wire_time /= ETH_LINK_SPEED_20G;
		break;
	case ETH_LINK_SPEED_10G:
		wire_time /= ETH_LINK_SPEED_10G;
		break;
	case ETH_LINK_SPEED_1000:
		wire_time /= ETH_LINK_SPEED_1000;
		break;
	case 0:
		{
		/* Maybe the link was down originally, but now it should be up */
		struct rte_eth_link link = {0};
		rte_eth_link_get_nowait(format_data->port, &link);
		if (link.link_status && link.link_speed) {
			format_data->link_speed = link.link_speed;
#ifdef DEBUG
			fprintf(stderr, "Link has come up updated speed=%d\n", (int) link.link_speed);
#endif
			goto retry_calc_wiretime;
		}
		/* We don't know the link speed, make sure numbers are counting up */
		wire_time = 1;
		break;
		}
	default:
		wire_time /= format_data->link_speed;
	}
	return wire_time;
}



/*
 * Does any extra preperation to all captured packets
 * This includes adding our extra header to it with the timestamp,
 * and any snapping
 *
 * @param format_data The DPDK format data
 * @param plc The DPDK per lcore format data
 * @param pkts An array of size nb_pkts of DPDK packets
 * @param nb_pkts The number of packets in pkts and optionally packets
 * @param packets Optional - If not null nb_pkts of libtrace packets which will be prepared
 */
static inline void dpdk_ready_pkts(struct dpdk_format_data_t *format_data, struct dpdk_per_lcore_t *plc,
                                   struct rte_mbuf **pkts, size_t nb_pkts, libtrace_packet_t **packets) {
	struct dpdk_addt_hdr *hdr;
	size_t i;
	uint64_t cur_sys_time_ns;
#if HAS_HW_TIMESTAMPS_82580
	struct hw_timestamp_82580 *hw_ts;
	uint64_t estimated_wraps;
#else

#endif

#if USE_CLOCK_GETTIME
	struct timespec cur_sys_time = {0};
	/* This looks terrible and I feel bad doing it. But it's OK
	 * on new kernels, because this is a fast vsyscall */
	clock_gettime(CLOCK_REALTIME, &cur_sys_time);
	cur_sys_time_ns = TS_TO_NS(cur_sys_time);
#else
	struct timeval cur_sys_time = {0};
	/* Also a fast vsyscall */
	gettimeofday(&cur_sys_time, NULL);
	cur_sys_time_ns = TV_TO_NS(cur_sys_time);
#endif

	/* The system clock is not perfect so when running
	 * at linerate we could timestamp a packet in the past.
	 * To avoid this we munge the timestamp to appear 1ns
	 * after the previous packet. We should eventually catch up
	 * to system time since a 64byte packet on a 10G link takes 67ns.
	 *
	 * Note with parallel readers timestamping packets
	 * with duplicate stamps or out of order is unavoidable without
	 * hardware timestamping from the NIC.
	 */
#if !HAS_HW_TIMESTAMPS_82580
	if (plc->ts_last_sys >= cur_sys_time_ns) {
		cur_sys_time_ns = plc->ts_last_sys + 1;
	}
#endif

	assert(RTE_PKTMBUF_HEADROOM >= sizeof(struct dpdk_addt_hdr)); // TODO static compile time assert sometime??
	for (i = 0 ; i < nb_pkts ; ++i) {

		/* We put our header straight after the dpdk header */
		hdr = (struct dpdk_addt_hdr *) (pkts[i] + 1);
		memset(hdr, 0, sizeof(struct dpdk_addt_hdr));

#if GET_MAC_CRC_CHECKSUM
<<<<<<< HEAD
		/* Add back in the CRC sum */
		pkts[i]->pkt.pkt_len += ETHER_CRC_LEN;
		pkts[i]->pkt.data_len += ETHER_CRC_LEN;
		hdr->flags |= INCLUDES_CHECKSUM;
=======
    /* Add back in the CRC sum */
    rte_pktmbuf_pkt_len(pkt) += ETHER_CRC_LEN;
    rte_pktmbuf_data_len(pkt) += ETHER_CRC_LEN;
    hdr->flags |= INCLUDES_CHECKSUM;
>>>>>>> master
#endif

		hdr->cap_len = rte_pktmbuf_pkt_len(pkts[i]);

#if HAS_HW_TIMESTAMPS_82580
		/* The timestamp is sitting before our packet and is included in pkt_len */
		hdr->flags |= INCLUDES_HW_TIMESTAMP;
		hdr->cap_len -= sizeof(struct hw_timestamp_82580);
		hw_ts = (struct hw_timestamp_82580 *) MBUF_PKTDATA(pkts[i]);

		/* Taken from igb_ptp.c part of Intel Linux drivers (Good example code)
		 *
		 *        +----------+---+   +--------------+
		 *  82580 |    24    | 8 |   |      32      |
		 *        +----------+---+   +--------------+
		 *          reserved  \______ 40 bits _____/
		 *
		 * The 40 bit 82580 SYSTIM overflows every
		 *   2^40 * 10^-9 /  60  = 18.3 minutes.
		 *
		 * NOTE picture is in Big Endian order, in memory it's acutally in Little
		 * Endian (for the full 64 bits) i.e. picture is mirrored
		 */

		/* Despite what the documentation says this is in Little
		 * Endian byteorder. Mask the reserved section out.
		 */
		hdr->timestamp = le64toh(hw_ts->timestamp) &
			~(((~0ull)>>TS_NBITS_82580)<<TS_NBITS_82580);

		if (unlikely(plc->ts_first_sys == 0)) {
			plc->ts_first_sys = cur_sys_time_ns - hdr->timestamp;
			plc->ts_last_sys = plc->ts_first_sys;
		}

		/* This will have serious problems if packets aren't read quickly
		 * that is within a couple of seconds because our clock cycles every
		 * 18 seconds */
		estimated_wraps = (cur_sys_time_ns - plc->ts_last_sys)
		                  / (1ull<<TS_NBITS_82580);

		/* Estimated_wraps gives the number of times the counter should have
		 * wrapped (however depending on value last time it could have wrapped
		 * twice more (if hw clock is close to its max value) or once less (allowing
		 * for a bit of variance between hw and sys clock). But if the clock
		 * shouldn't have wrapped once then don't allow it to go backwards in time */
		if (unlikely(estimated_wraps >= 2)) {
			/* 2 or more wrap arounds add all but the very last wrap */
			plc->wrap_count += estimated_wraps - 1;
		}

		/* Set the timestamp to the lowest possible value we're considering */
		hdr->timestamp += plc->ts_first_sys +
		                  plc->wrap_count * (1ull<<TS_NBITS_82580);

		/* In most runs only the first if() will need evaluating - i.e our
		 * estimate is correct. */
		if (unlikely(!WITHIN_VARIANCE(cur_sys_time_ns,
		                              hdr->timestamp, MAXSKEW_82580))) {
			/* Failed to match estimated_wraps-1 (or estimated_wraps in ==0 case) */
			plc->wrap_count++;
			hdr->timestamp += (1ull<<TS_NBITS_82580);
			if (!WITHIN_VARIANCE(cur_sys_time_ns,
			                     hdr->timestamp, MAXSKEW_82580)) {
				/* Failed to match estimated_wraps */
				plc->wrap_count++;
				hdr->timestamp += (1ull<<TS_NBITS_82580);
				if (!WITHIN_VARIANCE(cur_sys_time_ns,
				                     hdr->timestamp, MAXSKEW_82580)) {
					if (estimated_wraps == 0) {
						/* 0 case Failed to match estimated_wraps+2 */
						printf("WARNING - Hardware Timestamp failed to"
						       " match using systemtime!\n");
						hdr->timestamp = cur_sys_time_ns;
					} else {
						/* Failed to match estimated_wraps+1 */
						plc->wrap_count++;
						hdr->timestamp += (1ull<<TS_NBITS_82580);
						if (!WITHIN_VARIANCE(cur_sys_time_ns,
						                     hdr->timestamp, MAXSKEW_82580)) {
							/* Failed to match estimated_wraps+2 */
							printf("WARNING - Hardware Timestamp failed to"
							       " match using systemtime!!\n");
						}
					}
				}
			}
		}
#else

		hdr->timestamp = cur_sys_time_ns;
		/* Offset the next packet by the wire time of previous */
		calculate_wire_time(format_data, hdr->cap_len);

#endif
		if(packets) {
			packets[i]->buffer = pkts[i];
			packets[i]->header = pkts[i];
#if HAS_HW_TIMESTAMPS_82580
			packets[i]->payload = (char *) pkts[i] + sizeof(struct rte_mbuf) +
			                      RTE_PKTMBUF_HEADROOM + sizeof(struct hw_timestamp_82580);
#else
			packets[i]->payload = (char *) pkts[i] + sizeof(struct rte_mbuf) +
			                      RTE_PKTMBUF_HEADROOM;
#endif
			packets[i]->error = 1;
		}
	}

	plc->ts_last_sys = cur_sys_time_ns;

	return;
}


static void dpdk_fin_packet(libtrace_packet_t *packet)
{
	if ( packet->buf_control == TRACE_CTRL_EXTERNAL ) {
		rte_pktmbuf_free(packet->buffer);
		packet->buffer = NULL;
	}
}


static int dpdk_read_packet (libtrace_t *libtrace, libtrace_packet_t *packet) {
    int nb_rx; /* Number of rx packets we've received */

    /* Free the last packet buffer */
    if (packet->buffer != NULL) {
	/* Buffer is owned by DPDK */
	if ( packet->buf_control == TRACE_CTRL_EXTERNAL ) {
	    rte_pktmbuf_free(packet->buffer);
	    packet->buffer = NULL;
	} else
	/* Buffer is owned by packet i.e. has been malloc'd */
	if (packet->buf_control == TRACE_CTRL_PACKET) {
	    free(packet->buffer);
	    packet->buffer = NULL;
	}
    }

    packet->buf_control = TRACE_CTRL_EXTERNAL;
    packet->type = TRACE_RT_DATA_DPDK;

    /* Check if we already have some packets buffered */
    if (FORMAT(libtrace)->burst_size != FORMAT(libtrace)->burst_offset) {
	    packet->buffer =  FORMAT(libtrace)->burst_pkts[FORMAT(libtrace)->burst_offset++];
	    dpdk_prepare_packet(libtrace, packet, packet->buffer, packet->type, 0);
	    return 1; // TODO should be bytes read, which essentially useless anyway
    }
    /* Wait for a packet */
    while (1) {
	/* Poll for a single packet */
	nb_rx = rte_eth_rx_burst(FORMAT(libtrace)->port,
	                         FORMAT(libtrace)->queue_id, FORMAT(libtrace)->burst_pkts, BURST_SIZE);
	if (nb_rx > 0) { /* Got a packet - otherwise we keep spining */
		FORMAT(libtrace)->burst_size = nb_rx;
		FORMAT(libtrace)->burst_offset = 1;
		dpdk_ready_pkts(FORMAT(libtrace), &FORMAT(libtrace)->per_lcore[0], FORMAT(libtrace)->burst_pkts, nb_rx, NULL);
		packet->buffer = FORMAT(libtrace)->burst_pkts[0];
		dpdk_prepare_packet(libtrace, packet, packet->buffer, packet->type, 0);
		return 1; // TODO should be bytes read, which essentially useless anyway
	}
	if (libtrace_halt) {
		return 0;
	}
	/* Wait a while, polling on memory degrades performance
	 * This relieves the pressure on memory allowing the NIC to DMA */
	rte_delay_us(10);
    }

    /* We'll never get here - but if we did it would be bad */
    return -1;
}

static int dpdk_pread_packets (libtrace_t *libtrace, libtrace_thread_t *t, libtrace_packet_t **packets, size_t nb_packets) {
    size_t nb_rx; /* Number of rx packets we've recevied */
    struct rte_mbuf* pkts_burst[nb_packets]; /* Array of pointer(s) */
    size_t i;

    for (i = 0 ; i < nb_packets ; ++i) {
	    /* Free the last packet buffer */
	    if (packets[i]->buffer != NULL) {
		/* Buffer is owned by DPDK */
		if (packets[i]->buf_control == TRACE_CTRL_EXTERNAL) {
		    rte_pktmbuf_free(packets[i]->buffer);
		    packets[i]->buffer = NULL;
		} else
		/* Buffer is owned by packet i.e. has been malloc'd */
		if (packets[i]->buf_control == TRACE_CTRL_PACKET) {
		    free(packets[i]->buffer);
		    packets[i]->buffer = NULL;
		}
	    }
	    packets[i]->buf_control = TRACE_CTRL_EXTERNAL;
	    packets[i]->type = TRACE_RT_DATA_DPDK;
    }

    /* Wait for a packet */
    while (1) {
	/* Poll for a single packet */
	nb_rx = rte_eth_rx_burst(PERPKT_FORMAT(t)->port,
			    PERPKT_FORMAT(t)->queue_id, pkts_burst, nb_packets);
	if (nb_rx > 0) {
		/* Got some packets - otherwise we keep spining */
		//fprintf(stderr, "Doing P READ PACKET port=%d q=%d\n", (int) FORMAT(libtrace)->port, (int) get_thread_table_num(libtrace));
		dpdk_ready_pkts(FORMAT(libtrace), PERPKT_FORMAT(t), pkts_burst, nb_rx, packets);
		return nb_rx;
	}
	// Check the message queue this could be (Well it shouldn't but anyway) be less than 0
	if (libtrace_message_queue_count(&t->messages) > 0) {
		printf("Extra message yay");
		return -2;
	}
	if (libtrace_halt) {
		return 0;
	}
	/* Wait a while, polling on memory degrades performance
	 * This relieves the pressure on memory allowing the NIC to DMA */
	rte_delay_us(10);
    }

    /* We'll never get here - but if we did it would be bad */
    return -1;
}

static struct timeval dpdk_get_timeval (const libtrace_packet_t *packet) {
    struct timeval tv;
    struct dpdk_addt_hdr * hdr = get_addt_hdr(packet);

    tv.tv_sec = hdr->timestamp / (uint64_t) 1000000000;
    tv.tv_usec = (hdr->timestamp % (uint64_t) 1000000000) / 1000;
    return tv;
}

static struct timespec dpdk_get_timespec (const libtrace_packet_t *packet) {
    struct timespec ts;
    struct dpdk_addt_hdr * hdr = get_addt_hdr(packet);

    ts.tv_sec = hdr->timestamp / (uint64_t) 1000000000;
    ts.tv_nsec = hdr->timestamp % (uint64_t) 1000000000;
    return ts;
}

static libtrace_linktype_t dpdk_get_link_type (const libtrace_packet_t *packet UNUSED) {
    return TRACE_TYPE_ETH; /* Always ethernet until proven otherwise */
}

static libtrace_direction_t dpdk_get_direction (const libtrace_packet_t *packet) {
    struct dpdk_addt_hdr * hdr = get_addt_hdr(packet);
    return (libtrace_direction_t) hdr->direction;
}

static libtrace_direction_t dpdk_set_direction(libtrace_packet_t *packet, libtrace_direction_t direction) {
    struct dpdk_addt_hdr * hdr = get_addt_hdr(packet);
    hdr->direction = (uint8_t) direction;
    return (libtrace_direction_t) hdr->direction;
}

/*
 * NOTE: Drops could occur for other reasons than running out of buffer
 * space. Such as failed MAC checksums and oversized packets.
 */
static uint64_t dpdk_get_dropped_packets (libtrace_t *trace) {
    struct rte_eth_stats stats = {0};

    if (trace->format_data == NULL || FORMAT(trace)->port == 0xFF)
	return UINT64_MAX;
    /* Grab the current stats */
    rte_eth_stats_get(FORMAT(trace)->port, &stats);

    /* Get the drop counter */
    return (uint64_t) stats.ierrors;
}

/*
 * This is the number of packets filtered by the NIC
 * and maybe ahead of number read using libtrace.
 *
 * XXX we are yet to implement any filtering, but if it was this should
 * get the result. So this will just return 0 for now.
 */
static uint64_t dpdk_get_filtered_packets (libtrace_t *trace) {
    struct rte_eth_stats stats = {0};

    if (trace->format_data == NULL || FORMAT(trace)->port == 0xFF)
	return UINT64_MAX;
    /* Grab the current stats */
    rte_eth_stats_get(FORMAT(trace)->port, &stats);

    /* Get the drop counter */
    return (uint64_t) stats.fdirmiss;
}

/* Attempts to read a packet in a non-blocking fashion. If one is not
 * available a SLEEP event is returned. We do not have the ability to
 * create a select()able file descriptor in DPDK.
 */
static libtrace_eventobj_t dpdk_trace_event(libtrace_t *trace,
					libtrace_packet_t *packet) {
    libtrace_eventobj_t event = {0,0,0.0,0};
    int nb_rx; /* Number of receive packets we've read */
    struct rte_mbuf* pkts_burst[1]; /* Array of 1 pointer(s) to rx buffers */

    do {

	/* See if we already have a packet waiting */
	nb_rx = rte_eth_rx_burst(FORMAT(trace)->port,
			FORMAT(trace)->queue_id, pkts_burst, 1);

	if (nb_rx > 0) {
	    /* Free the last packet buffer */
	    if (packet->buffer != NULL) {
		/* Buffer is owned by DPDK */
		if ( packet->buf_control == TRACE_CTRL_EXTERNAL ) {
		    rte_pktmbuf_free(packet->buffer);
		    packet->buffer = NULL;
		} else
		/* Buffer is owned by packet i.e. has been malloc'd */
		if (packet->buf_control == TRACE_CTRL_PACKET) {
		    free(packet->buffer);
		    packet->buffer = NULL;
		}
	    }

	    packet->buf_control = TRACE_CTRL_EXTERNAL;
	    packet->type = TRACE_RT_DATA_DPDK;
	    event.type = TRACE_EVENT_PACKET;
	    dpdk_ready_pkts(FORMAT(trace), &FORMAT(trace)->per_lcore[0], pkts_burst, 1, &packet);
	    event.size = 1; // TODO should be bytes read, which essentially useless anyway

	    /* XXX - Check this passes the filter trace_read_packet normally
	     * does this for us but this wont */
	    if (trace->filter) {
		if (!trace_apply_filter(trace->filter, packet)) {
		    /* Failed the filter so we loop for another packet */
		    trace->filtered_packets ++;
		    continue;
		}
	    }
	    trace->accepted_packets ++;
	} else {
	    /* We only want to sleep for a very short time - we are non-blocking */
	    event.type = TRACE_EVENT_SLEEP;
	    event.seconds = 0.0001;
	    event.size = 0;
	}

	/* If we get here we have our event */
	break;
    } while (1);

    return event;
}


static void dpdk_help(void) {
    printf("dpdk format module: $Revision: 1752 $\n");
    printf("Supported input URIs:\n");
    printf("\tdpdk:<domain:bus:devid.func>-<coreid>\n");
    printf("\tThe -<coreid> is optional \n");
    printf("\t e.g. dpdk:0000:01:00.1\n");
    printf("\t e.g. dpdk:0000:01:00.1-2 (Use the second CPU core)\n\n");
    printf("\t By default the last CPU core is used if not otherwise specified.\n");
    printf("\t Only a single libtrace instance of dpdk can use the same CPU core.\n");
    printf("\t Support for multiple simultaneous instances of dpdk format is currently limited.\n");
    printf("\n");
    printf("Supported output URIs:\n");
    printf("\tSame format as the input URI.\n");
    printf("\t e.g. dpdk:0000:01:00.1\n");
    printf("\t e.g. dpdk:0000:01:00.1-2 (Use the second CPU core)\n");
    printf("\n");
}

static struct libtrace_format_t dpdk = {
	"dpdk",
	"$Id: format_dpdk.c 1805 2013-03-08 02:01:35Z salcock $",
	TRACE_FORMAT_DPDK,
	NULL,	                /* probe filename */
	NULL,				    /* probe magic */
	dpdk_init_input,	    /* init_input */
	dpdk_config_input,	    /* config_input */
	dpdk_start_input,	    /* start_input */
	dpdk_pause_input,	    /* pause_input */
	dpdk_init_output,	    /* init_output */
	NULL,				    /* config_output */
	dpdk_start_output,	    /* start_ouput */
	dpdk_fin_input,		    /* fin_input */
	dpdk_fin_output,        /* fin_output */
	dpdk_read_packet,	    /* read_packet */
	dpdk_prepare_packet,    /* prepare_packet */
	dpdk_fin_packet,				    /* fin_packet */
	dpdk_write_packet,	    /* write_packet */
	dpdk_get_link_type,	    /* get_link_type */
	dpdk_get_direction,	    /* get_direction */
	dpdk_set_direction,	    /* set_direction */
	NULL,				    /* get_erf_timestamp */
	dpdk_get_timeval,	    /* get_timeval */
	dpdk_get_timespec,	    /* get_timespec */
	NULL,				    /* get_seconds */
	NULL,				    /* seek_erf */
	NULL,				    /* seek_timeval */
	NULL,				    /* seek_seconds */
	dpdk_get_capture_length,/* get_capture_length */
	dpdk_get_wire_length,	/* get_wire_length */
	dpdk_get_framing_length,/* get_framing_length */
	dpdk_set_capture_length,/* set_capture_length */
	NULL,				    /* get_received_packets */
	dpdk_get_filtered_packets,/* get_filtered_packets */
	dpdk_get_dropped_packets,/* get_dropped_packets */
	NULL,			/* get_statistics */
	NULL,		            /* get_fd */
	dpdk_trace_event,		/* trace_event */
	dpdk_help,              /* help */
	NULL,                   /* next pointer */
	{true, 8},              /* Live, NICs typically have 8 threads */
	dpdk_pstart_input, /* pstart_input */
	dpdk_pread_packets, /* pread_packets */
	dpdk_pause_input, /* ppause */
	dpdk_fin_input, /* p_fin */
	dpdk_pconfig_input, /* pconfig_input */
	dpdk_pregister_thread, /* pregister_thread */
	dpdk_punregister_thread, /* punregister_thread */
	NULL				/* get thread stats */
};

void dpdk_constructor(void) {
	register_format(&dpdk);
}
