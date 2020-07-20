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
 *
 * Kit capture format.
 *
 * Intel Data Plane Development Kit is a LIVE capture format.
 *
 * This format also supports writing which will write packets out to the
 * network as a form of packet replay. This should not be confused with the
 * RT protocol which is intended to transfer captured packet records between
 * RT-speaking programs.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "libtrace_arphrd.h"
#include "hash_toeplitz.h"
#include "format_dpdk.h"

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
# error "Can't find inttypes.h"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <math.h>

#ifdef HAVE_LIBNUMA
#include <numa.h>
#endif

#define MBUF(x) ((struct rte_mbuf *) x)
/* Get the original placement of the packet data */
#define MBUF_PKTDATA(x) ((char *) x + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define FORMAT(x) ((struct dpdk_format_data_t*)(x->format_data))
#define PERPKT_FORMAT(x) ((struct dpdk_per_lcore_t*)(x->format_data))

#define FORMAT_DATA_HEAD(x) FORMAT(x)->per_stream->head
#define FORMAT_DATA_FIRST(x) ((dpdk_per_stream_t *)FORMAT_DATA_HEAD(x)->data)

#define TV_TO_NS(tv) ((uint64_t) tv.tv_sec*1000000000ull + \
			(uint64_t) tv.tv_usec*1000ull)
#define TS_TO_NS(ts) ((uint64_t) ts.tv_sec*1000000000ull + \
			(uint64_t) ts.tv_nsec)

#if RTE_PKTMBUF_HEADROOM != 128
#warning "RTE_PKT_MBUF_HEADROOM is not set to the default value of 128 - " \
	 "any libtrace instance processing these packet must be have the" \
	 "same RTE_PKTMBUF_HEADROOM set"
#endif


static pthread_mutex_t dpdk_lock = PTHREAD_MUTEX_INITIALIZER;
/* Memory pools Per NUMA node */
static struct rte_mempool * mem_pools[5][RTE_MAX_LCORE] = {{0}};

/* A list of cores we have allocated polling lcores on.
 * Normally DPDK wants to do this itself, however because we start our
 * own threads, we keep track of it here. This is similar to the
 * approach that OvS uses.
 */
static bool core_config[RTE_MAX_LCORE] = {0};

enum device_type {
	INVALID_DEVICE=0,
	PCI_DEVICE,
	VDEV_DEVICE,
};

/* Used by both input and output however some fields are not used
 * for output */
struct dpdk_format_data_t {
	int8_t promisc; /* promiscuous mode - RX only */
	uint8_t paused; /* See paused_state */
	portid_t port; /* Always 0 we only whitelist a single port - Shared TX & RX */
	portid_t nb_ports; /* Total number of usable ports on system should be 1 */
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
	enum hasher_types hasher_type;
	uint8_t *rss_key;
	/* To improve single-threaded performance we always batch reading
	 * packets, in a burst, otherwise the parallel library does this for us */
	struct rte_mbuf* burst_pkts[BURST_SIZE];
	int burst_size; /* The total number read in the burst */
	int burst_offset; /* The offset we are into the burst */
	enum device_type dev_type; /* The type of DPDK device vdev vs. PCI */

	/* Our parallel streams */
	libtrace_list_t *per_stream;
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

static bool dpdk_can_write(libtrace_packet_t *packet) {
        libtrace_linktype_t ltype = trace_get_link_type(packet);

        if (ltype == TRACE_TYPE_CONTENT_INVALID) {
                return false;
        }
        if (ltype == TRACE_TYPE_NONDATA || ltype == TRACE_TYPE_ERF_META ||
                        ltype == TRACE_TYPE_PCAPNG_META) {
                return false;
        }
	return true;
}

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
					" increasing BLACK_LIST_SIZE\n");
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
	if (rte_devargs_add(RTE_DEVTYPE_WHITELISTED_PCI, pci_str) < 0) {
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

	if (!str) {
		fprintf(stderr, "NULL str passed into parse_pciaddr()\n");
		return -1;
	}
#if RTE_VERSION >= RTE_VERSION_NUM(17, 8, 0, 1)
	matches = sscanf(str, "%8"SCNx32":%2"SCNx8":%2"SCNx8".%2"SCNx8"-%ld",
	                 &addr->domain, &addr->bus, &addr->devid,
	                 &addr->function, core);
#else
	matches = sscanf(str, "%4"SCNx16":%2"SCNx8":%2"SCNx8".%2"SCNx8"-%ld",
	                 &addr->domain, &addr->bus, &addr->devid,
	                 &addr->function, core);
#endif
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
		if (fscanf(file, "%d", &numa_node) != 1) {
                        numa_node = -1;
                }
		fclose(file);
		return numa_node;
	}
	return -1;
}

static inline long dpdk_processor_count() {
	long nb_cpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (nb_cpu <= 0) {
		perror("sysconf(_SC_NPROCESSORS_ONLN) failed."
		       " Falling back to the first core.");
		return 1;
	} else {
		return nb_cpu;
	}
}

#if DEBUG
/* For debugging */
static inline void dump_configuration()
{
	long nb_cpu = dpdk_processor_count();
	int i;

	if (nb_cpu > RTE_MAX_LCORE)
		nb_cpu = RTE_MAX_LCORE;

	fprintf(stderr, "Intel DPDK setup\n"
		"---Version      : %s\n"
		"---Master LCore : %"PRIu32"\n"
		"---LCore Count  : %"PRIu32"\n",
		rte_version(),
		rte_get_master_lcore(), rte_lcore_count());

	for (i = 0 ; i < nb_cpu; i++) {
		fprintf(stderr, "   ---Core %d : %s\n", i,
			rte_lcore_is_enabled(i) ? "on" : "off");
	}

	const char * proc_type;
	switch (rte_eal_process_type()) {
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
#endif

/** Remove the affinity of the master lcore
 * Note we also remove the master lcore's tid
 */
static inline int dpdk_unbind_master_lcore(libtrace_t *libtrace) {
	cpu_set_t cpuset;
	long i;
	long core_count = dpdk_processor_count();

	CPU_ZERO(&cpuset);
	for (i = 0; i < core_count; ++i) {
		CPU_SET(i, &cpuset);
	}

	i = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
	if (i != 0) {
		trace_set_err(libtrace, errno, "pthread_setaffinity_np failed\n");
		return -1;
	}

	RTE_PER_LCORE(_lcore_id) = LCORE_ID_ANY;
	return 0;
}

/**
 * XXX This is very bad XXX
 * But we have to do something to allow getopts nesting
 * Luckily, normally the format is last so it doesn't matter
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
	char master_lcore_id[10] = {0}; /* The master-lcore id as a number */
	char mem_map[20] = {0}; /* The memory name */
	long nb_cpu; /* The number of CPUs in the system */
	long my_cpu; /* The CPU core we want to bind to, counting from 1 not 0 */
	int i;
	struct saved_getopts save_opts;

	/* This initialises the Environment Abstraction Layer (EAL)
	 * If we had slave workers these are put into WAITING state
	 *
	 * Basically binds this thread to a fixed core, which we choose as
	 * the last core on the machine (assuming fewer interrupts mapped here).
	 * "-c" controls the cpu mask 0x1=1st core 0x2=2nd 0x4=3rd and so on
	 *      We exclude this and rely on DPDK's default behaviour:
	 *      Since 17.02-rc1 (2ebda8) if excluded this is set based on
	 *      the core mask. I believe from as early as 1.6 (f563a3) this
	 *      will default to using all cores.
	 * "-l" We use -l to assign this thread to a core, which becomes
	 *      DPDK's master (later we unbind its affinity).
	 * "-n" the number of memory channels into the CPU (hardware specific)
	 *      - Most likely to be half the number of ram slots in your machine.
	 *        We could count ram slots by "dmidecode -t 17 | grep -c 'Size:'"
	 * Controls where in memory packets are stored such that they are spread
	 * across the channels. We just use 1 to be safe.
	 *
	 * Using unique file prefixes mean separate memory is used, unlinking
	 * the two processes. However be careful we still cannot access a
	 * port that is already in use.
	 */
	char* argv[] = {"libtrace",
	                "-n", "1",
			"-l", master_lcore_id, /* Give DPDK only the master lcore */
	                "--proc-type", "auto",
	                "--file-prefix", mem_map,
			"--no-shconf", "--huge-unlink",
	                "-m", "512",
#if DPDK_USE_LOG_LEVEL
#	if DEBUG
	                "--log-level", "8", /* RTE_LOG_DEBUG */
#	else
	                "--log-level", "5", /* RTE_LOG_WARNING */
#	endif
#endif
			/* vdev only arguments */
			"--no-pci", "--vdev", uridata,
			NULL};
	int argc = sizeof(argv) / sizeof(argv[0]) - 1;

	if (format_data->dev_type != PCI_DEVICE &&
	    format_data->dev_type != VDEV_DEVICE) {
		snprintf(err, errlen,
		         "Libtrace DPDK: Invalid device type, corruption?");
		return -1;
	}

	if (format_data->dev_type == PCI_DEVICE) {
		/* PCI device, chop off the last 3 vdev specific args */
		argv[--argc] = NULL;
		argv[--argc] = NULL;
		argv[--argc] = NULL;
	}


#if DEBUG
	rte_log_set_global_level(RTE_LOG_DEBUG);
#else
	rte_log_set_global_level(RTE_LOG_WARNING);
#endif

	/* Get the number of cpu cores in the system and use the last core
	 * on the correct numa node */
	nb_cpu = dpdk_processor_count();
	if (nb_cpu > RTE_MAX_LCORE)
		nb_cpu = RTE_MAX_LCORE;

	my_cpu = -1;

	if (format_data->dev_type == PCI_DEVICE) {
		/* This allows the user to specify the core - we would try to do this
		 * automatically but it's hard to tell that this is secondary
		 * before running rte_eal_init(...). Currently we are limited to 1
		 * instance per core due to the way memory is allocated. */
		if (parse_pciaddr(uridata, &use_addr, &my_cpu) != 0) {
			snprintf(err, errlen, "Failed to parse URI");
			return -1;
		}
	}

#ifdef HAVE_LIBNUMA
	if (format_data->dev_type == PCI_DEVICE) {
		format_data->nic_numa_node = pci_to_numa(&use_addr);
	} else {
		format_data->nic_numa_node = -1;
	}
	if (my_cpu < 0) {
#if DEBUG
		/* If we can assign to a core on the same numa node */
		fprintf(stderr, "Using pci card on numa_node%d\n", format_data->nic_numa_node);
#endif
		if(format_data->nic_numa_node >= 0) {
			int max_node_cpu = -1;
			struct bitmask *mask = numa_allocate_cpumask();
			if (!mask) {
				fprintf(stderr, "Unable to allocate cpu mask in dpdk_init_environment()\n");
				return -1;
			}
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

	if (!(my_cpu > 0 && my_cpu <= MIN(RTE_MAX_LCORE, nb_cpu))) {
		snprintf(err, errlen,
		         "Libtrace DPDK: User defined a bad CPU number %"PRIu32" must be"
		         " between 1 and %"PRIu32, (uint32_t) my_cpu,
			 (uint32_t) MIN(RTE_MAX_LCORE, nb_cpu));
		return -1;
	}

	snprintf(master_lcore_id, sizeof(master_lcore_id), "%ld", my_cpu-1);

#if !DPDK_USE_BLACKLIST
	/* Black list all ports besides the one that we want to use */
	if (format_data->dev_type == PCI_DEVICE) {
		if ((ret = whitelist_device(format_data, &use_addr)) < 0) {
			snprintf(err, errlen, "Libtrace DPDK: Whitelisting PCI device failed,"
				 " are you sure the address is correct?: %s", strerror(-ret));
			return -1;
		}
	}
#endif

	/* Give the memory map a unique name */
	snprintf(mem_map, sizeof(mem_map), "libtrace-%d", (int) getpid());
	/* rte_eal_init it makes a call to getopt so we need to reset the
	 * global optind variable of getopt otherwise this fails */
	save_getopts(&save_opts);
	optind = 1;

#if DEBUG
	fprintf(stderr, "rte_eal_init:");
	for (int i = 0; i < argc; i++) {
		fprintf(stderr, "%s ", argv[i]);
	}
	fprintf(stderr, "\n");
#endif
	if ((ret = rte_eal_init(argc, argv)) < 0) {
		snprintf(err, errlen,
		         "Libtrace DPDK: Initialisation of EAL failed: %s", strerror(-ret));
		return -1;
	}
	restore_getopts(&save_opts);

	// Check our main thread (which is this thread) is where we expect it
	if ((long) rte_get_master_lcore() != my_cpu-1) {
		fprintf(stderr, "Warning: master core running on core %d not %ld.\n",
			rte_get_master_lcore(), my_cpu-1);
	}

	// Only the master should be running
	if (rte_lcore_count() != 1) {
		fprintf(stderr, "Expected only the master core to be running in dpdk_init_environment()\n");
		return -1;
	}

#if DEBUG
	dump_configuration();
#endif

#if DPDK_USE_PMD_INIT
	/* This registers all available NICs with Intel DPDK
	 * These are not loaded until rte_eal_pci_probe() is called.
	 */
	if ((ret = rte_pmd_init_all()) < 0) {
		snprintf(err, errlen,
		         "Libtrace DPDK: rte_pmd_init_all failed: %s", strerror(-ret));
		return -1;
	}
#endif

#if DPDK_USE_BLACKLIST
	/* Blacklist all ports besides the one that we want to use */
	if (format_data->dev_type == PCI_DEVICE) {
		if ((ret = blacklist_devices(format_data, &use_addr)) < 0) {
			snprintf(err, errlen, "Libtrace DPDK: Whitelisting PCI device failed,"
				 " are you sure the address is correct?: %s", strerror(-ret));
			return -1;
		}
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

	format_data->nb_ports = rte_eth_dev_count_avail();

	if (format_data->nb_ports != 1) {
		snprintf(err, errlen,
		         "Intel DPDK - rte_eth_dev_count returned %d but it should be 1",
		         format_data->nb_ports);
		return -1;
	}

	return 0;
}

static int dpdk_init_input (libtrace_t *libtrace, enum device_type dev_type) {
	dpdk_per_stream_t stream = DPDK_EMPTY_STREAM;
	char err[500];
	err[0] = 0;

	libtrace->format_data = (struct dpdk_format_data_t *)
	                        malloc(sizeof(struct dpdk_format_data_t));

	if (!libtrace->format_data) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Unable to allocate memory for "
			"format data inside dpdk_init_input()");
		return 1;
	}

	FORMAT(libtrace)->port = 0; /* Always assume 1 port loaded */
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
	memset(FORMAT(libtrace)->burst_pkts, 0,
	       sizeof(FORMAT(libtrace)->burst_pkts[0]) * BURST_SIZE);
	FORMAT(libtrace)->burst_size = 0;
	FORMAT(libtrace)->burst_offset = 0;
	FORMAT(libtrace)->hasher_type = HASHER_BALANCE;
	FORMAT(libtrace)->rss_key = NULL;
	FORMAT(libtrace)->dev_type = dev_type;

	/* Make our first stream */
	FORMAT(libtrace)->per_stream = libtrace_list_init(sizeof(struct dpdk_per_stream_t));
	libtrace_list_push_back(FORMAT(libtrace)->per_stream, &stream);

	if (dpdk_init_environment(libtrace->uridata, FORMAT(libtrace), err, sizeof(err)) != 0) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err);
		free(libtrace->format_data);
		libtrace->format_data = NULL;
		return -1;
	}
	return 0;
}

int dpdk_init_input_pci(libtrace_t *libtrace) {
	return dpdk_init_input(libtrace, PCI_DEVICE);
}

int dpdk_init_input_vdev(libtrace_t *libtrace) {
	return dpdk_init_input(libtrace, VDEV_DEVICE);
}

static int dpdk_init_output(libtrace_out_t *libtrace, enum device_type dev_type)
{
	dpdk_per_stream_t stream = DPDK_EMPTY_STREAM;
	char err[500];
	err[0] = 0;

	libtrace->format_data = (struct dpdk_format_data_t *)
	                        malloc(sizeof(struct dpdk_format_data_t));

	if (!libtrace->format_data) {
		trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "Unable to allocate memory for "
			"format data inside dpdk_init_output()");
		return -1;
	}
	FORMAT(libtrace)->port = 0; /* Always assume 1 port loaded */
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
	FORMAT(libtrace)->dev_type = dev_type;

	FORMAT(libtrace)->per_stream = libtrace_list_init(sizeof(struct dpdk_per_stream_t));
	libtrace_list_push_back(FORMAT(libtrace)->per_stream, &stream);

	if (dpdk_init_environment(libtrace->uridata, FORMAT(libtrace), err, sizeof(err)) != 0) {
		trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "%s", err);
		free(libtrace->format_data);
		libtrace->format_data = NULL;
		return -1;
	}
	return 0;
}

static int dpdk_init_output_pci(libtrace_out_t *libtrace) {
	return dpdk_init_output(libtrace, PCI_DEVICE);
}

static int dpdk_init_output_vdev(libtrace_out_t *libtrace) {
	return dpdk_init_output(libtrace, VDEV_DEVICE);
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
int dpdk_config_input (libtrace_t *libtrace,
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
	case TRACE_OPTION_HASHER:
		switch (*((enum hasher_types *) data))
		{
		case HASHER_BALANCE:
		case HASHER_UNIDIRECTIONAL:
		case HASHER_BIDIRECTIONAL:
			FORMAT(libtrace)->hasher_type = *(enum hasher_types*)data;
			if (FORMAT(libtrace)->rss_key)
				free(FORMAT(libtrace)->rss_key);
			FORMAT(libtrace)->rss_key = NULL;
			return 0;
		case HASHER_CUSTOM:
			// Let libtrace do this
			return -1;
		}
		break;
	case TRACE_OPTION_FILTER:
		/* TODO filtering */
	case TRACE_OPTION_META_FREQ:
	case TRACE_OPTION_DISCARD_META:
	case TRACE_OPTION_EVENT_REALTIME:
        case TRACE_OPTION_REPLAY_SPEEDUP:
        case TRACE_OPTION_CONSTANT_ERF_FRAMING:
        case TRACE_OPTION_XDP_HARDWARE_OFFLOAD:
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

#if RTE_VERSION >= RTE_VERSION_NUM(18, 8, 0, 1)

  #ifdef DEV_RX_OFFLOAD_KEEP_CRC
	#define _KEEP_CRC DEV_RX_OFFLOAD_KEEP_CRC
  #else
	#define _KEEP_CRC 0
  #endif

  #ifdef DEV_RX_OFFLOAD_CRC_STRIP
	#define _STRIP_CRC DEV_RX_OFFLOAD_CRC_STRIP
  #else
	#define _STRIP_CRC 0
  #endif

  #if GET_MAC_CRC_CHECKSUM
	.offloads = _KEEP_CRC
  #else	/* not GET_MAC_CRC_CHECKSUM */
	.offloads = _STRIP_CRC
  #endif	/* GET_MAC_CRC_CHECKSUM */

#else	/* not RTE_VERSION >= 18.8.0-rc1 */
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
  #else	/* not GET_MAC_CRC_CHECKSUM */
/* By default strip the MAC checksum because it's a bit of a hack to
 * actually read these. And don't want to rely on disabling this to actualy
 * always cut off the checksum in the future
 */
		.hw_strip_crc   = 1, /**< CRC stripped by hardware */
  #endif	/* GET_MAC_CRC_CHECKSUM */

#endif /* RTE_VERSION >= 18.8.0-rc1 */
	},
	.txmode = {
		.mq_mode = ETH_DCB_NONE,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_hf = RX_RSS_FLAGS,
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
		/*
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
#if RTE_VERSION >= RTE_VERSION_NUM(17, 8, 0, 1)
static int dpdk_lsc_callback(portid_t port, enum rte_eth_event_type event,
                              void *cb_arg, void *retparam UNUSED) {
#else
static void dpdk_lsc_callback(portid_t port, enum rte_eth_event_type event,
                              void *cb_arg) {
#endif
	struct dpdk_format_data_t * format_data = cb_arg;
	struct rte_eth_link link_info;
	if (event != RTE_ETH_EVENT_INTR_LSC) {
		fprintf(stderr, "Received unexpected event in dpdk_lsc_callback()\n");
		#if RTE_VERSION >= RTE_VERSION_NUM(17, 8, 0, 1)
		return -1;
		#else
		return;
		#endif
	}
	if (port != format_data->port) {
		fprintf(stderr, "Port does not match port in format data in dpdk_lsc_callback()\n");
		#if RTE_VERSION >= RTE_VERSION_NUM(17, 8, 0, 1)
		return -1;
		#else
		return;
		#endif
	}

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
#if RTE_VERSION >= RTE_VERSION_NUM(17, 8, 0, 1)
        return 0;
#endif
}

/** Reserve a DPDK lcore ID for a thread globally.
 *
 * @param real If true allocate a real lcore, otherwise allocate a core which
 * does not exist on the local machine.
 * @param socket the preferred NUMA socket - only used if a real core is requested
 * @return a valid core, which can later be used with dpdk_register_lcore() or a
 * -1 if have run out of cores.
 *
 * If any thread is reading or freeing packets we need to register it here
 * due to TLS caches in the memory pools.
 */
static int dpdk_reserve_lcore(bool real, int socket) {
	int new_id = -1;
	int i;
	(void) socket;
	long nb_core = dpdk_processor_count();

	pthread_mutex_lock(&dpdk_lock);
	/* If 'reading packets' fill in cores from 0 up and bind affinity
	 * otherwise start from the MAX core (which is also the master) and work backwards
	 * in this case physical cores on the system will not exist so we don't bind
	 * these to any particular physical core */
	if (real) {
#ifdef HAVE_LIBNUMA
		for (i = 0; i < MIN(nb_core, RTE_MAX_LCORE); ++i) {
			if (!core_config[i] && numa_node_of_cpu(i) == socket) {
				new_id = i;
				break;
			}
		}
#endif
		/* Retry without the numa restriction */
		if (new_id == -1) {
			for (i = 0; i < RTE_MAX_LCORE; ++i) {
				if (!core_config[i]) {
					new_id = i;
					if (new_id >= nb_core)
						fprintf(stderr, "Warning the"
						        " number of 'reading' "
						        "threads exceed cores\n");
					break;
				}
			}
		}
	} else {
		for (i = RTE_MAX_LCORE-1; i >= 0; --i) {
			if (!core_config[i]) {
				new_id = i;
				break;
			}
		}
	}

	if (new_id != -1) {
		/* Enable the core in global DPDK structs */
		core_config[new_id] = 1;
	}

	pthread_mutex_unlock(&dpdk_lock);
	return new_id;
}

/** Register a thread as an lcore
 * @param libtrace any error is set against libtrace on exit
 * @param real If this is true lcore we will bind its affinity to the
 * requested core.
 * @param lcore The lcore as retrieved from dpdk_reserve_lcore()
 * @return 0, if successful otherwise -1 if an error occured (details are stored
 * in libtrace)
 *
 * @note This must be called from the thread being registered.
 */
static int dpdk_register_lcore(libtrace_t *libtrace, bool real, int lcore) {
	int ret;
	RTE_PER_LCORE(_lcore_id) = lcore;

	/* Set affinity bind to corresponding core */
	if (real) {
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		CPU_SET(rte_lcore_id(), &cpuset);
		ret = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
		if (ret != 0) {
			trace_set_err(libtrace, errno, "Warning "
			              "pthread_setaffinity_np failed");
			return -1;
		}
	}

	return 0;
}

/** Allocates a new dpdk packet buffer memory pool.
 *
 * @param n The number of packets to allocate in the pool
 * @param pkt_size The packet size
 * @param socket_id The NUMA socket id
 * @param A new mempool, if NULL query the DPDK library for the error code
 * see rte_mempool_create() documentation.
 *
 * This allocates a new pool or recycles an existing memory pool.
 * Call dpdk_free_memory() to free the memory.
 * We cannot delete memory so instead we store the pools, allowing them to be
 * re-used.
 */
static struct rte_mempool *dpdk_alloc_memory(unsigned n,
                                             unsigned pkt_size,
                                             int socket_id) {
	struct rte_mempool *ret;
	size_t j,k;
	int socket_index = socket_id;
	char name[MEMPOOL_NAME_LEN];

	/* Add on packet size overheads */
	pkt_size += sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;

	pthread_mutex_lock(&dpdk_lock);

	if (socket_id == SOCKET_ID_ANY || socket_id >= 4) {
		/* Allocate memory from any node */
		socket_id = SOCKET_ID_ANY;
		socket_index = 4;
	}

	/* Find a valid pool */
	for (j = 0; j < RTE_MAX_LCORE && mem_pools[socket_index][j]; ++j) {
		if (mem_pools[socket_index][j]->size >= n &&
		    mem_pools[socket_index][j]->elt_size >= pkt_size) {
			break;
		}
	}

	/* Find the end (+1) of the list */
	for (k = j; k < RTE_MAX_LCORE && mem_pools[socket_index][k]; ++k) {}

	if (mem_pools[socket_index][j]) {
		ret = mem_pools[socket_index][j];
		mem_pools[socket_index][j] = mem_pools[socket_index][k-1];
		mem_pools[socket_index][k-1] = NULL;
		mem_pools[socket_index][j] = NULL;
	} else {
		static uint32_t test = 10;
		test++;
		snprintf(name, MEMPOOL_NAME_LEN,
		         "libtrace_pool_%"PRIu32, test);

		ret = rte_mempool_create(name, n, pkt_size,
		                         128, sizeof(struct rte_pktmbuf_pool_private),
		                         rte_pktmbuf_pool_init, NULL,
		                         rte_pktmbuf_init, NULL,
		                         socket_id, 0);
	}

	pthread_mutex_unlock(&dpdk_lock);
	return ret;
}

/** Stores the memory against the DPDK library.
 *
 * @param mempool The mempool to free
 * @param socket_id The NUMA socket this mempool was allocated upon.
 *
 * Because we cannot free a memory pool, we verify it's full (i.e. unused) and
 * store the memory shared globally against the format.
 */
static void dpdk_free_memory(struct rte_mempool *mempool, int socket_id) {
	size_t i;
	pthread_mutex_lock(&dpdk_lock);

	/* We should have all entries back in the mempool */
	rte_mempool_audit(mempool);
#if DEBUG
	if (!rte_mempool_full(mempool)) {
		fprintf(stderr, "Libtrace DPDK: memory pool not empty"
			" %d of %d. Please free all packets before finishing"
			" a trace. This warning may be spurious as some DPDK"
			" drivers don't free memory.\n",
		        rte_mempool_avail_count(mempool), mempool->size);
	}
#endif

	if (socket_id == SOCKET_ID_ANY || socket_id >= 4) {
		socket_id = 4;
	}

	/* Find the end (+1) of the list */
	for (i = 0; i < RTE_MAX_LCORE && mem_pools[socket_id][i]; ++i) {}

	if (i >= RTE_MAX_LCORE) {
		fprintf(stderr, "Libtrace DPDK: too many memory pools,"
			" dropping this one\n");
	} else {
		mem_pools[socket_id][i] = mempool;
	}

	pthread_mutex_unlock(&dpdk_lock);
}

/* Attach memory to the port and start (or restart) the port/s.
 */
static int dpdk_start_streams(struct dpdk_format_data_t *format_data,
                              char *err, int errlen, uint16_t rx_queues,
                              bool wait_for_link) {
	int ret, i, buf_size;
	struct rte_eth_link link_info; /* Wait for link */
	dpdk_per_stream_t empty_stream = DPDK_EMPTY_STREAM;
	struct rte_eth_dev_info dev_info;
	uint32_t dev_flags;

	/* Already started */
	if (format_data->paused == DPDK_RUNNING)
		return 0;

	rte_eth_dev_info_get(format_data->port, &dev_info);

	/*  dev_flags were added to dev_info in 18.05-rc1 (736b30)
	 *  The old API is accessing internal structures */
#if RTE_VERSION >= RTE_VERSION_NUM(18, 5, 0, 1)
	dev_flags = *dev_info.dev_flags;
#else
	dev_flags = rte_eth_devices[format_data->port].data->dev_flags;
#endif

	/* Calculate the required buffer size and try enable jumbo frames */
	if (format_data->snaplen <= RTE_ETHER_MAX_LEN) {
		/* We don't need jumbo frames, so keep default settings
		 * for the best driver compatibility.
		 * dpdk_ready_pkts() applies the snaplen, if snaplen <= 0
		 * then packets are returned unchanged.
		 */
		buf_size = RX_MBUF_SIZE;
#if RTE_VERSION >= RTE_VERSION_NUM(18, 8, 0, 1)
		port_conf.rxmode.offloads &=
				(~(DEV_RX_OFFLOAD_JUMBO_FRAME));
#else
		port_conf.rxmode.jumbo_frame = 0;
#endif
		port_conf.rxmode.max_rx_pkt_len = 0;
	} else {
		/* We need jumbo frames */
		double expn;
#if DEBUG
		fprintf(stderr, "Libtrace DPDK: enabling jumbo frames for"
			" snaplen %d\n", format_data->snaplen);
#endif

#ifdef DEV_RX_OFFLOAD_JUMBO_FRAME
		if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_JUMBO_FRAME) {
#if RTE_VERSION >= RTE_VERSION_NUM(18, 8, 0, 1)
			port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
#else
			port_conf.rxmode.jumbo_frame = 1;
#endif
		} else {
			fprintf(stderr, "Libtrace DPDK: warning driver does"
				" not support jumbo frames snaplen %d\n",
				format_data->snaplen);
		}
#else  /* not def DEV_RX_OFFLOAD_JUMBO_FRAME, must assume support */
		port_conf.rxmode.jumbo_frame = 1;
#endif
		buf_size = format_data->snaplen;
		port_conf.rxmode.max_rx_pkt_len = buf_size;

		/* Use fewer buffers if we're supporting jumbo frames
		 * otherwise we won't be able to allocate memory.
		 */
		format_data->nb_rx_buf /= 2;

		/* snaplen should be rounded up to next power of two
		 * to ensure enough memory is allocated for each
		 * mbuf :(
		 */
		expn = ceil(log2((double)(buf_size)));
		buf_size = pow(2, (int)expn);
	}

#if GET_MAC_CRC_CHECKSUM
	/* This is additional overhead so make sure we allow space for this */
	buf_size += RTE_ETHER_CRC_LEN;
#endif
#if HAS_HW_TIMESTAMPS_82580
	buf_size += sizeof(struct hw_timestamp_82580);
#endif

	/* First time started we need to alloc our memory, doing this here
	 * rather than in environment setup because we don't have snaplen then */
	if (format_data->paused == DPDK_NEVER_STARTED) {
		/* Create the mbuf pool, which is the place packets are allocated
		 * from - There is no free function (I cannot see one).
		 * NOTE: RX queue requires nb_packets + 1 otherwise it fails to
		 * allocate however that extra 1 packet is not used.
		 * (I assume <= vs < error some where in DPDK code)
		 * TX requires nb_tx_buffers + 1 in the case the queue is full
		 * so that will fill the new buffer and wait until slots in the
		 * ring become available.
		 */
#if DEBUG
		fprintf(stderr, "Libtrace DPDK: creating mempool named %s\n",
			format_data->mempool_name);
#endif
		format_data->pktmbuf_pool = dpdk_alloc_memory(format_data->nb_tx_buf*2,
		                                              buf_size,
		                                              format_data->nic_numa_node);

		if (format_data->pktmbuf_pool == NULL) {
			snprintf(err, errlen, "Libtrace DPDK: initialisation of mbuf "
			         "pool failed: %s", strerror(rte_errno));
			return -1;
		}
	}

	/* Generate the hash key, based on the device */
	uint8_t rss_size = 52; // 52 for i40e, 40 for others, use the largest by default
	// In new versions DPDK we can query the size
#if RTE_VERSION >= RTE_VERSION_NUM(2, 1, 0, 0)
	rss_size = dev_info.hash_key_size;

        port_conf.rx_adv_conf.rss_conf.rss_hf = dev_info.flow_type_rss_offloads;
#endif
	if (rss_size != 0) {
		format_data->rss_key = malloc(rss_size);
		if (format_data->hasher_type == HASHER_BIDIRECTIONAL) {
			toeplitz_ncreate_bikey(format_data->rss_key, rss_size);
		} else {
			toeplitz_ncreate_unikey(format_data->rss_key, rss_size);
		}
		port_conf.rx_adv_conf.rss_conf.rss_key = format_data->rss_key;
#if RTE_VERSION >= RTE_VERSION_NUM(1, 7, 0, 1)
		port_conf.rx_adv_conf.rss_conf.rss_key_len = rss_size;
#endif
	} else {
		fprintf(stderr, "Libtrace DPDK: couldn't configure RSS hashing!\n");
	}

	/* ----------- Now do the setup for the port mapping ------------ */
	/* Order of calls must be
	 * rte_eth_dev_configure()
	 * rte_eth_tx_queue_setup()
	 * rte_eth_rx_queue_setup()
	 * rte_eth_dev_start()
	 * other rte_eth calls
	 */

	if (dev_flags & RTE_ETH_DEV_INTR_LSC) {
		port_conf.intr_conf.lsc = wait_for_link ? 0 : 1;
	} else {
		port_conf.intr_conf.lsc = 0;
	}

	/* This must be called first before another *eth* function
	 * 1+ rx, 1 tx queues, port_conf sets checksum stripping etc */
	ret = rte_eth_dev_configure(format_data->port, rx_queues, 1, &port_conf);
	if (ret < 0) {
		snprintf(err, errlen, "Intel DPDK - Cannot configure device port"
		         " %"PRIu8" : %s", format_data->port,
		         strerror(-ret));
		return -1;
	}
#if DEBUG
	fprintf(stderr, "Libtrace DPDK: Doing dev configure\n");
#endif
	/* Initialise the TX queue a minimum value if using this port for
	 * receiving. Otherwise a larger size if writing packets.
	 */
	ret = rte_eth_tx_queue_setup(format_data->port,
	                             0 /* queue XXX */,
	                             format_data->nb_tx_buf,
	                             SOCKET_ID_ANY,
	                             DPDK_USE_NULL_QUEUE_CONFIG ? NULL : &tx_conf);
	if (ret < 0) {
		snprintf(err, errlen, "Intel DPDK - Cannot configure TX queue"
		         " on port %d : %s", (int)format_data->port,
		         strerror(-ret));
		return -1;
	}

	/* Attach memory to our RX queues */
	for (i=0; i < rx_queues; i++) {
		dpdk_per_stream_t *stream;
#if DEBUG
		fprintf(stderr, "Libtrace DPDK: Configuring queue %d\n", i);
#endif

		/* Add storage for the stream */
		if (libtrace_list_get_size(format_data->per_stream) <= (size_t) i)
			libtrace_list_push_back(format_data->per_stream, &empty_stream);
		stream = libtrace_list_get_index(format_data->per_stream, i)->data;
		stream->queue_id = i;

		if (stream->lcore == -1)
			stream->lcore = dpdk_reserve_lcore(true, format_data->nic_numa_node);

		if (stream->lcore == -1) {
			snprintf(err, errlen, "Intel DPDK - Failed to reserve a lcore"
			         ". Too many threads?");
			return -1;
		}

		if (stream->mempool == NULL) {
			stream->mempool = dpdk_alloc_memory(
			                          format_data->nb_rx_buf*2,
			                          buf_size,
			                          rte_lcore_to_socket_id(stream->lcore));

			if (stream->mempool == NULL) {
				snprintf(err, errlen, "Intel DPDK - Initialisation of mbuf "
				         "pool failed: %s", strerror(rte_errno));
				return -1;
			}
		}

		/* Initialise the RX queue with some packets from memory */
		ret = rte_eth_rx_queue_setup(format_data->port,
		                             stream->queue_id,
		                             format_data->nb_rx_buf,
		                             format_data->nic_numa_node,
		                             DPDK_USE_NULL_QUEUE_CONFIG ? NULL: &rx_conf,
		                             stream->mempool);
		if (ret < 0) {
			snprintf(err, errlen, "Intel DPDK - Cannot configure"
			         " RX queue on port %d : %s",
			         (int)format_data->port,
			         strerror(-ret));
			return -1;
		}
	}

#if DEBUG
	fprintf(stderr, "Libtrace DPDK: Doing start device\n");
#endif
	rte_eth_stats_reset(format_data->port);
	/* Start device */
	ret = rte_eth_dev_start(format_data->port);
	if (ret < 0) {
		snprintf(err, errlen, "Libtrace DPDK: rte_eth_dev_start failed : %s",
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


	if (port_conf.intr_conf.lsc) {
		/* Register a callback for link state changes */
		ret = rte_eth_dev_callback_register(format_data->port,
						    RTE_ETH_EVENT_INTR_LSC,
						    dpdk_lsc_callback,
						    format_data);
#if DEBUG
		if (ret)
			fprintf(stderr, "Libtrace DPDK: "
				"rte_eth_dev_callback_register failed %d : %s\n",
				ret, strerror(-ret));
#endif
	}

	/* Get the current link status */
	if (wait_for_link) {
		/* If LSC is setup this won't wait, so we disable LSC
		 * Only used for TX */
		rte_eth_link_get(format_data->port, &link_info);
		format_data->link_speed = link_info.link_speed;
		// Wait an extra 0.5s, as the link has just come up and
		// the receiver might not actually be ready yet.
		usleep(500000);
	}
	rte_eth_link_get_nowait(format_data->port, &link_info);
	format_data->link_speed = link_info.link_speed;
#if DEBUG
	fprintf(stderr, "Libtrace DPDK: Link status is %d %d %d\n",
		(int) link_info.link_status,
	        (int) link_info.link_duplex, (int) link_info.link_speed);
#endif

	return 0;
}

int dpdk_start_input (libtrace_t *libtrace) {
	char err[500];
	err[0] = 0;

	/* Make sure we don't reserve an extra thread for this */
	FORMAT_DATA_FIRST(libtrace)->queue_id = rte_lcore_id();

	if (dpdk_start_streams(FORMAT(libtrace), err, sizeof(err), 1, false) != 0) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err);
		free(libtrace->format_data);
		libtrace->format_data = NULL;
		return -1;
	}
	return 0;
}

static inline size_t dpdk_get_max_rx_queues (portid_t port_id) {
	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(port_id, &dev_info);
	return dev_info.max_rx_queues;
}


int dpdk_pstart_input (libtrace_t *libtrace) {
	char err[500];
	int phys_cores=0;
	int tot = libtrace->perpkt_thread_count;
	err[0] = 0;

	if (rte_lcore_id() != rte_get_master_lcore() && rte_lcore_id() != LCORE_ID_ANY)
		fprintf(stderr, "Libtrace DPDK: warning dpdk_pstart_input "
			"should be called from the master DPDK thread!\n");

	/* If the master is bound to an allocated thread, remove its affinity */
	if (rte_lcore_id() != LCORE_ID_ANY && core_config[rte_lcore_id()]) {
		if(dpdk_unbind_master_lcore(libtrace) != 0)
			return -1;
	}

	/* Don't exceed the number of cores in the system/detected by dpdk
	 * We don't have to force this but performance wont be good if we don't */
	phys_cores = dpdk_processor_count();

	tot = MIN(libtrace->perpkt_thread_count,
	          dpdk_get_max_rx_queues(FORMAT(libtrace)->port));
	tot = MIN(tot, phys_cores);

#if DEBUG
	fprintf(stderr, "Running pstart DPDK tot=%d req=%d phys=%d\n", tot,
	        libtrace->perpkt_thread_count, phys_cores);
#endif

	if (dpdk_start_streams(FORMAT(libtrace), err, sizeof(err), tot, false) != 0) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "%s", err);
		free(libtrace->format_data);
		libtrace->format_data = NULL;
		return -1;
	}

	/* Make sure we only start the number that we should */
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
int dpdk_pregister_thread(libtrace_t *libtrace, libtrace_thread_t *t, bool reading)
{
#if DEBUG
	char name[99];
	name[0] = 0;
#if defined(HAVE_PTHREAD_SETNAME_NP) && defined(__linux__)
	pthread_getname_np(pthread_self(),
	                   name, sizeof(name));
#endif
#endif
	if (reading) {
		dpdk_per_stream_t *stream;
		/* Attach our thread */
		if(t->type == THREAD_PERPKT) {
			t->format_data = libtrace_list_get_index(FORMAT(libtrace)->per_stream, t->perpkt_num)->data;
			if (t->format_data == NULL) {
				trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				              "Too many threads registered");
				return -1;
			}
		} else {
			t->format_data = FORMAT_DATA_FIRST(libtrace);
		}
		stream = t->format_data;
#if DEBUG
		fprintf(stderr, "%s new id memory:%s cpu-core:%d\n", name, stream->mempool->name, rte_lcore_id());
#endif
		return dpdk_register_lcore(libtrace, true, stream->lcore);
	} else {
		int lcore = dpdk_reserve_lcore(reading, 0);
		if (lcore == -1) {
			trace_set_err(libtrace, TRACE_ERR_INIT_FAILED, "Too many threads"
			              " for DPDK");
			return -1;
		}
#if DEBUG
		fprintf(stderr, "%s new id cpu-core:%d\n", name, rte_lcore_id());
#endif
		return dpdk_register_lcore(libtrace, false, lcore);
	}

	return 0;
}

/**
 * Unregister a thread with the DPDK system.
 *
 * Only previously registered threads should be calling this just before
 * they are destroyed.
 */
void dpdk_punregister_thread(libtrace_t *libtrace UNUSED, libtrace_thread_t *t UNUSED)
{

	if (rte_lcore_id() >= RTE_MAX_LCORE) {
		fprintf(stderr, "Expected core id less than or equal to RTE_MAX_LCORE in "
			"dpdk_punregister_thread()\n");
		return;
	}
	pthread_mutex_lock(&dpdk_lock);
	/* Skip if not registered (such as the master lcore) */
	if (!core_config[rte_lcore_id()]) {
		fprintf(stderr, "INFO: we are skipping unregistering a unknown lcore\n");
		pthread_mutex_unlock(&dpdk_lock);
		return;
	}

	/* Disable this core in global DPDK structs */
	core_config[rte_lcore_id()] = 0;
	RTE_PER_LCORE(_lcore_id) = LCORE_ID_ANY; // Unassign the lcore ID
	pthread_mutex_unlock(&dpdk_lock);
	return;
}

static int dpdk_start_output(libtrace_out_t *libtrace)
{
	char err[500];
	err[0] = 0;

	if (dpdk_start_streams(FORMAT(libtrace), err, sizeof(err), 1, true) != 0) {
		trace_set_err_out(libtrace, TRACE_ERR_INIT_FAILED, "%s", err);
		free(libtrace->format_data);
		libtrace->format_data = NULL;
		return -1;
	}
	return 0;
}

int dpdk_pause_input(libtrace_t * libtrace) {
	libtrace_list_node_t *tmp = FORMAT_DATA_HEAD(libtrace);
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

		for (; tmp != NULL; tmp = tmp->next) {
			dpdk_per_stream_t *stream = tmp->data;
			stream->ts_last_sys = 0;
#if HAS_HW_TIMESTAMPS_82580
			stream->ts_first_sys = 0;
#endif
		}

	}
	return 0;
}

static int dpdk_write_packet(libtrace_out_t *trace,
                             libtrace_packet_t *packet){

	/* Check dpdk can write this type of packet */
	if (!dpdk_can_write(packet)) {
		return 0;
	}

	struct rte_mbuf* m_buff[1];

	int wirelen = trace_get_wire_length(packet);
	int caplen = trace_get_capture_length(packet);

	/* Check for a checksum and remove it */
	if (trace_get_link_type(packet) == TRACE_TYPE_ETH &&
	    wirelen == caplen)
		caplen -= RTE_ETHER_CRC_LEN;

	m_buff[0] = rte_pktmbuf_alloc(FORMAT(trace)->pktmbuf_pool);
	if (m_buff[0] == NULL) {
		trace_set_err_out(trace, errno, "Cannot get an empty packet buffer");
		return -1;
	} else {
		int ret;
		memcpy(rte_pktmbuf_append(m_buff[0], caplen), packet->payload, caplen);
		do {
			ret = rte_eth_tx_burst(FORMAT(trace)->port, 0 /*queue TODO*/, m_buff, 1);
		} while (ret != 1);
	}

	return 0;
}

int dpdk_fin_input(libtrace_t * libtrace) {
	libtrace_list_node_t * n;
	/* Free our memory structures */
	if (libtrace->format_data != NULL) {

		if (FORMAT(libtrace)->port != 0xFF)
			rte_eth_dev_callback_unregister(FORMAT(libtrace)->port,
			                                RTE_ETH_EVENT_INTR_LSC,
			                                dpdk_lsc_callback,
			                                FORMAT(libtrace));
		/* Close the device completely, device cannot be restarted */
		rte_eth_dev_close(FORMAT(libtrace)->port);

		dpdk_free_memory(FORMAT(libtrace)->pktmbuf_pool,
		                 FORMAT(libtrace)->nic_numa_node);

		for (n = FORMAT(libtrace)->per_stream->head; n ; n = n->next) {
			dpdk_per_stream_t * stream = n->data;
			if (stream->mempool)
				dpdk_free_memory(stream->mempool,
				                 rte_lcore_to_socket_id(stream->lcore));
		}

		libtrace_list_deinit(FORMAT(libtrace)->per_stream);
		/* filter here if we used it */
		if (FORMAT(libtrace)->rss_key)
			free(FORMAT(libtrace)->rss_key);
		free(libtrace->format_data);
	}

	return 0;
}


static int dpdk_fin_output(libtrace_out_t * libtrace) {
	/* Free our memory structures */
	if (libtrace->format_data != NULL) {
		/* Close the device completely, device cannot be restarted */
		if (FORMAT(libtrace)->port != 0xFF)
			rte_eth_dev_close(FORMAT(libtrace)->port);
		libtrace_list_deinit(FORMAT(libtrace)->per_stream);
		/* filter here if we used it */
		free(libtrace->format_data);
	}

	return 0;
}

/**
 * Get the start of the additional header that we added to a packet.
 */
static inline struct dpdk_addt_hdr * get_addt_hdr (const libtrace_packet_t *packet) {
	if (!packet) {
		fprintf(stderr, "NULL packet passed into dpdk_addt_hdr()\n");
		return NULL;
	}
	if (!packet->buffer) {
		fprintf(stderr, "NULL packet buffer passed into dpdk_addt_hdr()\n");
		return NULL;
	}
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
	packet->cached.capture_length = -1;
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
		return org_cap_size + RTE_ETHER_CRC_LEN;
	}
}

int dpdk_get_framing_length (const libtrace_packet_t *packet) {
	struct dpdk_addt_hdr * hdr = get_addt_hdr(packet);
	if (hdr->flags & INCLUDES_HW_TIMESTAMP)
		return sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM +
		                sizeof(struct hw_timestamp_82580);
	else
		return sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;
}

int dpdk_prepare_packet(libtrace_t *libtrace UNUSED,
                               libtrace_packet_t *packet, void *buffer,
                               libtrace_rt_types_t rt_type, uint32_t flags) {
	if (!packet) {
		fprintf(stderr, "NULL packet passed into dpdk_prepare_packet()\n");
		return TRACE_ERR_NULL_PACKET;
	}
	if (packet->buffer != buffer &&
	    packet->buf_control == TRACE_CTRL_PACKET) {
		free(packet->buffer);
	}

	if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER)
		packet->buf_control = TRACE_CTRL_PACKET;
	else
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
	wire_time = ((pkt_size + 20 + RTE_ETHER_CRC_LEN) * 8000);
# endif

	/* Division is really slow and introduces a pipeline stall
	 * The compiler will optimise this into magical multiplication and shifting
	 * See http://ridiculousfish.com/blog/posts/labor-of-division-episode-i.html
	 */
retry_calc_wiretime:
	switch (format_data->link_speed) {
	case ETH_SPEED_NUM_40G:
		wire_time /=  ETH_SPEED_NUM_40G;
		break;
	case ETH_SPEED_NUM_20G:
		wire_time /= ETH_SPEED_NUM_20G;
		break;
	case ETH_SPEED_NUM_10G:
		wire_time /= ETH_SPEED_NUM_10G;
		break;
	case ETH_SPEED_NUM_1G:
		wire_time /= ETH_SPEED_NUM_1G;
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

/**
 * Does any extra preperation to all captured packets
 * This includes adding our extra header to it with the timestamp,
 * and any snapping
 *
 * @param format_data The DPDK format data
 * @param plc The DPDK per lcore format data
 * @param pkts An array of size nb_pkts of DPDK packets
 */
static inline void dpdk_ready_pkts(libtrace_t *libtrace,
                                   struct dpdk_per_stream_t *plc,
                                   struct rte_mbuf **pkts,
                                   size_t nb_pkts) {
	struct dpdk_format_data_t *format_data = FORMAT(libtrace);
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

	ct_assert(RTE_PKTMBUF_HEADROOM >= sizeof(struct dpdk_addt_hdr));
	for (i = 0 ; i < nb_pkts ; ++i) {

		/* We put our header straight after the dpdk header */
		hdr = (struct dpdk_addt_hdr *) (pkts[i] + 1);
		memset(hdr, 0, sizeof(struct dpdk_addt_hdr));

#if GET_MAC_CRC_CHECKSUM
		/* Add back in the CRC sum */
		rte_pktmbuf_pkt_len(pkts[i]) += RTE_ETHER_CRC_LEN;
		rte_pktmbuf_data_len(pkts[i]) += RTE_ETHER_CRC_LEN;
		hdr->flags |= INCLUDES_CHECKSUM;
#endif

		hdr->cap_len = rte_pktmbuf_pkt_len(pkts[i]); // TODO should this be data_len?

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
		if (format_data->snaplen > 0) {
			hdr->cap_len = MIN(format_data->snaplen, hdr->cap_len);
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

/** Reads at least one packet or returns an error
 */
int dpdk_read_packet_stream (libtrace_t *libtrace,
                                           dpdk_per_stream_t *stream,
                                           libtrace_message_queue_t *mesg,
                                           struct rte_mbuf* pkts_burst[],
                                           size_t nb_packets) {
	size_t nb_rx; /* Number of rx packets we've recevied */
	while (1) {
		/* Poll for a batch of packets */
		nb_rx = rte_eth_rx_burst(FORMAT(libtrace)->port,
		                         stream->queue_id, pkts_burst, nb_packets);
		if (nb_rx > 0) {
			/* Got some packets - otherwise we keep spining */
			dpdk_ready_pkts(libtrace, stream, pkts_burst, nb_rx);
			//fprintf(stderr, "Doing P READ PACKET port=%d q=%d\n", (int) FORMAT(libtrace)->port, (int) get_thread_table_num(libtrace));
			return nb_rx;
		}
		/* Check the message queue this could be less than 0.
                 * If the message queue is not available return and let libtrace
                 * check for new messages. */
		if ((mesg && libtrace_message_queue_count(mesg) > 0) || !mesg)
			return READ_MESSAGE;
		if ((nb_rx=is_halted(libtrace)) != (size_t) -1)
			return nb_rx;
		/* Wait a while, polling on memory degrades performance
		 * This relieves the pressure on memory allowing the NIC to DMA */
		rte_delay_us(10);
	}

	/* We'll never get here - but if we did it would be bad */
	return READ_ERROR;
}

static int dpdk_pread_packets (libtrace_t *libtrace,
                                    libtrace_thread_t *t,
                                    libtrace_packet_t **packets,
                                    size_t nb_packets) {
	int nb_rx; /* Number of rx packets we've recevied */
	struct rte_mbuf* pkts_burst[nb_packets]; /* Array of pointer(s) */
	int i;
	dpdk_per_stream_t *stream = t->format_data;
	struct dpdk_addt_hdr * hdr;

	nb_rx = dpdk_read_packet_stream (libtrace, stream, &t->messages,
	                                 pkts_burst, nb_packets);

	if (nb_rx > 0) {
		for (i = 0; i < nb_rx; ++i) {
			if (packets[i]->buffer != NULL) {
				/* The packet should always be finished */
				if (packets[i]->buf_control != TRACE_CTRL_PACKET) {
					trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Expected packet buffer "
						"to be empty in dpdk_pread_packets()\n");
					return -1;
				}
				free(packets[i]->buffer);
			}
			packets[i]->buf_control = TRACE_CTRL_EXTERNAL;
			packets[i]->type = TRACE_RT_DATA_DPDK;
			packets[i]->buffer = pkts_burst[i];
			packets[i]->trace = libtrace;
			packets[i]->error = 1;
			hdr = (struct dpdk_addt_hdr *)
					((struct rte_mbuf*) pkts_burst[i] + 1);
			packets[i]->order = hdr->timestamp;
			dpdk_prepare_packet(libtrace, packets[i], packets[i]->buffer, packets[i]->type, 0);
		}
	}

	return nb_rx;
}

int dpdk_read_packet (libtrace_t *libtrace, libtrace_packet_t *packet) {
	int nb_rx; /* Number of rx packets we've received */
	dpdk_per_stream_t *stream = FORMAT_DATA_FIRST(libtrace);

	/* Free the last packet buffer */
	if (packet->buffer != NULL) {
		/* The packet should always be finished */
		if (packet->buf_control != TRACE_CTRL_PACKET) {
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Expected packet buffer to be "
				"empty in dpdk_read_packet()\n");
			return -1;
		}
		free(packet->buffer);
		packet->buffer = NULL;
	}

	packet->buf_control = TRACE_CTRL_EXTERNAL;
	packet->type = TRACE_RT_DATA_DPDK;

	/* Check if we already have some packets buffered */
	if (FORMAT(libtrace)->burst_size != FORMAT(libtrace)->burst_offset) {
		packet->buffer = FORMAT(libtrace)->burst_pkts[FORMAT(libtrace)->burst_offset++];
                packet->trace = libtrace;
		dpdk_prepare_packet(libtrace, packet, packet->buffer, packet->type, 0);
		return 1; // TODO should be bytes read, which essentially useless anyway
	}

	nb_rx = dpdk_read_packet_stream (libtrace, stream, NULL,
	                                 FORMAT(libtrace)->burst_pkts, BURST_SIZE);

	if (nb_rx > 0) {
		FORMAT(libtrace)->burst_size = nb_rx;
		FORMAT(libtrace)->burst_offset = 1;
		packet->buffer = FORMAT(libtrace)->burst_pkts[0];
                packet->trace = libtrace;
		dpdk_prepare_packet(libtrace, packet, packet->buffer, packet->type, 0);
		return 1;
	}
	return nb_rx;
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
	if (hdr->direction == (uint8_t) -1)
		return TRACE_DIR_UNKNOWN;
	return (libtrace_direction_t) hdr->direction;
}

static libtrace_direction_t dpdk_set_direction(libtrace_packet_t *packet, libtrace_direction_t direction) {
	struct dpdk_addt_hdr * hdr = get_addt_hdr(packet);
	hdr->direction = (uint8_t) direction;
	return (libtrace_direction_t) hdr->direction;
}

void dpdk_get_stats(libtrace_t *trace, libtrace_stat_t *stats) {
	struct rte_eth_stats dev_stats = {0};

	if (trace->format_data == NULL || FORMAT(trace)->port == 0xFF)
		return;

	/* Grab the current stats */
	rte_eth_stats_get(FORMAT(trace)->port, &dev_stats);

	stats->captured_valid = true;
	stats->captured = dev_stats.ipackets;

	stats->dropped_valid = true;
	stats->dropped = dev_stats.imissed;

#if RTE_VERSION >= RTE_VERSION_NUM(16, 4, 0, 2)
	/* DPDK commit 86057c fixes ensures missed does not get counted as
	 * errors */
	stats->errors_valid = true;
	stats->errors = dev_stats.ierrors;
#else
	/* DPDK errors includes drops */
	stats->errors_valid = true;
	stats->errors = dev_stats.ierrors - dev_stats.imissed;
#endif
	stats->received_valid = true;
	stats->received = dev_stats.ipackets + dev_stats.imissed;

}

/* Attempts to read a packet in a non-blocking fashion. If one is not
 * available a SLEEP event is returned. We do not have the ability to
 * create a select()able file descriptor in DPDK.
 */
libtrace_eventobj_t dpdk_trace_event(libtrace_t *trace,
                                            libtrace_packet_t *packet) {
	libtrace_eventobj_t event = {0,0,0.0,0};
	size_t nb_rx; /* Number of received packets we've read */

	do {

		/* No packets waiting in our buffer? Try and read some more */
		if (FORMAT(trace)->burst_size == FORMAT(trace)->burst_offset) {
			nb_rx = rte_eth_rx_burst(FORMAT(trace)->port,
			                         FORMAT_DATA_FIRST(trace)->queue_id,
			                         FORMAT(trace)->burst_pkts, BURST_SIZE);
			if (nb_rx > 0) {
				dpdk_ready_pkts(trace, FORMAT_DATA_FIRST(trace),
				                FORMAT(trace)->burst_pkts, nb_rx);
				FORMAT(trace)->burst_size = nb_rx;
				FORMAT(trace)->burst_offset = 0;
			}
		}

		/* Now do we have packets waiting? */
		if (FORMAT(trace)->burst_size != FORMAT(trace)->burst_offset) {
			/* Free the last packet buffer */
			if (packet->buffer != NULL) {
				/* The packet should always be finished */
				if (packet->buf_control != TRACE_CTRL_PACKET) {
					trace_set_err(trace, TRACE_ERR_BAD_PACKET, "Expected packet "
						"buffer to be empty in dpdk_trace_event()\n");
					event.type = TRACE_EVENT_TERMINATE;
					return event;
				}
				free(packet->buffer);
				packet->buffer = NULL;
			}

			packet->buf_control = TRACE_CTRL_EXTERNAL;
			packet->type = TRACE_RT_DATA_DPDK;
			event.type = TRACE_EVENT_PACKET;
			packet->buffer = FORMAT(trace)->burst_pkts[
			                     FORMAT(trace)->burst_offset++];
			dpdk_prepare_packet(trace, packet, packet->buffer, packet->type, 0);
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
	printf("dpdk format module: %s (%d) \n", rte_version(), RTE_VERSION);
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

static void dpdk_vdev_help(void) {
	printf("dpdk vdev format module: %s (%d) \n", rte_version(), RTE_VERSION);
	printf("Supported input and output URIs:\n");
	printf("\tdpdkvdev:<driver><id>,[key=val, ...]-<coreid>\n");
	printf("\tThe -<coreid> is optional\n");
	printf("\tEverything before the '-' is given to DPDK in a --vdev argument\n");
	printf("\tSee the DPDK documentation for the valid values\n");
	printf("\t e.g. dpdkvdev:net_pcap0,iface=veth0\n");
	printf("\t e.g. dpdkvdev:net_tap0,iface=tap0\n");
	printf("\n");
}

static struct libtrace_format_t dpdk = {
	"dpdk",
	"$Id$",
	TRACE_FORMAT_DPDK,
	NULL,                               /* probe filename */
	NULL,                               /* probe magic */
	dpdk_init_input_pci,                /* init_input */
	dpdk_config_input,                  /* config_input */
	dpdk_start_input,                   /* start_input */
	dpdk_pause_input,                   /* pause_input */
	dpdk_init_output_pci,               /* init_output */
	NULL,                               /* config_output */
	dpdk_start_output,                  /* start_ouput */
	dpdk_fin_input,                     /* fin_input */
	dpdk_fin_output,                    /* fin_output */
	dpdk_read_packet,                   /* read_packet */
	dpdk_prepare_packet,                /* prepare_packet */
	dpdk_fin_packet,                    /* fin_packet */
	dpdk_write_packet,                  /* write_packet */
	NULL,                               /* flush_output */
	dpdk_get_link_type,                 /* get_link_type */
	dpdk_get_direction,                 /* get_direction */
	dpdk_set_direction,                 /* set_direction */
	NULL,                               /* get_erf_timestamp */
	dpdk_get_timeval,                   /* get_timeval */
	dpdk_get_timespec,                  /* get_timespec */
	NULL,                               /* get_seconds */
	NULL,                               /* seek_erf */
	NULL,                               /* seek_timeval */
	NULL,                               /* seek_seconds */
	NULL,                               /* get_meta_section */
	dpdk_get_capture_length,            /* get_capture_length */
	dpdk_get_wire_length,               /* get_wire_length */
	dpdk_get_framing_length,            /* get_framing_length */
	dpdk_set_capture_length,            /* set_capture_length */
	NULL,                               /* get_received_packets */
	NULL,                               /* get_filtered_packets */
	NULL,                               /* get_dropped_packets */
	dpdk_get_stats,                     /* get_statistics */
	NULL,                               /* get_fd */
	dpdk_trace_event,                   /* trace_event */
	dpdk_help,                          /* help */
	NULL,                               /* next pointer */
	{true, 8},                          /* Live, NICs typically have 8 threads */
	dpdk_pstart_input,                  /* pstart_input */
	dpdk_pread_packets,                 /* pread_packets */
	dpdk_pause_input,                   /* ppause */
	dpdk_fin_input,                     /* p_fin */
	dpdk_pregister_thread,              /* pregister_thread */
	dpdk_punregister_thread,            /* punregister_thread */
	NULL                                /* get thread stats */
};

static struct libtrace_format_t dpdk_vdev = {
	"dpdkvdev",
	"$Id$",
	TRACE_FORMAT_DPDK,
	NULL,                               /* probe filename */
	NULL,                               /* probe magic */
	dpdk_init_input_vdev,               /* init_input */
	dpdk_config_input,                  /* config_input */
	dpdk_start_input,                   /* start_input */
	dpdk_pause_input,                   /* pause_input */
	dpdk_init_output_vdev,              /* init_output */
	NULL,                               /* config_output */
	dpdk_start_output,                  /* start_ouput */
	dpdk_fin_input,                     /* fin_input */
	dpdk_fin_output,                    /* fin_output */
	dpdk_read_packet,                   /* read_packet */
	dpdk_prepare_packet,                /* prepare_packet */
	dpdk_fin_packet,                    /* fin_packet */
	dpdk_write_packet,                  /* write_packet */
	NULL,                               /* flush_output */
	dpdk_get_link_type,                 /* get_link_type */
	dpdk_get_direction,                 /* get_direction */
	dpdk_set_direction,                 /* set_direction */
	NULL,                               /* get_erf_timestamp */
	dpdk_get_timeval,                   /* get_timeval */
	dpdk_get_timespec,                  /* get_timespec */
	NULL,                               /* get_seconds */
	NULL,                               /* seek_erf */
	NULL,                               /* seek_timeval */
	NULL,                               /* seek_seconds */
	NULL,                               /* get_meta_section */
	dpdk_get_capture_length,            /* get_capture_length */
	dpdk_get_wire_length,               /* get_wire_length */
	dpdk_get_framing_length,            /* get_framing_length */
	dpdk_set_capture_length,            /* set_capture_length */
	NULL,                               /* get_received_packets */
	NULL,                               /* get_filtered_packets */
	NULL,                               /* get_dropped_packets */
	dpdk_get_stats,                     /* get_statistics */
	NULL,                               /* get_fd */
	dpdk_trace_event,                   /* trace_event */
	dpdk_vdev_help,                     /* help */
	NULL,                               /* next pointer */
	{true, 8},                          /* Live, NICs typically have 8 threads */
	dpdk_pstart_input,                  /* pstart_input */
	dpdk_pread_packets,                 /* pread_packets */
	dpdk_pause_input,                   /* ppause */
	dpdk_fin_input,                     /* p_fin */
	dpdk_pregister_thread,              /* pregister_thread */
	dpdk_punregister_thread,            /* punregister_thread */
	NULL                                /* get thread stats */
};

void dpdk_constructor(void) {
	register_format(&dpdk);
	register_format(&dpdk_vdev);
}
