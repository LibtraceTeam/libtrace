#ifndef FORMAT_LINUX_HELPERS_H
#define FORMAT_LINUX_HELPERS_H

#include "libtrace.h"
#include "libtrace_int.h"

#include <net/if.h>

/* A structure we use to hold statistic counters from the network cards
 * as accessed via the /proc/net/dev
 */
struct linux_dev_stats {
    char if_name[IF_NAMESIZE];
    uint64_t rx_bytes;
    uint64_t rx_packets;
    uint64_t rx_errors;
    uint64_t rx_drops;
    uint64_t rx_fifo;
    uint64_t rx_frame;
    uint64_t rx_compressed;
    uint64_t rx_multicast;
    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t tx_errors;
    uint64_t tx_drops;
    uint64_t tx_fifo;
    uint64_t tx_colls;
    uint64_t tx_carrier;
    uint64_t tx_compressed;
};

int linux_set_nic_promisc(const int sock, const unsigned int ifindex,
                          bool enable);
int linux_get_nic_max_queues(char *ifname);
int linux_get_nic_queues(char *ifname);
int linux_set_nic_queues(char *ifname, int queues);
int linux_set_nic_hasher(char *ifname, enum hasher_types hasher);
int linux_get_nic_flow_rule_count(char *ifname);
int linux_get_nic_rx_rings(char *ifname);
int linux_get_nic_tx_rings(char *ifname);
int linux_get_nic_max_rx_rings(char *ifname);
int linux_get_nic_max_tx_rings(char *ifname);
int linux_set_nic_rx_tx_rings(int tx, int rx, char *ifname);
int linux_get_dev_statistics(char *ifname, struct linux_dev_stats *stats);

#endif
