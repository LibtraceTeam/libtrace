#ifndef FORMAT_LINUX_HELPERS_H
#define FORMAT_LINUX_HELPERS_H

#include "libtrace.h"
#include "libtrace_int.h"

int linuxcommon_set_promisc(const int sock, const unsigned int ifindex, bool enable);
int linuxcommon_get_nic_max_queues(char *ifname);
int linuxcommon_get_nic_queues(char *ifname);
int linuxcommon_set_nic_queues(char *ifname, int queues);
int linuxcommon_set_nic_hasher(char *ifname, enum hasher_types hasher);
int linuxcommon_get_nic_flow_rule_count(char *ifname);
int linuxcommon_get_nic_rx_rings(char *ifname);
int linuxcommon_get_nic_tx_rings(char *ifname);
int linuxcommon_get_nic_max_rx_rings(char *ifname);
int linuxcommon_get_nic_max_tx_rings(char *ifname);
int linuxcommon_set_nic_rx_tx_rings(int tx, int rx, char *ifname);

#endif
