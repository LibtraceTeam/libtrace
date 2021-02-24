#include "libtrace.h"
#include "libtrace_int.h"
#include "format_linux_helpers.h"
#include "hash_toeplitz.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/ethtool.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <errno.h>

int linux_set_promisc(const int sock, const unsigned int ifindex, bool enable) {

    struct packet_mreq mreq;
    int action;

    memset(&mreq,0,sizeof(mreq));
    mreq.mr_ifindex = ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;

    if (enable)
        action = PACKET_ADD_MEMBERSHIP;
    else
        action = PACKET_DROP_MEMBERSHIP;


    if (setsockopt(sock, SOL_PACKET, action, &mreq, sizeof(mreq)) == -1)
        return -1;

    return 0;
}

static int linux_send_ioctl_ethtool(void *data, char *ifname) {

    struct ifreq ifr = {};
    int fd, err, ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -errno;

    ifr.ifr_data = data;
    int cpy_len = strlen(ifname) < IFNAMSIZ ? strlen(ifname) : IFNAMSIZ -1;
    memcpy(ifr.ifr_name, ifname, cpy_len);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    err = ioctl(fd, SIOCETHTOOL, &ifr);
    if (err && errno != EOPNOTSUPP) {
        ret = -errno;
        goto out;
    }

    /* return 1 on error, error usually occurs when the nic only
     * supports a single queue. */
    if (err) {
        ret = 1;
    } else {
        ret = 0;
    }

out:
    close(fd);
    return ret;
}

int linux_get_nic_max_queues(char *ifname) {

    struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
    int ret;

    if ((ret = linux_send_ioctl_ethtool(&channels, ifname)) == 0) {
        ret = MAX(channels.max_rx, channels.max_tx);
        ret = MAX(ret, (int)channels.max_combined);
    }

    return ret;
}

int linux_get_nic_queues(char *ifname) {
    struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
    int ret;

    if ((ret = linux_send_ioctl_ethtool(&channels, ifname)) == 0) {
        ret = MAX(channels.rx_count, channels.tx_count);
        ret = MAX(ret, (int)channels.combined_count);
    }

    return ret;
}

int linux_set_nic_queues(char *ifname, int queues) {
    struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
    __u32 org_combined;
    int ret;

    /* get the current settings */
    if ((ret = linux_send_ioctl_ethtool(&channels, ifname)) == 0) {

        org_combined = channels.combined_count;
        channels.cmd = ETHTOOL_SCHANNELS;
        channels.combined_count = queues;
        /* try update */
        if ((ret = linux_send_ioctl_ethtool(&channels, ifname)) == 0) {
            /* success */
            return channels.combined_count;
        }

        /* try set rx and tx individually */
        channels.rx_count = queues;
        channels.tx_count = queues;
        channels.combined_count = org_combined;
        /* try again */
        if ((ret = linux_send_ioctl_ethtool(&channels, ifname)) == 0) {
            /* success */
            return channels.rx_count;
        }
    }

    /* could not set the number of queues */
    return ret;
}

int linux_set_nic_hasher(char *ifname, enum hasher_types hasher) {

    int err;
    int indir_bytes;

    struct ethtool_rxfh rss_head = {0};
    rss_head.cmd = ETHTOOL_GRSSH;
    err = linux_send_ioctl_ethtool(&rss_head, ifname);
    if (err != 0) {
        return -1;
    }

    // make sure key is a multiple of 2 , RSS keys can be 40 or 52 bytes long.
    if (rss_head.key_size % 2 != 0 || (rss_head.key_size != 40 && rss_head.key_size != 52))
        return -1;

    indir_bytes = rss_head.indir_size * sizeof(rss_head.rss_config[0]);

    struct ethtool_rxfh *rss;
    rss = calloc(1, sizeof(*rss) + (rss_head.indir_size * sizeof(rss_head.rss_config[0])) + rss_head.key_size);
    if (!rss) {
        return -1;
    }
    rss->cmd = ETHTOOL_SRSSH;
    rss->rss_context = 0;
    //rss->hfunc = rss_head.hfunc;
    rss->indir_size = 0;
    rss->key_size = rss_head.key_size;
    switch (hasher) {
        case HASHER_BALANCE:
        case HASHER_UNIDIRECTIONAL:
            toeplitz_ncreate_unikey((uint8_t *)rss->rss_config + indir_bytes, rss_head.key_size);
            break;
        case HASHER_BIDIRECTIONAL:
            toeplitz_ncreate_bikey((uint8_t *)rss->rss_config + indir_bytes, rss_head.key_size);
            break;
        case HASHER_CUSTOM:
            // should never hit this, just here to silence warnings
            free(rss);
            return 0;
    }
    err = linux_send_ioctl_ethtool(rss, ifname);
    if (err != 0) {
        free(rss);
        return -1;
    }
    free(rss);

    return 0;
}

int linux_get_nic_flow_rule_count(char *ifname) {

    int err;

    struct ethtool_rxnfc nfccmd = {};
    nfccmd.cmd = ETHTOOL_GRXCLSRLCNT;
    nfccmd.data = 0;
    err = linux_send_ioctl_ethtool(&nfccmd, ifname);
    if (err != 0) {
        return -1;
    }

    return nfccmd.rule_cnt;
}

static struct ethtool_ringparam *linux_get_nic_rings(struct ethtool_ringparam *ering, char *ifname) {
    ering->cmd = ETHTOOL_GRINGPARAM;
    if (linux_send_ioctl_ethtool(ering, ifname) != 0)
        return NULL;
    return ering;
}

int linux_get_nic_rx_rings(char *ifname) {
    struct ethtool_ringparam ering = {};
    if (linux_get_nic_rings(&ering, ifname) != NULL)
        return ering.rx_pending;
    return -1;
}

int linux_get_nic_tx_rings(char *ifname) {
    struct ethtool_ringparam ering = {};
    if (linux_get_nic_rings(&ering, ifname) != NULL)
        return ering.tx_pending;
    return -1;
}

int linux_get_nic_max_rx_rings(char *ifname) {
    struct ethtool_ringparam ering = {};
    if (linux_get_nic_rings(&ering, ifname) != NULL)
        return ering.rx_max_pending;
    return -1;
}

int linux_get_nic_max_tx_rings(char *ifname) {
    struct ethtool_ringparam ering = {};
    if (linux_get_nic_rings(&ering, ifname) != NULL)
        return ering.tx_max_pending;
    return -1;
}

int linux_set_nic_rx_tx_rings(int tx, int rx, char *ifname) {
    struct ethtool_ringparam ering = {};
    if (linux_get_nic_rings(&ering, ifname) == NULL)
        return -1;
    ering.cmd = ETHTOOL_SRINGPARAM;
    ering.rx_pending = rx;
    ering.tx_pending = tx;
    if (linux_send_ioctl_ethtool(&ering, ifname) != 0)
        return -1;
    return 1;
}
