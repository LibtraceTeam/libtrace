#include "config.h"

#ifndef HAVE_PCAP_NEXT_EX
#include <stdio.h>
#include <pcap.h>
#ifdef HAVE_PCAP_INT_H
# include <pcap-int.h>
#endif
#include <string.h>
#include <libtrace.h>
#include <stdlib.h>

struct pcap_data_t {
	struct pcap_pkthdr *header;
	u_char *payload;
};


static struct pcap_data_t pcap_data;

static void trace_pcap_handler(u_char *user, const struct pcap_pkthdr *pcaphdr,const u_char *pcappkt) {
        struct pcap_data_t *packet = (struct pcap_data_t *)user;

	/* pcaphdr and pcappkt don't seem to persist for particularly long
	 * so we need to memcpy them. Obviously, this spoils the whole
	 * zero-copy concept but if you're using outdated pcap libraries
	 * you deserve everything you get 
	 */
	memcpy(packet->header, pcaphdr, sizeof(struct pcap_pkthdr));
	memcpy(packet->payload, pcappkt, packet->header->len);
}


int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
                        const u_char **pkt_data) {

	int pcapbytes = 0;

	pcap_data.header = *pkt_header;
	pcap_data.payload = *pkt_data;

	pcapbytes = pcap_dispatch(p, 1, &trace_pcap_handler,
                       (u_char *) &pcap_data);

	if (pcapbytes == -1)
		return -1;

	if (pcapbytes == 0 && pcap_file(p) != NULL)
		return -2;

	if (pcapbytes == 0)
		return 0;

        return 1;
}
#endif
