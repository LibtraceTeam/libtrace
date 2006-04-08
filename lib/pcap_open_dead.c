#include "config.h"

#ifndef HAVE_PCAP_OPEN_DEAD
#include <stdio.h>
#include <pcap.h>
#if HAVE_PCAP_INT_H
# include <pcap-int.h>
#else
# error "Need pcap-int.h for declaration of pcap_t"
#endif
#include <string.h>

pcap_t *pcap_open_dead(int linktype, int snaplen) {
    pcap_t *p = NULL;

    p = (pcap_t *)malloc(sizeof(*p));
    if (p == NULL)
        return NULL;    
  //  memset (p, 0, sizeof(*p));
    p->snapshot = snaplen;
    p->linktype = linktype;
    return p;
}
#endif
