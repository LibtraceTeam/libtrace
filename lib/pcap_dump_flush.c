#ifdef HAVE_PCAP
#include "config.h"

#ifndef HAVE_PCAP_DUMP_FLUSH
#include <stdio.h>
#include <pcap.h>
#ifdef HAVE_PCAP_INT_H
# include <pcap-int.h>
#endif
#include <string.h>

int pcap_dump_flush(pcap_dumper_t *p) {
	if (fflush((FILE *)p) == EOF)
		return (-1);
	else
		return (0);
}

#endif

#endif // HAVE_PCAP
