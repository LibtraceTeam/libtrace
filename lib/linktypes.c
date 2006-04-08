#include "libtrace.h"
#ifdef HAVE_PCAP
#include <pcap.h>
#endif
#include "dagformat.h"
#include "rt_protocol.h"
#include <assert.h>

/* This file maps libtrace types to/from pcap DLT and erf types
 *
 * When adding a new linktype to libtrace, add the mapping(s) here,
 * and add the understanding of the type to get_ip(), and perhaps
 * get_{source,destination}_mac (if your linklayer has mac's)
 */

libtrace_linktype_t pcap_dlt_to_libtrace(int dlt)
{
	switch(dlt) {
#if HAVE_PCAP
		case DLT_NULL: return TRACE_TYPE_NONE;
		case DLT_EN10MB: return TRACE_TYPE_ETH;
		case DLT_ATM_RFC1483: return TRACE_TYPE_ATM;
		case DLT_IEEE802_11: return TRACE_TYPE_80211;
#ifdef DLT_LINUX_SLL
		case DLT_LINUX_SLL: return TRACE_TYPE_LINUX_SLL;
#endif
#ifdef DLT_PFLOG
		case DLT_PFLOG: return TRACE_TYPE_PFLOG;
#endif
#endif
	}
	return -1;
}

int libtrace_to_pcap_dlt(libtrace_linktype_t type)
{
	switch(type) {
#ifdef HAVE_PCAP
		case TRACE_TYPE_NONE: return DLT_NULL;
		case TRACE_TYPE_ETH: return DLT_EN10MB;
		case TRACE_TYPE_ATM: return DLT_ATM_RFC1483;
		case TRACE_TYPE_80211: return DLT_IEEE802_11;
#ifdef DLT_LINUX_SLL
		case TRACE_TYPE_LINUX_SLL: return DLT_LINUX_SLL;
#endif
#ifdef DLT_PFLOG
		case TRACE_TYPE_PFLOG: return DLT_PFLOG;
#endif
#endif
	}
	return -1;
}

enum rt_field_t pcap_dlt_to_rt(int dlt) 
{
	/* For pcap the rt type is just the dlt + a fixed value */
	return dlt + RT_DATA_PCAP;
}

int rt_to_pcap_dlt(enum rt_field_t rt_type)
{
	assert(rt_type >= RT_DATA_PCAP);
	return rt_type - RT_DATA_PCAP;
}

libtrace_linktype_t erf_type_to_libtrace(char erf)
{
	switch (erf) {
		case TYPE_LEGACY:	return TRACE_TYPE_LEGACY;
		case TYPE_HDLC_POS:	return TRACE_TYPE_HDLC_POS;
		case TYPE_ETH:		return TRACE_TYPE_ETH;
		case TYPE_ATM:		return TRACE_TYPE_ATM;
		case TYPE_AAL5:		return TRACE_TYPE_AAL5;
	}
	return -1;
}

char libtrace_to_erf_type(libtrace_linktype_t linktype)
{
	switch(linktype) {
		case TRACE_TYPE_LEGACY:	return TYPE_LEGACY;
		case TRACE_TYPE_ETH:	return TYPE_ETH;
		case TRACE_TYPE_ATM:	return TYPE_ATM;
	}
	return -1;
}
