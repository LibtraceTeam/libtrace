/* Show the top 'n' flows from a libtrace source
 *
 */
#define __STDC_FORMAT_MACROS 1
#include "config.h"
#include "libtrace.h"
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <map>
#include <queue>
#include <inttypes.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <assert.h>
#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <net/if_dl.h>
#endif

#if HAVE_NCURSES_NCURSES_H
#include <ncurses/ncurses.h>
#else
#include <ncurses.h>
#endif

typedef enum { BITS_PER_SEC, BYTES, PERCENT } display_t;
display_t display_as = BYTES;
float interval=2;
double last_report=0;

bool use_sip = true;
bool use_dip = true;
bool use_sport = true;
bool use_dport = true;
bool use_protocol = true;
bool quit = false;
bool fullspeed = false;
bool wide_display = false;

uint64_t total_bytes=0;
uint64_t total_packets=0;

int cmp_sockaddr_in6(const struct sockaddr_in6 *a, const struct sockaddr_in6 *b)
{
	if (a->sin6_port != b->sin6_port)
		return a->sin6_port - b->sin6_port;
	return memcmp(a->sin6_addr.s6_addr,b->sin6_addr.s6_addr,sizeof(a->sin6_addr.s6_addr));
}

int cmp_sockaddr_in(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
	if (a->sin_port != b->sin_port)
		return a->sin_port - b->sin_port;
	return a->sin_addr.s_addr - b->sin_addr.s_addr;
}

#ifdef HAVE_NETPACKET_PACKET_H
int cmp_sockaddr_ll(const struct sockaddr_ll *a, const struct sockaddr_ll *b)
{
	return memcmp(a->sll_addr, b->sll_addr, b->sll_halen);
}
#else
int cmp_sockaddr_dl(const struct sockaddr_dl *a, const struct sockaddr_dl *b)
{
	return memcmp(a->sdl_data, b->sdl_data, b->sdl_alen);
}

#endif


int cmp_sockaddr(const struct sockaddr *a, const struct sockaddr *b)
{
	if (a->sa_family != b->sa_family) {
		return a->sa_family - b->sa_family;
	}
	switch (a->sa_family) {
		case AF_INET:
			return cmp_sockaddr_in((struct sockaddr_in *)a,(struct sockaddr_in*)b);
		case AF_INET6:
			return cmp_sockaddr_in6((struct sockaddr_in6 *)a,(struct sockaddr_in6*)b);
#ifdef HAVE_NETPACKET_PACKET_H
		case AF_PACKET:
			return cmp_sockaddr_ll((struct sockaddr_ll *)a,(struct sockaddr_ll*)b);
#else
		case AF_LINK:
			return cmp_sockaddr_dl((struct sockaddr_dl *)a, (struct sockaddr_dl *)b);
#endif
		case AF_UNSPEC:
			return 0; /* Can't compare UNSPEC's! */
		default:
			fprintf(stderr,"Don't know how to compare family %d\n",a->sa_family);
			abort();
	}
}

char *trace_sockaddr2string(const struct sockaddr *a, socklen_t salen, char *buffer, size_t bufflen)
{
	static char intbuffer[NI_MAXHOST];
	char *mybuf = buffer ? buffer : intbuffer;
	size_t mybufflen = buffer ? bufflen : sizeof(intbuffer);
	int err;

	/* Some systems (FreeBSD and Solaris, I'm looking at you) have a bug
	 * where they can't deal with the idea of a sockaddr_storage being
	 * passed into getnameinfo. Linux just deals by looking
	 * at sa_family and figuring out what sockaddr it is really.
	 *
	 * Anyway, the fix appears to be to manually hax the sockaddr length
	 * to be the right value for the underlying family.
	 */
	switch (a->sa_family) {
		case AF_INET:
			salen = sizeof(struct sockaddr_in);
			if ((err=getnameinfo(a, salen, mybuf, mybufflen, NULL, 0, NI_NUMERICHOST))!=0) {
				strncpy(mybuf,gai_strerror(err),mybufflen);
			}
			break;
		case AF_INET6:
			salen = sizeof(struct sockaddr_in6);
			if ((err=getnameinfo(a, salen, mybuf, mybufflen, NULL, 0, NI_NUMERICHOST))!=0) {
				strncpy(mybuf,gai_strerror(err),mybufflen);
			}
			break;
#ifdef HAVE_NETPACKET_PACKET_H
		case AF_PACKET:
			trace_ether_ntoa(((struct sockaddr_ll*)a)->sll_addr, mybuf);
			break;
#else
		case AF_LINK:
			trace_ether_ntoa((uint8_t *)((struct sockaddr_dl *)a)->sdl_data, mybuf);
			break;
#endif
		default:
			snprintf(mybuf,mybufflen,"Unknown family %d",a->sa_family);
	}
	return mybuf;
}

static void set_port_for_sockaddr(struct sockaddr *sa,uint16_t port)
{
	switch (sa->sa_family) {
		case AF_INET:
			((struct sockaddr_in *)sa)->sin_port = htons(port);
			break;
		case AF_INET6:
			((struct sockaddr_in6 *)sa)->sin6_port = htons(port);
			break;
	}
}

static void clear_addr_for_sockaddr(struct sockaddr *sa)
{
	switch (sa->sa_family) {
		case AF_INET:
			((struct sockaddr_in *)sa)->sin_addr.s_addr = 0;
			break;
		case AF_INET6:
			memset((void*)&((struct sockaddr_in6 *)sa)->sin6_addr,0,sizeof(((struct sockaddr_in6 *)sa)->sin6_addr));
			break;
	}
}

static uint16_t get_port_from_sockaddr(struct sockaddr *sa)
{
	switch (sa->sa_family) {
		case AF_INET:
			return ntohs(((struct sockaddr_in *)sa)->sin_port);
			break;
		case AF_INET6:
			return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
			break;
	}

	return 0;
}

struct flowkey_t {
	struct sockaddr_storage sip;
	struct sockaddr_storage dip;
	uint16_t sport;
	uint16_t dport;
	uint8_t protocol;

	bool operator <(const flowkey_t &b) const {
		int c;

		if (use_sip) {
			c = cmp_sockaddr((struct sockaddr*)&sip,(struct sockaddr*)&b.sip);
			if (c != 0) return c<0;
		}
		if (use_dip) {
			c = cmp_sockaddr((struct sockaddr*)&dip,(struct sockaddr*)&b.dip);
			if (c != 0) return c<0;
		}

		return protocol < b.protocol;
	}
};

struct flowdata_t {
	uint64_t packets;
	uint64_t bytes;
};

typedef std::map<flowkey_t,flowdata_t> flows_t;

flows_t flows;

const char *nice_bandwidth(double bytespersec)
{
	static char ret[1024];
	double bitspersec = bytespersec*8;

	if (bitspersec>1e12)
		snprintf(ret,sizeof(ret),"%.03fTb/s", bitspersec/1e12);
	else if (bitspersec>1e9)
		snprintf(ret,sizeof(ret),"%.03fGb/s", bitspersec/1e9);
	else if (bitspersec>1e6)
		snprintf(ret,sizeof(ret),"%.03fMb/s", bitspersec/1e6);
	else if (bitspersec>1e3)
		snprintf(ret,sizeof(ret),"%.03fkb/s", bitspersec/1e3);
	else
		snprintf(ret,sizeof(ret),"%.03fb/s", bitspersec);
	return ret;
}

static void per_packet(libtrace_packet_t *packet)
{
	flowkey_t flowkey;
	flows_t::iterator it;

	if (trace_get_source_address(packet,(struct sockaddr*)&flowkey.sip)==NULL)
		flowkey.sip.ss_family = AF_UNSPEC;

	if (trace_get_destination_address(packet,(struct sockaddr*)&flowkey.dip)==NULL)
		flowkey.dip.ss_family = AF_UNSPEC;

	if (!use_sip)
		clear_addr_for_sockaddr((struct sockaddr *)&flowkey.sip);

	if (!use_dip)
		clear_addr_for_sockaddr((struct sockaddr *)&flowkey.dip);

	if (!use_sport)
		set_port_for_sockaddr((struct sockaddr *)&flowkey.sip,0);

	if (!use_dport) 
		set_port_for_sockaddr((struct sockaddr *)&flowkey.dip,0);

	if (use_protocol && trace_get_transport(packet,&flowkey.protocol, NULL) == NULL)
		flowkey.protocol = 255;


	it = flows.find(flowkey);
	if (it == flows.end()) {
		flowdata_t flowdata = { 0, 0 };
		flows_t::value_type insdata(flowkey,flowdata);
		std::pair<flows_t::iterator,bool> ins= flows.insert(insdata);
		it = ins.first;
	}

	++it->second.packets;
	it->second.bytes+=trace_get_wire_length(packet);

	++total_packets;
	total_bytes+=trace_get_wire_length(packet);

}

struct flow_data_t {
	uint64_t bytes;
	uint64_t packets;
	struct sockaddr_storage sip;
	struct sockaddr_storage dip;
	uint8_t protocol;

	bool operator< (const flow_data_t &b) const {
		if (bytes != b.bytes) return bytes < b.bytes;
		return packets < b.packets;
	}
};

static void do_report()
{
	typedef  std::priority_queue<flow_data_t> pq_t;
	int row,col;
	pq_t pq;
	for(flows_t::const_iterator it=flows.begin();it!=flows.end();++it) {
		flow_data_t data;
		data.bytes = it->second.bytes,
		data.packets = it->second.packets,
		data.sip = it->first.sip;
		data.dip = it->first.dip;
		data.protocol = it->first.protocol;
		pq.push(data);
	}
	getmaxyx(stdscr,row,col);
	move(0,0);
	printw("Total Bytes: %10" PRIu64 " (%s)\tTotal Packets: %10" PRIu64, total_bytes, nice_bandwidth(total_bytes/interval), total_packets);
	clrtoeol();
	attrset(A_REVERSE);
	move(1,0);
	if (use_sip) {
		printw("%*s", wide_display ? 42 : 20, "source ip");
		if (use_sport)
			printw("/");
		else
			printw("\t");
	}
	if (use_sport)
		printw("%s  ", "sport");
	if (use_dip) {
		printw("%*s", wide_display ? 42 : 20, "dest ip");
		if (use_dport)
			printw("/");
		else
			printw("\t");
	}
	if (use_dport)
		printw("%s  ", "dport");
	if (use_protocol)
		printw("%10s\t", "proto");
	switch(display_as) {
		case BYTES:
			printw("%7s","Bytes\t");
			break;
		case BITS_PER_SEC:
			printw("%14s\t","Bits/sec");
			break;
		case PERCENT:
			printw("%% bytes\t");
			break;
	}
	printw("Packets");

	attrset(A_NORMAL);
	char sipstr[1024];
	char dipstr[1024];
	for(int i=1; i<row-3 && !pq.empty(); ++i) {
		move(i+1,0);
		if (use_sip) {
			printw("%*s", wide_display ? 42 : 20, 
					trace_sockaddr2string(
						(struct sockaddr*)&pq.top().sip,
						sizeof(struct sockaddr_storage),
						sipstr,sizeof(sipstr)));
			if (use_sport)
				printw("/");
			else
				printw("\t");
		}
		if (use_sport)
			printw("%-5d  ", get_port_from_sockaddr((struct sockaddr*)&pq.top().sip));
		if (use_dip) {
			printw("%*s", wide_display ? 42 : 20, 
					trace_sockaddr2string(
						(struct sockaddr*)&pq.top().dip,
						sizeof(struct sockaddr_storage),
						dipstr,sizeof(dipstr)));
			if (use_dport)
				printw("/");
			else
				printw("\t");
		}
		if (use_dport)
			printw("%-5d  ", get_port_from_sockaddr((struct sockaddr*)&pq.top().dip));
		if (use_protocol) {
			struct protoent *proto = getprotobynumber(pq.top().protocol);
			if (proto) 
				printw("%-10s  ", proto->p_name);
			else
				printw("%10d  ",pq.top().protocol);
		}
		switch (display_as) {
			case BYTES:
				printw("%7"PRIu64"\t%7"PRIu64"\n",
						pq.top().bytes,
						pq.top().packets);
				break;
			case BITS_PER_SEC:
				printw("%14.03f\t%"PRIu64"\n",
						8.0*pq.top().bytes/interval,
						pq.top().packets);
				break;
			case PERCENT:
				printw("%6.2f%%\t%6.2f%%\n",
						100.0*pq.top().bytes/total_bytes,
						100.0*pq.top().packets/total_packets);
		}
		pq.pop();
	}
	flows.clear();
	total_packets = 0;
	total_bytes = 0;

	clrtobot();
	refresh();
}

static void run_trace(libtrace_t *trace)
{
	libtrace_packet_t *packet = trace_create_packet();
	libtrace_eventobj_t obj;
	fd_set rfds;
	struct timeval sleep_tv;
	struct timeval *tv = NULL;

	do {
		int maxfd=0;
		FD_ZERO(&rfds);
		FD_SET(0, &rfds); /* stdin */
		tv=NULL;
		maxfd=0;

		obj = trace_event(trace, packet);
		switch(obj.type) {
			case TRACE_EVENT_IOWAIT:
				FD_SET(obj.fd, &rfds);
				maxfd = obj.fd;
				break;

			case TRACE_EVENT_SLEEP:
				sleep_tv.tv_sec = (int)obj.seconds;
				sleep_tv.tv_usec = (int)((obj.seconds - sleep_tv.tv_sec)*1000000.0);

				tv = &sleep_tv;
				break;;

			case TRACE_EVENT_TERMINATE:
				trace_destroy_packet(packet);
				return;

			case TRACE_EVENT_PACKET:
				if (obj.size == -1)
					break;
				if (trace_get_seconds(packet) - last_report >= interval) {
					do_report();
						
					last_report=trace_get_seconds(packet);
				}
				if (trace_read_packet(trace,packet) <= 0) {
					obj.size = -1;
					break;
				}
				per_packet(packet);
				continue;
		}

		if (tv && tv->tv_sec > interval) {
			tv->tv_sec = (int)interval;
			tv->tv_usec = 0;
		}

		select(maxfd+1, &rfds, 0, 0, tv);
		if (FD_ISSET(0, &rfds)) {
			switch (getch()) {
				case '%':
					display_as = PERCENT;
					break;
				case 'b':
					display_as = BITS_PER_SEC;
					break;
				case 'B':
					display_as = BYTES;
					break;
				case '\x1b': /* Escape */
				case 'q':
					quit = true;
					trace_destroy_packet(packet);
					return;
				case '1': use_sip 	= !use_sip; break;
				case '2': use_sport 	= !use_sport; break;
				case '3': use_dip 	= !use_dip; break;
				case '4': use_dport 	= !use_dport; break;
				case '5': use_protocol 	= !use_protocol; break;
			}
		}
	} while (obj.type != TRACE_EVENT_TERMINATE || obj.size == -1);

	trace_destroy_packet(packet);
} 

static void usage(char *argv0)
{
	fprintf(stderr,"usage: %s [options] libtraceuri...\n",argv0);
	fprintf(stderr," --filter bpfexpr\n");
	fprintf(stderr," -f bpfexpr\n");
	fprintf(stderr,"\t\tApply a bpf filter expression\n");
	fprintf(stderr," --snaplen snaplen\n");
	fprintf(stderr," -s snaplen\n");
	fprintf(stderr,"\t\tCapture only snaplen bytes\n");
	fprintf(stderr," --promisc 0|1\n");
	fprintf(stderr," -p 0|1\n");
	fprintf(stderr,"\t\tEnable/Disable promiscuous mode\n");
	fprintf(stderr," --bits-per-sec\n");
	fprintf(stderr," -B\n");
	fprintf(stderr,"\t\tDisplay usage in bits per second, not bytes per second\n");
	fprintf(stderr," --percent\n");
	fprintf(stderr," -P\n");
	fprintf(stderr,"\t\tDisplay usage in percentage of total usage\n");
	fprintf(stderr," --interval int\n");
	fprintf(stderr," -i int\n");
	fprintf(stderr,"\t\tUpdate the display every int seconds\n");
	fprintf(stderr," --wide\n");
	fprintf(stderr," -w\n");
	fprintf(stderr,"\t\tExpand IP address fields to fit IPv6 addresses\n");
}

int main(int argc, char *argv[])
{
	libtrace_t *trace;
	libtrace_filter_t *filter=NULL;
	int snaplen=-1;
	int promisc=-1;

	setprotoent(1);

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",		1, 0, 'f' },
			{ "snaplen",		1, 0, 's' },
			{ "promisc",		1, 0, 'p' },
			{ "help",		0, 0, 'h' },
			{ "libtrace-help",	0, 0, 'H' },
			{ "bits-per-sec",	0, 0, 'B' },
			{ "percent",		0, 0, 'P' },
			{ "interval",		1, 0, 'i' },
			{ "fast",		0, 0, 'F' },
			{ "wide", 		0, 0, 'w' },
			{ NULL,			0, 0, 0 }
		};

		int c= getopt_long(argc, argv, "BPf:Fs:p:hHi:w12345",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'f':
				filter=trace_create_filter(optarg);
				break;
			case 'F':
				fullspeed = true;
				break;
			case 's':
				snaplen=atoi(optarg);
				break;
			case 'p':
				promisc=atoi(optarg);
				break;
			case 'H':
				trace_help();
				return 1;
			case 'B':
				display_as = BITS_PER_SEC;
				break;
			case 'P':
				display_as = PERCENT;
				break;
			case 'i':
				interval = atof(optarg);
				if (interval<=0) {
					fprintf(stderr,"Interval must be >0\n");
					return 1;
				}
				break;
			case 'w':
				wide_display = true;
				break;
			case '1': use_sip 	= !use_sip; break;
			case '2': use_sport 	= !use_sport; break;
			case '3': use_dip 	= !use_dip; break;
			case '4': use_dport 	= !use_dport; break;
			case '5': use_protocol 	= !use_protocol; break;
			default:
				fprintf(stderr,"Unknown option: %c\n",c);
				/* FALL THRU */
			case 'h':
				usage(argv[0]);
				return 1;
		}
	}

	if (optind>=argc) {
		fprintf(stderr,"Missing input uri\n");
		usage(argv[0]);
		return 1;
	}

	initscr(); cbreak(); noecho();

	while (!quit && optind<argc) {
		trace = trace_create(argv[optind]);
		++optind;

		if (trace_is_err(trace)) {
			endwin();
			trace_perror(trace,"Opening trace file");
			return 1;
		}

		if (snaplen>0)
			if (trace_config(trace,TRACE_OPTION_SNAPLEN,&snaplen)) {
				trace_perror(trace,"ignoring: ");
			}
		if (filter)
			if (trace_config(trace,TRACE_OPTION_FILTER,filter)) {
				trace_perror(trace,"ignoring: ");
			}
		if (promisc!=-1) {
			if (trace_config(trace,TRACE_OPTION_PROMISC,&promisc)) {
				trace_perror(trace,"ignoring: ");
			}
		}
		if (fullspeed) {
			int flag=1;
			if (trace_config(trace,TRACE_OPTION_EVENT_REALTIME,&flag)) {
				trace_perror(trace,"Setting EVENT_REALTIME option");
			}
		}

		if (trace_start(trace)) {
			endwin();
			trace_perror(trace,"Starting trace");
			trace_destroy(trace);
			return 1;
		}

		run_trace(trace);

		if (trace_is_err(trace)) {
			trace_perror(trace,"Reading packets");
		}

		trace_destroy(trace);
	}

	endwin();
	endprotoent();

	return 0;
}
