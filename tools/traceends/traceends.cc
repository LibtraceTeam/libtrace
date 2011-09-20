#define __STDC_FORMAT_MACROS

#include <libtrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include <map>

typedef struct end_counter {
	uint64_t src_bytes;
	uint64_t src_pbytes;
	uint64_t src_pkts;
	uint64_t dst_pkts;
	uint64_t dst_bytes;
	uint64_t dst_pbytes;

	double last_active;

} end_counter_t;

typedef struct mac_addr {
	uint8_t addr[6];
} mac_addr_t;

struct v6comp {
	bool operator() (const struct in6_addr &a, const struct in6_addr &b) const {
		if (memcmp(&a, &b, sizeof(struct in6_addr)) < 0)
			return true;
		return false;
	}
};
	
struct maccomp {
	bool operator() (const mac_addr_t &a, const mac_addr_t &b) const {
		if (memcmp(&a, &b, sizeof(mac_addr_t)) < 0)
			return true;
		return false;
	}
};

typedef std::map<uint32_t, end_counter_t *> IP4EndMap;
typedef std::map<struct in6_addr, end_counter_t *, v6comp> IP6EndMap;
typedef std::map<mac_addr_t, end_counter_t *, maccomp> MacEndMap;

enum {
	MODE_MAC,
	MODE_IPV4,
	MODE_IPV6
};

int mode = MODE_IPV4;

IP4EndMap ipv4;
IP6EndMap ipv6;
MacEndMap mac;

static int usage(char *argv0)
{
        printf("Usage:\n"
        "%s flags inputuri [inputuri ... ] \n"
        "-f --filter=bpf        Only output packets that match filter\n"
        "-H --help     		Print this message\n"
        "-A --address=addr     	Specifies which address type to match (mac, v4, v6)\n"
        ,argv0);
        exit(1);
}

volatile int done=0;

static void cleanup_signal(int sig)
{
        (void)sig;
        done=1;
	trace_interrupt();
}

static end_counter_t *create_counter() {
	end_counter_t *c = (end_counter_t *)malloc(sizeof(end_counter_t));

	c->src_bytes = 0;
	c->src_pbytes = 0;
	c->src_pkts = 0;
	c->dst_pkts = 0;
	c->dst_bytes = 0;
	c->dst_pbytes = 0;

	c->last_active = 0.0;
	return c;
}

static char *mac_string(mac_addr_t m, char *str) {
	
	
	snprintf(str, 80, "%02x:%02x:%02x:%02x:%02x:%02x", 
		m.addr[0], m.addr[1], m.addr[2], m.addr[3], m.addr[4],
		m.addr[5]);
	return str;
}

static void dump_mac_map() {
	MacEndMap::iterator it;
	char str[80];
	char timestr[80];
	struct tm *tm;
	time_t t;
	
	for (it = mac.begin(); it != mac.end(); it++) {
		t = (time_t)(it->second->last_active);
		tm = localtime(&t);
		strftime(timestr, 80, "%d/%m,%H:%M:%S", tm);
		printf("%18s %16s %16" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16" PRIu64 "\n", 
				mac_string(it->first, str),
				timestr,
				it->second->src_pkts,
				it->second->src_bytes,
				it->second->src_pbytes,
				it->second->dst_pkts,
				it->second->dst_bytes,
				it->second->dst_pbytes);
	}
}

static void dump_ipv4_map() {
	IP4EndMap::iterator it;
	struct in_addr in;
	char timestr[80];
	struct tm *tm;
	time_t t;
	for (it = ipv4.begin(); it != ipv4.end(); it++) {
		in.s_addr = it->first;
		t = (time_t)(it->second->last_active);
		tm = localtime(&t);
		strftime(timestr, 80, "%d/%m,%H:%M:%S", tm);
		printf("%16s %16s %16" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16" PRIu64 "\n", 
				inet_ntoa(in),
				timestr,
				it->second->src_pkts,
				it->second->src_bytes,
				it->second->src_pbytes,
				it->second->dst_pkts,
				it->second->dst_bytes,
				it->second->dst_pbytes);
	}
}

static void dump_ipv6_map() {
	IP6EndMap::iterator it;
	struct in6_addr in;
	char ip6_addr[128];
	char timestr[80];
	struct tm *tm;
	time_t t;

	for (it = ipv6.begin(); it != ipv6.end(); it++) {
		in = it->first;
		t = (time_t)(it->second->last_active);
		tm = localtime(&t);
		strftime(timestr, 80, "%d/%m,%H:%M:%S", tm);
		printf("%40s %16s %16" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16" PRIu64 "\n", 
				inet_ntop(AF_INET6, &in, ip6_addr, 128),
				timestr,
				it->second->src_pkts,
				it->second->src_bytes,
				it->second->src_pbytes,
				it->second->dst_pkts,
				it->second->dst_bytes,
				it->second->dst_pbytes);
	}
}

static void update_ipv6(libtrace_ip6_t *ip, uint16_t ip_len, uint32_t rem, 
		uint32_t plen, 	double ts) {

	struct in6_addr key;
	IP6EndMap::iterator it;
	end_counter_t *c = NULL;

	if (rem < sizeof(libtrace_ip6_t))
		return;
	
	key = ip->ip_src;
	
	it = ipv6.find(key);
	if (it == ipv6.end()) {
		c = create_counter();
		ipv6[key] = c;
	} else {
		c = it->second;
	}

	c->src_pkts ++;
	c->src_pbytes += plen;
	c->src_bytes += ip_len;
	c->last_active = ts;
	
	key = ip->ip_dst;
	
	it = ipv6.find(key);
	if (it == ipv6.end()) {
		c = create_counter();
		ipv6[key] = c;
	} else {
		c = it->second;
	}

	c->dst_pkts ++;
	c->dst_pbytes += plen;
	c->dst_bytes += ip_len;
	c->last_active = ts;
}

static void update_mac(uint8_t *src, uint8_t *dst, uint16_t ip_len,
		uint32_t plen, double ts) {

	mac_addr_t key;
	end_counter_t *c = NULL;
	MacEndMap::iterator it;

	memcpy(&(key.addr), src, sizeof(key.addr));
	it = mac.find(key);
	
	if (it == mac.end()) {
		c = create_counter();
		mac[key] = c;
	} else {
		c = it->second;
	}

	c->src_pkts ++;
	c->src_pbytes += plen;
	c->src_bytes += ip_len;
	c->last_active = ts;

	memcpy(&key.addr, dst, sizeof(key.addr));
	it = mac.find(key);
	
	if (it == mac.end()) {
		c = create_counter();
		mac[key] = c;
	} else {
		c = it->second;
	}

	c->dst_pkts ++;
	c->dst_pbytes += plen;
	c->dst_bytes += ip_len;
	c->last_active = ts;
}

static void update_ipv4(libtrace_ip_t *ip, uint16_t ip_len, uint32_t rem, 
		uint32_t plen, 	double ts) {

	uint32_t key;
	IP4EndMap::iterator it;
	end_counter_t *c = NULL;

	if (rem < sizeof(libtrace_ip_t))
		return;
	
	key = ip->ip_src.s_addr;
	
	it = ipv4.find(key);
	if (it == ipv4.end()) {
		c = create_counter();
		ipv4[key] = c;
	} else {
		c = it->second;
	}

	c->src_pkts ++;
	c->src_pbytes += plen;
	c->src_bytes += ip->ip_len;
	c->last_active = ts;
	
	key = ip->ip_dst.s_addr;
	
	it = ipv4.find(key);
	if (it == ipv4.end()) {
		c = create_counter();
		ipv4[key] = c;
	} else {
		c = it->second;
	}

	c->dst_pkts ++;
	c->dst_pbytes += plen;
	c->dst_bytes += ip_len;
	c->last_active = ts;
}

static int per_packet(libtrace_packet_t *packet) {

	void *header;
	uint16_t ethertype;
	uint32_t rem;
	uint16_t ip_len = 0;
	uint32_t plen = trace_get_payload_length(packet);
	double ts = trace_get_seconds(packet);
	libtrace_ip_t *ip = NULL;
	libtrace_ip6_t *ip6 = NULL;
	uint8_t *src_mac, *dst_mac;

	header = trace_get_layer3(packet, &ethertype, &rem);

	if (header == NULL || rem == 0)
		return 1;
	
	if (ethertype == TRACE_ETHERTYPE_IP) {
		ip = (libtrace_ip_t *)header;
		if (rem < sizeof(libtrace_ip_t))
			return 1;
		ip_len = ntohs(ip->ip_len);
		if (mode == MODE_IPV4 && ip) {
			update_ipv4(ip, ip_len, rem, plen, ts);
			return 1;
		}
	}

	if (ethertype == TRACE_ETHERTYPE_IPV6) {
		ip6 = (libtrace_ip6_t *)header;
		if (rem < sizeof(libtrace_ip6_t))
			return 1;
		ip_len = ntohs(ip6->plen) + sizeof(libtrace_ip6_t);
		if (mode == MODE_IPV6 && ip6) {
			update_ipv6(ip6, ip_len, rem, plen, ts);
			return 1;
		}
	}

	if (mode == MODE_MAC) {
		src_mac = trace_get_source_mac(packet);
		dst_mac = trace_get_destination_mac(packet);

		if (src_mac == NULL || dst_mac == NULL)
			return 1;
		update_mac(src_mac, dst_mac, ip_len, plen, ts);
	}

	return 1;
}

int main(int argc, char *argv[]) {

        int i;
        struct sigaction sigact;
	struct libtrace_filter_t *filter=NULL;
        struct libtrace_t *input = NULL;
        struct libtrace_packet_t *packet = trace_create_packet();

        while(1) {
                int option_index;
                struct option long_options[] = {
                        { "filter",        1, 0, 'f' },
                        { "help", 	   0, 0, 'H' },
			{ "addresses", 	   1, 0, 'A' },	
                        { NULL,            0, 0, 0   },
                };

                int c=getopt_long(argc, argv, "A:f:H",
                                long_options, &option_index);

                if (c==-1)
                        break;
		switch (c) {
			case 'A':
				if (strncmp(optarg, "mac", 3) == 0)
					mode = MODE_MAC;
				else if (strncmp(optarg, "v4", 2) == 0)
					mode = MODE_IPV4;
				else if (strncmp(optarg, "v6", 2) == 0)
					mode = MODE_IPV6;
				else {
					fprintf(stderr, "Invalid address type, must be either mac, v4 or v6\n");
					return 1;
				}
				break;

                        case 'f': filter=trace_create_filter(optarg);
                        	break;
			case 'H':
                                usage(argv[0]);
                                break;
			default:
                                fprintf(stderr,"Unknown option: %c\n",c);
                                usage(argv[0]);
                                return 1;
		}

	}
        sigact.sa_handler = cleanup_signal;
        sigemptyset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;

        sigaction(SIGINT, &sigact, NULL);
        sigaction(SIGTERM, &sigact, NULL);
        sigaction(SIGPIPE, &sigact, NULL);
        sigaction(SIGHUP, &sigact, NULL);

	for (i = optind; i < argc; i++) {
		input = trace_create(argv[i]);

                if (trace_is_err(input)) {
                        trace_perror(input,"%s",argv[i]);
                        return 1;
                }

                if (filter && trace_config(input, TRACE_OPTION_FILTER, filter) == 1) {
                        trace_perror(input, "Configuring filter for %s",
                                        argv[i]);
                        return 1;
                }

                if (trace_start(input)==-1) {
                        trace_perror(input,"%s",argv[i]);
                        return 1;
                }

		while (trace_read_packet(input,packet)>0) {
                        if (per_packet(packet) < 1)
                                done = 1;
                        if (done)
                                break;
                }

                if (done)
                        break;

                if (trace_is_err(input)) {
                        trace_perror(input,"Reading packets");
                        trace_destroy(input);
                        break;
                }

                trace_destroy(input);
        }

	/* Dump results */
	if (mode == MODE_IPV4)
		dump_ipv4_map();
	if (mode == MODE_IPV6)
		dump_ipv6_map();
	if (mode == MODE_MAC)
		dump_mac_map();
	return 0;
}
