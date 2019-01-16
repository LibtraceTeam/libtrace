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
 */


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

#include "libtrace_parallel.h"

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


typedef struct traceend_global {
        int mode;
        int threads;
        int track_source;
        int track_dest;
} global_t;

typedef struct traceend_local {
        union {
                IP4EndMap *ipv4;
                IP6EndMap *ipv6;
                MacEndMap *mac;
        } map;
} local_t;

typedef struct traceend_result_local {
        union {
                IP4EndMap *ipv4;
                IP6EndMap *ipv6;
                MacEndMap *mac;
        } map;
        int threads_reported;
} result_t;

libtrace_t *currenttrace = NULL;

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

static void cleanup_signal(int sig)
{
        (void)sig;
        if (currenttrace) {
        	trace_pstop(currenttrace);
        }
}

static void *cb_starting(libtrace_t *trace UNUSED, libtrace_thread_t *t UNUSED,
                void *global) {

        global_t *glob = (global_t *)global;
        local_t *local = (local_t *)malloc(sizeof(local_t));

        switch(glob->mode) {
                case MODE_IPV4:
                        local->map.ipv4 = new IP4EndMap();
                        break;
                case MODE_IPV6:
                        local->map.ipv6 = new IP6EndMap();
                        break;
                case MODE_MAC:
                        local->map.mac = new MacEndMap();
                        break;
        }
        return local;

}

static void cb_stopping(libtrace_t *trace, libtrace_thread_t *t,
                void *global UNUSED, void *tls) {

        local_t *local = (local_t *)tls;
        libtrace_generic_t gen;

        gen.ptr = local;
        trace_publish_result(trace, t, 0, gen, RESULT_USER);
}

static inline end_counter_t *create_counter() {
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

static inline char *mac_string(mac_addr_t m, char *str) {
	snprintf(str, 80, "%02x:%02x:%02x:%02x:%02x:%02x", 
		m.addr[0], m.addr[1], m.addr[2], m.addr[3], m.addr[4],
		m.addr[5]);
	return str;
}

static inline void combine_counters(end_counter_t *c, end_counter_t *c2) {

        c->src_pkts += c2->src_pkts;
        c->src_bytes += c2->src_bytes;
        c->src_pbytes += c2->src_pbytes;
        c->dst_pkts += c2->dst_pkts;
        c->dst_bytes += c2->dst_bytes;
        c->dst_pbytes += c2->dst_pbytes;

}

static void combine_mac_maps(MacEndMap *dst, MacEndMap *src) {

        MacEndMap::iterator it;
        MacEndMap::iterator found;

        for (it = src->begin(); it != src->end(); it++) {
                found = dst->find(it->first);

                if (found == dst->end()) {
                        (*dst)[it->first] = it->second;
                        continue;
                }

                combine_counters(found->second, it->second);
                free(it->second);
        }

}

static void combine_ipv4_maps(IP4EndMap *dst, IP4EndMap *src) {

        IP4EndMap::iterator it;
        IP4EndMap::iterator found;

        for (it = src->begin(); it != src->end(); it++) {
                found = dst->find(it->first);

                if (found == dst->end()) {
                        (*dst)[it->first] = it->second;
                        continue;
                }

                combine_counters(found->second, it->second);
                free(it->second);
        }

}

static void combine_ipv6_maps(IP6EndMap *dst, IP6EndMap *src) {

        IP6EndMap::iterator it;
        IP6EndMap::iterator found;

        for (it = src->begin(); it != src->end(); it++) {
                found = dst->find(it->first);

                if (found == dst->end()) {
                        (*dst)[it->first] = it->second;
                        continue;
                }

                combine_counters(found->second, it->second);
                free(it->second);
        }

}

static void dump_ipv4_map(IP4EndMap *ipv4, bool destroy) {
	IP4EndMap::iterator it;
	struct in_addr in;
	char timestr[80];
	struct tm *tm;
	time_t t;
	for (it = ipv4->begin(); it != ipv4->end(); it++) {
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
                if (destroy) {
                       free(it->second);
                }
	}
}

static void dump_ipv6_map(IP6EndMap *ipv6, bool destroy) {
	IP6EndMap::iterator it;
	struct in6_addr in;
	char ip6_addr[128];
	char timestr[80];
	struct tm *tm;
	time_t t;

	for (it = ipv6->begin(); it != ipv6->end(); it++) {
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
                if (destroy) {
                       free(it->second);
                }
	}
}

static void dump_mac_map(MacEndMap *mac, bool destroy) {
	MacEndMap::iterator it;
	char str[80];
	char timestr[80];
	struct tm *tm;
	time_t t;

	for (it = mac->begin(); it != mac->end(); it++) {
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
                if (destroy) {
                       free(it->second);
                }
	}
}

static void update_ipv6(global_t *glob,
                local_t *local, libtrace_ip6_t *ip, uint16_t ip_len,
                uint32_t rem, uint32_t plen, 	double ts) {

	struct in6_addr key;
	IP6EndMap::iterator it;
	end_counter_t *c = NULL;

	if (rem < sizeof(libtrace_ip6_t))
		return;
        if (glob->track_source) {
                key = ip->ip_src;

                it = local->map.ipv6->find(key);
                if (it == local->map.ipv6->end()) {
                        c = create_counter();
                        (*(local->map.ipv6))[key] = c;
                } else {
                        c = it->second;
                }

                c->src_pkts ++;
                c->src_pbytes += plen;
                c->src_bytes += ip_len;
                if (ts != 0)
                        c->last_active = ts;
        }

        if (glob->track_dest) {
                key = ip->ip_dst;

                it = local->map.ipv6->find(key);
                if (it == local->map.ipv6->end()) {
                        c = create_counter();
                        (*(local->map.ipv6))[key] = c;
                } else {
                        c = it->second;
                }

                c->dst_pkts ++;
                c->dst_pbytes += plen;
                c->dst_bytes += ip_len;
                if (ts != 0)
                        c->last_active = ts;
        }
}

static void update_mac(global_t *glob, local_t *local,
                uint8_t *src, uint8_t *dst, uint16_t ip_len,
		uint32_t plen, double ts) {

	mac_addr_t key;
	end_counter_t *c = NULL;
	MacEndMap::iterator it;

        if (glob->track_source) {
                memcpy(&(key.addr), src, sizeof(key.addr));
                it = local->map.mac->find(key);

                if (it == local->map.mac->end()) {
                        c = create_counter();
                        (*(local->map.mac))[key] = c;
                } else {
                        c = it->second;
                }

                c->src_pkts ++;
                c->src_pbytes += plen;
                c->src_bytes += ip_len;
                c->last_active = ts;
        }

        if (glob->track_dest) {
                memcpy(&key.addr, dst, sizeof(key.addr));
                it = local->map.mac->find(key);

                if (it == local->map.mac->end()) {
                        c = create_counter();
                        (*(local->map.mac))[key] = c;
                } else {
                        c = it->second;
                }

                c->dst_pkts ++;
                c->dst_pbytes += plen;
                c->dst_bytes += ip_len;
                c->last_active = ts;
        }
}

static void update_ipv4(global_t *glob,
                local_t *local, libtrace_ip_t *ip, uint16_t ip_len,
                uint32_t rem, uint32_t plen, double ts) {

	uint32_t key;
	IP4EndMap::iterator it;
	end_counter_t *c = NULL;

	if (rem < sizeof(libtrace_ip_t))
		return;

        if (glob->track_source) {
                key = ip->ip_src.s_addr;

                it = local->map.ipv4->find(key);
                if (it == local->map.ipv4->end()) {
                        c = create_counter();
                        (*(local->map.ipv4))[key] = c;
                } else {
                        c = it->second;
                }

                c->src_pkts ++;
                c->src_pbytes += plen;
                c->src_bytes += ip->ip_len;
                if (ts != 0)
                        c->last_active = ts;
        }

        if (glob->track_dest) {
                key = ip->ip_dst.s_addr;

                it = local->map.ipv4->find(key);
                if (it == local->map.ipv4->end()) {
                        c = create_counter();
                        (*(local->map.ipv4))[key] = c;
                } else {
                        c = it->second;
                }

                c->dst_pkts ++;
                c->dst_pbytes += plen;
                c->dst_bytes += ip_len;
                if (ts != 0)
                        c->last_active = ts;
        }
}

static void *cb_result_starting(libtrace_t *trace UNUSED,
                libtrace_thread_t *t UNUSED, void *global) {

        global_t *glob = (global_t *)global;
        result_t *res = (result_t *)malloc(sizeof(result_t));

        switch(glob->mode) {
                case MODE_IPV4:
                        res->map.ipv4 = new IP4EndMap();
                        break;
                case MODE_IPV6:
                        res->map.ipv6 = new IP6EndMap();
                        break;
                case MODE_MAC:
                        res->map.mac = new MacEndMap();
                        break;
        }
        res->threads_reported = 0;
        return res;
}

static void cb_result(libtrace_t *trace UNUSED,
                libtrace_thread_t *sender UNUSED, void *global,
                void *tls, libtrace_result_t *result) {

        global_t *glob = (global_t *)global;
        result_t *res = (result_t *)tls;
        local_t *recvd = (local_t *)(result->value.ptr);


        switch(glob->mode) {
                case MODE_IPV4:
                        combine_ipv4_maps(res->map.ipv4, recvd->map.ipv4);
                        delete(recvd->map.ipv4);
                        break;
                case MODE_IPV6:
                        combine_ipv6_maps(res->map.ipv6, recvd->map.ipv6);
                        delete(recvd->map.ipv6);
                        break;
                case MODE_MAC:
                        combine_mac_maps(res->map.mac, recvd->map.mac);
                        delete(recvd->map.mac);
                        break;
        }
        res->threads_reported ++;
        free(recvd);
}

static void cb_result_stopping(libtrace_t *trace UNUSED,
                libtrace_thread_t *t UNUSED, void *global, void *tls) {

        global_t *glob = (global_t *)global;
        result_t *res = (result_t *)tls;
        switch(glob->mode) {
                case MODE_IPV4:
                        dump_ipv4_map(res->map.ipv4, 1);
                        delete(res->map.ipv4);
                        break;
                case MODE_IPV6:
                        dump_ipv6_map(res->map.ipv6, 1);
                        delete(res->map.ipv6);
                        break;
                case MODE_MAC:
                        dump_mac_map(res->map.mac, 1);
                        delete(res->map.mac);
                        break;
        }
        free(res);
}


static libtrace_packet_t *cb_packet(libtrace_t *trace, libtrace_thread_t *t,
                void *global, void *tls, libtrace_packet_t *packet) {

        global_t *glob = (global_t *)global;
        local_t *local = (local_t *)tls;
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
		return packet;

	if (ethertype == TRACE_ETHERTYPE_IP) {
		ip = (libtrace_ip_t *)header;
		if (rem < sizeof(libtrace_ip_t))
			goto endpacketcb;
		ip_len = ntohs(ip->ip_len);
		if (glob->mode == MODE_IPV4 && ip) {
			update_ipv4(glob, local, ip, ip_len, rem, plen, ts);
			goto endpacketcb;
		}
	}

	if (ethertype == TRACE_ETHERTYPE_IPV6) {
		ip6 = (libtrace_ip6_t *)header;
		if (rem < sizeof(libtrace_ip6_t))
			goto endpacketcb;
		ip_len = ntohs(ip6->plen) + sizeof(libtrace_ip6_t);
		if (glob->mode == MODE_IPV6 && ip6) {
			update_ipv6(glob, local, ip6, ip_len, rem, plen, ts);
			goto endpacketcb;
		}
	}

	if (glob->mode == MODE_MAC) {
		src_mac = trace_get_source_mac(packet);
		dst_mac = trace_get_destination_mac(packet);

		if (src_mac == NULL || dst_mac == NULL)
		        goto endpacketcb;
		update_mac(glob, local, src_mac, dst_mac, ip_len, plen, ts);
	}

endpacketcb:
	return packet;
}

int main(int argc, char *argv[]) {

        int i;
        int threads = 1;
        struct sigaction sigact;
	struct libtrace_filter_t *filter=NULL;
        struct libtrace_t *input = NULL;
        global_t glob;
        libtrace_callback_set_t *pktcbs, *repcbs;

        glob.mode = MODE_IPV4;
        glob.track_source = 1;
        glob.track_dest = 1;

        while(1) {
                int option_index;
                struct option long_options[] = {
                        { "filter",        1, 0, 'f' },
                        { "help", 	   0, 0, 'H' },
			{ "addresses", 	   1, 0, 'A' },	
			{ "threads", 	   1, 0, 't' },	
			{ "ignore-dest", 	   0, 0, 'D' },	
			{ "ignore-source", 	   0, 0, 'S' },	
                        { NULL,            0, 0, 0   },
                };

                int c=getopt_long(argc, argv, "A:f:t:HDS",
                                long_options, &option_index);

                if (c==-1)
                        break;
		switch (c) {
			case 'A':
				if (strncmp(optarg, "mac", 3) == 0)
					glob.mode = MODE_MAC;
				else if (strncmp(optarg, "v4", 2) == 0)
					glob.mode = MODE_IPV4;
				else if (strncmp(optarg, "v6", 2) == 0)
					glob.mode = MODE_IPV6;
				else {
					fprintf(stderr, "Invalid address type, must be either mac, v4 or v6\n");
					return 1;
				}
				break;
                        case 'D':
                                glob.track_dest = 0;
                                break;
                        case 'f': filter=trace_create_filter(optarg);
                        	break;
			case 'H':
                                usage(argv[0]);
                                break;
                        case 'S':
                                glob.track_source = 0;
                                break;
                        case 't':
                                threads = atoi(optarg);
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

        if (threads <= 0) {
                threads = 1;
        }
        glob.threads = threads;

        if (glob.track_source == 0 && glob.track_dest == 0) {
                fprintf(stderr, "Bad configuration -- ignoring both source and dest endpoints will produce\nno results!\n");
                usage(argv[0]);
                return 1;
        }

	for (i = optind; i < argc; i++) {
		input = trace_create(argv[i]);

                if (trace_is_err(input)) {
                        trace_perror(input,"%s",argv[i]);
                        trace_destroy(input);
                        return 1;
                }

                if (filter && trace_config(input, TRACE_OPTION_FILTER, filter) == 1) {
                        trace_perror(input, "Configuring filter for %s",
                                        argv[i]);
                        return 1;
                }

                trace_set_combiner(input, &combiner_unordered,
                        (libtrace_generic_t){0});
                trace_set_perpkt_threads(input, threads);

                pktcbs = trace_create_callback_set();
                trace_set_starting_cb(pktcbs, cb_starting);
                trace_set_stopping_cb(pktcbs, cb_stopping);
                trace_set_packet_cb(pktcbs, cb_packet);

                repcbs = trace_create_callback_set();
                trace_set_starting_cb(repcbs, cb_result_starting);
                trace_set_stopping_cb(repcbs, cb_result_stopping);
                trace_set_result_cb(repcbs, cb_result);

                currenttrace = input;
                if (trace_pstart(input, &glob, pktcbs, repcbs) == -1) {
                        trace_perror(input, "Failed to start trace");
                        trace_destroy(input);
                        trace_destroy_callback_set(pktcbs);
                        trace_destroy_callback_set(repcbs);
                        return 1;
                }

                trace_join(input);

                if (trace_is_err(input)) {
                        trace_perror(input,"Reading packets");
                        trace_destroy(input);
                        break;
                }

                currenttrace = NULL;
                trace_destroy(input);
                trace_destroy_callback_set(pktcbs);
                trace_destroy_callback_set(repcbs);
        }

	return 0;
}
