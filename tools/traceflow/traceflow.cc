#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <map>
#include <list>

#include "libtrace.h"
#include "connid.h"

uint32_t info_freq = 180;
double last_report = 0.0;

uint32_t new_flows = 0;
uint32_t f_exp = 0;

class Direction {
	public:
		uint32_t packet_count;
		uint32_t byte_count;

		Direction() {
			this->packet_count = 0;
			this->byte_count = 0;
		}
};

typedef std::list<class Flow*> FlowList;

class Flow {
	public:
		Connid id;
		double expiry_ts;
		Direction dir[2];
	
		double first_pkt_ts;
		double last_pkt_ts;
		
		FlowList *flow_list;	
	
		Flow(const Connid conn_id) {
			this->id = conn_id;
			this->expiry_ts = 0;
			this->first_pkt_ts = 0;
			this->last_pkt_ts = 0;
		}
};

typedef std::map<Connid, FlowList::iterator> FlowMap;
typedef std::list<class Flow *> ExpiredFlowList;

FlowList active_lru;
FlowList inactive;

FlowMap active_flows;
ExpiredFlowList expired_flows;

Flow *getFlow(libtrace_packet_t *packet) {
	uint16_t src_port, dst_port;
	libtrace_ip_t *ip;
	Connid pkt_id;

	ip = trace_get_ip(packet);
        src_port = trace_get_source_port(packet);
        dst_port = trace_get_destination_port(packet);

        if (trace_get_server_port(ip->ip_p, src_port, dst_port) == USE_SOURCE) {
                /* Server port = source port */
                pkt_id = Connid(ip->ip_src.s_addr, ip->ip_dst.s_addr,
                                        src_port, dst_port, ip->ip_p);
        } else {
                /* Server port = dest port */
                pkt_id = Connid(ip->ip_dst.s_addr, ip->ip_src.s_addr,
                                        dst_port, src_port, ip->ip_p);
        }

        /* Is it in the map? */
        FlowMap::iterator i = active_flows.find(pkt_id);

        if (i != active_flows.end()) {
                Flow * pkt_flow = *((*i).second);
		return pkt_flow;
        }
	
	
        /* Not in map - new connection */
	Flow *new_flow = new Flow(pkt_id);
        new_flow->flow_list = &active_lru;
        new_flow->first_pkt_ts = trace_get_seconds(packet);
	active_lru.push_front(new_flow);
        active_flows[new_flow->id] = active_lru.begin();
        new_flows ++;
	return new_flow;

}

void update_expiry(Flow *flow, double ts) {
	
	double timeout = 5.0;
	FlowList *lru = &active_lru;
	
	flow->expiry_ts = ts + timeout;
	flow->flow_list->erase(active_flows[flow->id]);
	flow->flow_list = lru;
	lru->push_front(flow);
	active_flows[flow->id] = lru->begin();
}


void expire_conns_lru(FlowList *lru, double ts) {

	FlowList::iterator i;
	while (!lru->empty()) {
		Flow *flow = lru->back();
		if (flow->expiry_ts <= ts) {
			lru->pop_back();
			/* Move into inactive list */
			flow->flow_list = &inactive;
			inactive.push_front(flow);
			active_flows[flow->id] = inactive.begin();
		} else {
			break;
		}
	}
}

double extract_data(Flow *pkt_flow, libtrace_packet_t *packet) {
	double timestamp = trace_get_seconds(packet);
	libtrace_ip_t *ip = trace_get_ip(packet);
	libtrace_direction_t pkt_dir = trace_get_direction(packet);
	
	uint32_t ip_pkt_size = ntohs(ip->ip_len);
	pkt_flow->dir[pkt_dir].byte_count += ip_pkt_size;
	pkt_flow->dir[pkt_dir].packet_count ++;

	update_expiry(pkt_flow, timestamp);
	expire_conns_lru(&active_lru, timestamp);
	
	return timestamp;
		
}

void print_flow_stdout(Flow *f) {
	
	/* Textual representation - good for testing :] */	
	printf("%s ", f->id.get_server_ip_str());
	printf("%s ", f->id.get_client_ip_str());
	printf("%u ", f->id.get_server_port());
	printf("%u ", f->id.get_client_port());
	printf("%u\n", f->id.get_protocol());

	printf("\t Outgoing Bytes: %-14u\tOutgoing Packets: %-10u\n", f->dir[0].byte_count, f->dir[0].packet_count);
	printf("\t Incoming Bytes: %-14u\tIncoming Packets: %-10u\n", f->dir[1].byte_count, f->dir[1].packet_count);
	fflush(stdout);	
}

void export_flow(Flow *f) {
	print_flow_stdout(f);

}

void calc_expiry_ts(Flow *f) {
	double interval = (f->last_pkt_ts - f->first_pkt_ts) / (f->dir[0].packet_count + f->dir[1].packet_count);

	double exp_time = f->last_pkt_ts + (interval * 20);
	f->expiry_ts = exp_time;
}

void produce_report(double report_time) {
	printf("Report produced at %.6f trace time\n", report_time);
	
	printf("Active Flows\n");
	printf("-------------------------\n");

	FlowList::iterator i;
	for (i = active_lru.begin(); i != active_lru.end(); i++) {
		Flow *f = *i;

		export_flow(f);
	}
	
	for (i = inactive.begin(); i != inactive.end();) {
		Flow *f = *i;

		calc_expiry_ts(f);
		if (f->expiry_ts < report_time) {
			expired_flows.push_front(f);
			inactive.erase(i++);
			active_flows.erase(f->id);
		} else {
			export_flow(f);
			++i;
		}
	}
	
	
	printf("\nExpired Flows\n");
	printf("===========================\n");

	
	while (!expired_flows.empty()) {
		
		Flow *f = expired_flows.front();
		export_flow(f);
		f_exp ++;
		expired_flows.pop_front();
		delete(f);	
	}
	expired_flows.clear();
	assert(expired_flows.size() == 0);
	printf("**********************\n");
	printf("New flows added since last report: %d\n", new_flows);
	printf("Flows expired since last report: %d\n", f_exp);
	printf("Unexpired flows: %d\n", active_lru.size() + inactive.size());
	printf("**********************\n\n");
	
	new_flows = 0;
	f_exp = 0;
}

void per_packet(libtrace_packet_t *packet) {
	double timestamp;

	if (trace_get_ip(packet) == NULL) return;

	Flow * pkt_flow = getFlow(packet);
	timestamp = extract_data(pkt_flow, packet);
	if (timestamp < 0)
		return;

	pkt_flow->last_pkt_ts = timestamp;
	if (last_report == 0.0)
		last_report = timestamp;
	
	if (timestamp > last_report + info_freq) {
		last_report += info_freq;
		produce_report(last_report);
	}
}

void usage(char *prog) {
	fprintf(stderr,"Usage: %s tracefile...\n",prog);
}

int main(int argc, char *argv[]) {

	int opt;
	libtrace_t *trace;
	libtrace_packet_t *packet;

	while ((opt = getopt(argc, argv, "f:")) != EOF) {
		switch(opt) {
			case 'f':
				printf("Filtering not supported yet\n");
				break;
			default:
				usage(argv[0]);
		}
	}

	if (optind + 1 > argc) {
		usage(argv[0]);
		return 1;
	}
	packet = trace_create_packet();

	for (int i = optind; i < argc; i++) {
		trace = trace_create(argv[i]);

		if (trace_is_err(trace)) {
                        trace_perror(trace,"Opening trace file");
                        return 1;
                }

                if (trace_start(trace)) {
                        trace_perror(trace,"Starting trace");
                        trace_destroy(trace);
                        return 1;
                }


                while (trace_read_packet(trace,packet)>0) {
                        per_packet(packet);
                }


                if (trace_is_err(trace)) {
                        trace_perror(trace,"Reading packets");
                        trace_destroy(trace);
                        continue;
                }

                trace_destroy(trace);
        }
	trace_destroy_packet(packet);
	return 0;
}	
