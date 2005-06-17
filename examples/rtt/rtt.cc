#include <stdio.h>
#include <assert.h>
#include "libtrace.h"
#include <map>

struct flow_id_t {
	uint32_t ip_a;
	uint32_t ip_b;
	uint16_t port_a;
	uint16_t port_b;

	flow_id_t(void) : 
		ip_a(0), ip_b(0), 
		port_a(0), port_b(0) 
		{};
};

int cmp(const flow_id_t &a, const flow_id_t &b) {
	if (a.ip_a < b.ip_a) 	return -1;
	if (a.ip_a > b.ip_a) 	return 1;

	if (a.ip_b < b.ip_b) 	return -1;
	if (a.ip_b > b.ip_b) 	return 1;

	if (a.port_a < b.port_a) return -1;
	if (a.port_a > b.port_a) return 1;

	if (a.port_b < b.port_b) return -1;
	if (a.port_b > b.port_b) return 1;

	return 0;
}

bool operator <(const flow_id_t &a, const flow_id_t &b) 
{ 
	return cmp(a,b)<0; 
}

typedef uint32_t cookie_t;
typedef double ts_t;

typedef std::map<cookie_t,ts_t> cookie_jar_t;

typedef std::map<flow_id_t, cookie_jar_t > state_info_t;

state_info_t state_info;

struct libtrace_packet_t packet;

/** parse an option
 * @param ptr	the pointer to the current option
 * @param plen	the length of the remaining buffer
 * @param type	the type of the option
 * @param optlen the length of the option
 * @param data	the data of the option
 *
 * @returns bool true if there is another option (and the fields are filled in)
 */
int get_next_option(unsigned char **ptr,int *len,
			unsigned char *type,
			unsigned char *optlen,
			unsigned char **data)
{
	if (*len<=0)
		return 0;
	*type=**ptr;
	switch(*type) {
		case 0: /* End of options */
			return 0;
		case 1: /* Pad */
			(*ptr)++;
			(*len)--;
			return 1;
		default:
			*optlen = *(*ptr+1);
			if (*optlen<2)
				return 0; // I have no idea wtf is going on
					  // with these packets
			(*len)-=*optlen;
			(*data)=(*ptr+2);
			(*ptr)+=*optlen;
			if (*len<0)
				return 0;
			return 1;
	}
	assert(0);
}

void expire(double now)
{
	state_info_t::iterator flow_i = state_info.begin();

        for(; flow_i != state_info.end(); ++flow_i) {
            cookie_jar_t &cookie_jar = flow_i->second;
            cookie_jar_t::iterator cookie_i = cookie_jar.begin();
            for(; cookie_i != cookie_jar.end();) {
                if(now - cookie_i->second > 180) {
                    cookie_jar_t::iterator j = cookie_i;
                    ++j;
                    cookie_jar.erase(cookie_i);
                    cookie_i = j;
                } else {
                    ++cookie_i;
                }
            }
        }
}

void dump_db(void)
{
	fflush(stderr); fflush(stdout);
	for (state_info_t::const_iterator flow_i = state_info.begin();
			flow_i!=state_info.end();
			flow_i++) {
		fprintf(stderr,"%08x:%i -> %08x:%i\n",
			flow_i->first.ip_a,
			flow_i->first.port_a,
			flow_i->first.ip_b,
			flow_i->first.port_b);
		for(cookie_jar_t::const_iterator cookie_i=flow_i->second.begin();
				cookie_i!=flow_i->second.end();
				cookie_i++) {
			fprintf(stderr," %u -> %f\n",cookie_i->first,
						cookie_i->second);
		}
	}
	fprintf(stderr,"\n");
	fflush(stderr); fflush(stdout);
}

int main(int argc, char *argv[])
{
	struct libtrace_t *trace;
	double last = 0;
	struct flow_id_t a,b;
	a.ip_a = 0x7f000001;
	a.ip_b = 0x0ac0ffee;
	a.port_a = 80;
	a.port_b = 1024;
	b.ip_a = 0x0ac0ffee;
	b.ip_b = 0x7f000001;
	b.port_a = 1024;
	b.port_b = 80;

	printf("%i %u %u\n",cmp(a,b),a.ip_a,b.ip_a);

	assert(cmp(a,b)==1);

	trace = trace_create(argv[1]);

	for (;;) {
		struct libtrace_tcp *tcpptr;
		struct libtrace_ip *ipptr;
		int psize;

		if ((psize = trace_read_packet(trace, &packet)) <= 0) {
			break;
		}

		ipptr = trace_get_ip(&packet);
		if (!ipptr)
			continue;

		if (ipptr->ip_p!=6)
			continue;

		tcpptr = trace_get_tcp(&packet);

		if (!tcpptr)
			continue;

		struct flow_id_t fwd; 
		struct flow_id_t rev;
		fwd.ip_a = ipptr->ip_src.s_addr;
		fwd.ip_b = ipptr->ip_dst.s_addr;
		fwd.port_a = tcpptr->source;
		fwd.port_b = tcpptr->dest;

		rev.ip_b = ipptr->ip_src.s_addr;
		rev.ip_a = ipptr->ip_dst.s_addr;
		rev.port_b = tcpptr->source;
		rev.port_a = tcpptr->dest;

		double now = trace_get_seconds(&packet);

		/* search for the timestamp option */	
		unsigned char *pkt = (unsigned char *)tcpptr + sizeof(*tcpptr);
		//int plen = (packet.size-(pkt-(unsigned char*)packet.buffer)) <? (tcpptr->doff*4-sizeof *tcpptr);
		int plen = (tcpptr->doff*4-sizeof *tcpptr);
		unsigned char type = 0;
		unsigned char optlen = 0;
		unsigned char *data = 0;

		while (get_next_option(&pkt,&plen,&type,&optlen,&data)) {
			// ignore non timestamp options
			if (type!=8) {
				continue;
			}
			uint32_t *ts=(uint32_t *)&data[0];
			uint32_t *tsecho=(uint32_t*)&data[4];


                        state_info_t::iterator si = state_info.find(rev);
                        if(si != state_info.end()) {

                            cookie_jar_t &cookie_jar = si->second;
                            cookie_jar_t::iterator ci = cookie_jar.find(*tsecho);
                            if(ci != cookie_jar.end()) {
				printf("%f %.12f\n",
                                        now,
                                        now-ci->second);
                                cookie_jar.erase(ci);
                            }

			    assert(state_info.find(rev)!=state_info.end());
                        }

			if (*ts) {
                                state_info_t::iterator si = state_info.find(fwd);


				if (si==state_info.end()) {
					si = state_info.insert(
					 std::pair< flow_id_t, cookie_jar_t>(
						fwd, cookie_jar_t())).first;
					assert(state_info.find(fwd)!=state_info.end());
				}
				assert(state_info.find(fwd)!=state_info.end());
				cookie_jar_t &cookie_jar = si->second;
				cookie_jar[*ts]=now;
				assert(state_info.find(fwd)!=state_info.end());
			}
		}

		if (now-last>60) {

			last=now;

			expire(now);

		}

	}

	return 0;
}
