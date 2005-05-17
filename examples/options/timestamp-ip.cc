#include <stdio.h>
#include "libtrace.h"
#include <map>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

typedef std::map<uint32_t,std::pair<uint64_t,uint64_t> > ip2with_t;
ip2with_t ip2with;

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
	if (*len<=0) {
//		printf("Missing End of Options\n");
		return 0;
	}
	*type=**ptr;
	switch(*type) {
		case 0: /* End of options */
	//		printf("End of option\n");
			return 0;
		case 1: /* Pad */
			(*ptr)++;
			(*len)--;
			return 1;
		default:
		case 6: // ECHO (obsolete)
		case 7: // ECHO Reply (obsolete)
		case 9: // Partial ordering
		case 10: // Partial ordering service profile
		case 11: // CC
		case 13: // CC.ECHO
		case 14: // Alternative checksum request
		case 15: // Alternative checksum data
		case 16: // Skeeter
		case 17: // Bubba
		case 18: // Trailer checksum
		case 19: // Md5 signature
		case 20: // SCPS capability
		case 21: // Selective NACK
		case 22: // Record boundary
		case 23: // Corruption experienced
		case 24: // SNAP
		case 25: // Unassigned
		case 26: // TCP Compression filter
			printf("Unknown option type (%i)\n",*type);
		case 2: // MSS
		case 3: // WS
		case 4: // SACK permitted
		case 5: // SACK
		case 8: // Timestamp
		case 12: // CC.new
			*optlen = *(*ptr+1);
			if (*optlen<2) {
				printf("Optlen <2?! %i\n",*optlen);
				return 0; // I have no idea wtf is going on
					  // with these packets
			}
			(*len)-=(unsigned int)*optlen;
			(*data)=(*ptr+2);
			(*ptr)+=*optlen;
			if (*len<0) {
				printf("Option longer than option area (%i > %i)\n",*optlen,*len+*optlen);
				return 0;
			}
			return 1;
	}
	assert(0);
}

int main(int argc, char *argv[])
{
	struct libtrace_t *trace;
	double last = 0;

	trace = trace_create(argv[1]);

	for (;;) {
		struct libtrace_tcp *tcpptr;
		struct libtrace_ip *ipptr;
		int psize;

		if ((psize = trace_read_packet(trace, &packet)) <= 0) {
			break;
		}

		ipptr = trace_get_ip(&packet);
		tcpptr = trace_get_tcp(&packet);

		if (!tcpptr)
			continue;

		if (!tcpptr->syn)
			continue;

		double now = trace_get_seconds(&packet);

		/* search for the timestamp option */	
		unsigned char *pkt = (unsigned char *)tcpptr + sizeof(*tcpptr);
		//int plen = (packet.size-(pkt-(unsigned char*)packet.buffer)) <? (tcpptr->doff*4-sizeof *tcpptr);
		int plen = (tcpptr->doff*4-sizeof *tcpptr);
		unsigned char type = 0;
		unsigned char optlen = 0;
		unsigned char *data = 0;
		bool flag = false;


		while (get_next_option(&pkt,&plen,&type,&optlen,&data) != 0) {
			// ignore non timestamp options
			if (type!=8) {
				continue;
			}

			flag=true;
		}

		if (flag) 
			ip2with[ipptr->ip_src.s_addr].first++;
		else
			ip2with[ipptr->ip_src.s_addr].second++;


		if (now-last>60) {

			last=now;

			printf("\n");

			for(ip2with_t::const_iterator i=ip2with.begin();
					i!=ip2with.end();
					i++) {
				if (i->second.first + i->second.second < 100)
					continue;
				printf("%-16s: %6lli %6lli\n",
						inet_ntoa(*(struct in_addr *)&i->first),
						i->second.first,
						i->second.second);
			}

		}

	}

	return 0;
}
