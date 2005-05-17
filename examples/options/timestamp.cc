#include <stdio.h>
#include "libtrace.h"
#include <map>

uint64_t with_ts[4][65536];
uint64_t without_ts[4][65536];

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
		int psize;

		if ((psize = trace_read_packet(trace, &packet)) <= 0) {
			break;
		}

		tcpptr = trace_get_tcp(&packet);

		int dir = trace_get_direction(&packet);

		if (!tcpptr)
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

		if (flag) {
			if (htons(tcpptr->dest) < htons(tcpptr->source))
				with_ts[dir][htons(tcpptr->dest)]++;
			else
				with_ts[dir][htons(tcpptr->source)]++;
		}
		else {
			if (htons(tcpptr->dest) < htons(tcpptr->source))
				without_ts[dir][htons(tcpptr->dest)]++;
			else
				without_ts[dir][htons(tcpptr->source)]++;
		}

		if (now-last>60) {
			int i=0;

			last=now;

			printf("\n");
			uint64_t with=0;
			uint64_t without=0;
			for(i=0;i<65535;i++) {
				if (with_ts[0][i]+without_ts[0][i]+
				with_ts[1][i]+without_ts[1][i]		<20)
					continue;
				printf("%6i: %6lli %6lli  %6lli %6lli (%6.02f%%)\n",
						i,
						with_ts[0][i],
						without_ts[0][i],
						with_ts[1][i],
						without_ts[1][i],
						(with_ts[0][i]+with_ts[1][i])*100.0/(
							with_ts[0][i]+without_ts[0][i]+
							with_ts[1][i]+without_ts[1][i])
						);
				with+=with_ts[0][i]+with_ts[1][i];
				without+=without_ts[0][i]+without_ts[1][i];
				with_ts[0][i]=0;
				without_ts[0][i]=0;
				with_ts[1][i]=0;
				without_ts[1][i]=0;
			}
			printf("%6s: %6lli %6lli (%6.02f%%)\n",
					"",
					with,
					without,
					with*100.0/(with+without)
			      );
		}

	}

	return 0;
}
