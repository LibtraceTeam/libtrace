#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "libtrace.h"
#include "tracereport.h"


uint64_t byte_counter[3][2] = {{0,0},{0,0},{0,0}};
uint64_t packet_counter[3][2] = {{0,0},{0,0},{0,0}};

#define MAX_MAP_LINE_LEN 80

struct pnode {
  bool   local;        /*True if all IPs with this prefix are local*/
  struct pnode *one;   /*link to tree if 1                */
  struct pnode *zero;  /*link to tree if 0                */
};

enum {
	NATIONAL,
	INTERNATIONAL,
	FOREIGN
};

struct pnode root;
bool tree_created = false;

void add(long bits, int prefix_len){
        int bit;
        int bit_no;
        struct pnode *pos;

        pos = &root;
        for ( bit_no = 31; bit_no > 31 - prefix_len; --bit_no ) {
                bit = (bits>>bit_no) & 0x1;

                if ( bit == 0 ) {
                        if ( pos->zero == NULL ) {
                                pos->zero = (struct pnode *)malloc(sizeof(struct
 pnode));
                                pos->zero->zero = NULL;
                                pos->zero->one  = NULL;
                                pos->zero->local = false;
                        }
                        pos = pos->zero;
                }
                else {  /* ( bit == 1 ) */
                        if ( pos->one == NULL ) {
                                pos->one = (struct pnode *)malloc(sizeof(struct
pnode));
                                pos->one->zero = NULL;
                                pos->one->one  = NULL;
                                pos->one->local = false;
                        }
                        pos = pos->one;
                } /*else*/
        } /*for*/
        pos->local = true;
} /*void add()*/

void init_tree(char *local_ip_file) {
        FILE *map;
        char line[MAX_MAP_LINE_LEN];
        char addr[20];
        int  prefix_len;

        root.local = false;
        root.one = NULL;
        root.zero = NULL;

        map = fopen(local_ip_file, "r");
        if ( map == NULL ) { perror("Couldn't open map file"); exit(-0); }
        while ( NULL != (fgets(line, MAX_MAP_LINE_LEN - 2, map))) {
                line[MAX_MAP_LINE_LEN-1] = '\0';  /*ensure null termination*/
                if ( 2 != sscanf(line, "%19[0-9.] %d\n", addr, &prefix_len) ) {
                        fprintf(stderr, "Bad line in map: %s", line);
                } else {
                        add(htonl(inet_addr(addr)), prefix_len);
                }
        } /*while*/
        fclose(map);

}

bool match(long bits){
        /*bits must be in host byte order*/
        int bit;
        int bit_no;
        struct pnode *pos;


        pos = &root;


        for ( bit_no = 31; bit_no >= 0; --bit_no ) {
                bit = (bits>>bit_no) & 0x1;
                if ( pos->local ) { goto exit_match; }
                if ( bit == 0 ) pos = pos->zero;  else pos = pos->one;
                if ( pos == NULL ) goto exit_match;
        } /*for*/

exit_match:
        return(pos == NULL ? false : pos->local);
} /*void match()*/

void locality_per_packet(libtrace_packet_t *packet) {
libtrace_ip_t *ip = trace_get_ip(packet);
        uint32_t ip_a, ip_b;
	uint8_t dir = trace_get_direction(packet);
	
        if (!ip)
                return;

        ip_a = ip->ip_src.s_addr;
        ip_b = ip->ip_dst.s_addr;

        if (match(ntohl(ip_a)) && match(ntohl(ip_b))) {
                /* national */
                byte_counter[NATIONAL][dir] += trace_get_wire_length(packet);
        	packet_counter[NATIONAL][dir] ++;
	} else if (!match(ntohl(ip_a)) && !match(ntohl(ip_b))) {
                byte_counter[FOREIGN][dir] += trace_get_wire_length(packet);
		packet_counter[FOREIGN][dir] ++;
        } else {
                byte_counter[INTERNATIONAL][dir] += trace_get_wire_length(packet);
		packet_counter[INTERNATIONAL][dir] ++;
        }

}

void locality_report(void) {
	int i;
	int j;
	uint64_t total_bytes = 0;
	uint64_t total_packets = 0;
	
	FILE *out = fopen("locality.out", "w");
	if (!out) {
		perror("fopen");
		return;
	}

	/* inefficient, but we only have three categories */
	for (i = 0; i < 3; i++) {
		total_bytes += byte_counter[i][0] + byte_counter[i][1];
		total_packets += packet_counter[i][0] + packet_counter[i][1];
	}
	
	fprintf(out, "%-16s\t%24s %24s\n", "", "BYTES", "PACKETS");
	for (i=0; i<3; i++) {
		switch(i) {
			case NATIONAL:
				fprintf(out, "%16s", "NATIONAL\n");
				break;
			case INTERNATIONAL:
				fprintf(out, "%16s", "INTERNATIONAL\n");
				break;
			case FOREIGN:
				fprintf(out, "%16s", "FOREIGN\n");
				break;
		}
		for (j = 0; j < 3; j++) {
			uint64_t bytes_to_report = 0;
			uint64_t pkts_to_report = 0;
			switch(j) {
				case TRACE_DIR_OUTGOING:
					fprintf(out, "%16s", "Outgoing");
					bytes_to_report = byte_counter[i][j];
					pkts_to_report = packet_counter[i][j];
					break;
				case TRACE_DIR_INCOMING:
					fprintf(out, "%16s", "Incoming");
					bytes_to_report = byte_counter[i][j];
					pkts_to_report = packet_counter[i][j];
					break;
				case 2:
					fprintf(out, "%16s", "Total");
					bytes_to_report = byte_counter[i][0] + byte_counter[i][1];
					pkts_to_report = packet_counter[i][0] + packet_counter[i][1];
					break;	
			}
			fprintf(out, "\t%16llu (%.2f) ", bytes_to_report, bytes_to_report / (total_bytes / 100.0));
			fprintf(out, "%16llu (%.2f)\n", pkts_to_report, pkts_to_report / (total_packets / 100.0));
		}
	}
		
}

int locality_init(char *input_file) {
	
	if (!tree_created)	{
		init_tree(input_file);
		tree_created = true;
			
	}
	else {
		printf("You shouldn't be asking for this report twice!\n");
		return -1;
	}
	return 1;
}
