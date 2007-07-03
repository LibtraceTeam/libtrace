#ifndef DAG_LEGACY_H
#define DAG_LEGACY_H

typedef struct legacy_cell {
        uint64_t  ts;
        uint32_t  crc;
} PACKED legacy_cell_t;

typedef struct legacy_ether {
        uint64_t  ts;
        uint16_t  wlen;
} PACKED legacy_ether_t;

typedef struct legacy_pos {
        uint64_t  ts;
        uint32_t  slen;
        uint32_t  wlen;
} PACKED legacy_pos_t;

typedef struct atmhdr {
	uint32_t ts_fraction;
	uint32_t ts_sec;
} PACKED atmhdr_t;

typedef struct legacy_nzix {
	uint32_t ts;
	uint32_t crc;
	uint32_t len;
	/* The padding has actually been placed in the middle of the IP
	 * header - when we read in the packet, we will move various bits
	 * of the packet around until the padding ends up here and the 
	 * IP header is undivided */
	uint8_t pad[2];		
} PACKED legacy_nzix_t;
#endif
