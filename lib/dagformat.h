#ifndef _DAGFORMAT_H_
#define _DAGFORMAT_H_

/* GPP record type defines */
#define TYPE_LEGACY       0
#define TYPE_HDLC_POS     1
#define TYPE_ETH          2
#define TYPE_ATM          3
#define TYPE_AAL5         4

/* GPP Type 1 */
typedef struct pos_rec {
	uint32_t  hdlc;
	uint8_t	  pload[1];
}  pos_rec_t;

/* GPP Type 2 */
typedef struct eth_rec {
	uint8_t   offset;
	uint8_t   pad;
	uint8_t   dst[6];
	uint8_t   src[6];
	uint16_t  etype;
	uint8_t   pload[1];
}  eth_rec_t;

/* GPP Type 3 */
typedef struct atm_rec {
	uint32_t  header; 
	uint8_t   pload[1];
}  atm_rec_t;

/* GPP Type 4 */
typedef struct aal5_rec {
	uint32_t  header; 
	uint8_t   pload[1];
}  aal5_rec_t;

typedef struct flags {
	uint8_t   iface:2;
	uint8_t   vlen:1;
	uint8_t   trunc:1;
	uint8_t   rxerror:1;
	uint8_t   dserror:1;
	uint8_t   pad:2;
} __attribute__((packed)) flags_t;

/* GPP Global type */
typedef struct dag_record {
	uint64_t  ts;
	uint8_t   type;
	flags_t   flags;
	uint16_t  rlen;
	uint16_t  lctr;
	uint16_t  wlen;
	union {
		pos_rec_t       pos;
		eth_rec_t       eth;
		atm_rec_t       atm;
		aal5_rec_t      aal5;
	} rec;
} __attribute__((packed)) dag_record_t;

typedef struct duck_inf_pkt {
        uint32_t  command;
	uint32_t  config;
	uint32_t  clock_inc;
	uint32_t  clock_wrap;
	uint32_t  DDS_rate;
        uint32_t  crystal_freq;
        uint32_t  synth_freq;
	uint32_t  sync_rate;
        uint64_t  last_ticks;
        uint32_t  resyncs;
        uint32_t  bad_diffs, bad_offs, bad_pulses;
        uint32_t  worst_error, worst_off;
        uint32_t  off_limit, off_damp;
        uint32_t  pulses, single_pulses_missing, longest_pulse_missing;
        uint32_t  health; 
	uint32_t  sickness;
        int32_t   error;
	int32_t   offset;
        int32_t   stat_start, stat_end;  
        uint32_t  set_duck_field;
} duck_inf;

#define dag_record_size         16

typedef struct legacy_cell {
        uint64_t  ts;
        uint32_t  crc;
} legacy_cell_t;

typedef struct legacy_ether {
        uint64_t  ts;
        uint16_t  wlen;
} legacy_ether_t;

typedef struct legacy_pos {
        uint64_t  ts;
        uint32_t  slen;
        uint32_t  wlen;
} legacy_pos_t;

#endif // _DAGFORMAT_H_
