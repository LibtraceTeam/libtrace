#ifndef _DAGFORMAT_H_
#define _DAGFORMAT_H_

#include "libtrace.h"

/* GPP record type defines */
#define TYPE_LEGACY       0
#define TYPE_HDLC_POS     1
#define TYPE_ETH          2
#define TYPE_ATM          3
#define TYPE_AAL5         4

#ifdef WIN32
#pragma pack(push)
#pragma pack(1)
#endif

/** GPP Type 1 */
typedef struct pos_rec {
	uint32_t  hdlc;
	uint8_t	  pload[1];		/**< payload */
}  pos_rec_t;

/** GPP Type 2 */
typedef struct eth_rec {
	uint8_t   offset;
	uint8_t   pad;
	uint8_t   dst[6];
	uint8_t   src[6];
	uint16_t  etype;		/**< ether type (?) */
	uint8_t   pload[1];		/**< payload */
}  eth_rec_t;

/** GPP Type 3 */
typedef struct atm_rec {
	uint32_t  header; 
	uint8_t   pload[1];		/**< payload */
}  atm_rec_t;

/** GPP Type 4 */
typedef struct aal5_rec {
	uint32_t  header; 
	uint8_t   pload[1];		/**< payload */
}  aal5_rec_t;

/** Flags */
typedef struct flags {
	LT_BITFIELD8  iface:2;		/**< Interface (direction) */
	LT_BITFIELD8  vlen:1;	
	LT_BITFIELD8  trunc:1;		/**< Trunacted */
	LT_BITFIELD8  rxerror:1;	/**< RX Error in this packet/before
					  * this packet
					  */
	LT_BITFIELD8  dserror:1;	/**< Data stream error */
	LT_BITFIELD8  pad:2;		/**< Unused */
} PACKED flags_t;

/** GPP Global type */
typedef struct dag_record {
	uint64_t  ts;		/**< erf timestamp */
	uint8_t   type;		/**< GPP record type */
	flags_t   flags;	/**< flags */
	uint16_t  rlen;		/**< record len (capture+framing) */
	uint16_t  lctr;		/**< loss counter */
	uint16_t  wlen;		/**< wire length */
	union {
		pos_rec_t       pos;	
		eth_rec_t       eth;
		atm_rec_t       atm;
		aal5_rec_t      aal5;
	} rec;
} PACKED dag_record_t;

/** Dynamic(?) Universal Clock Kit Information packet */
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

#ifdef WIN32
#pragma pack(pop)
#endif

/** sizeof(dag_record_t) without the payload helpers */
#define dag_record_size         16U

#endif /* _DAGFORMAT_H_ */
