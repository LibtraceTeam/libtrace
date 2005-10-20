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


typedef struct duck_inf
{
        uint32_t  Command, Config, Clock_Inc, Clock_Wrap, DDS_Rate;
        uint32_t  Crystal_Freq;
        uint32_t  Synth_Freq, Sync_Rate;
        uint64_t  Last_Ticks;
        uint32_t  Resyncs;
        uint32_t  Bad_Diffs, Bad_Offs, Bad_Pulses;
        uint32_t  Worst_Error, Worst_Off;
        uint32_t  Off_Limit, Off_Damp;
        uint32_t  Pulses, Single_Pulses_Missing, Longest_Pulse_Missing;
        uint32_t  Health, Sickness;
        int32_t   Error, Offset;
        int32_t   Stat_Start, Stat_End;   /* these are really time_t's */
        uint32_t  Set_Duck_Field;
} duck_inf;

#define dag_record_size         16

#endif // _DAGFORMAT_H_
