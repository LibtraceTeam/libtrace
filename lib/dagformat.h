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
	unsigned                hdlc;
	unsigned char           pload[1];
}  pos_rec_t;

/* GPP Type 2 */
typedef struct eth_rec {
	unsigned char           offset;
	unsigned char           pad;
	unsigned char           dst[6];
	unsigned char           src[6];
	unsigned short          etype;
	unsigned char           pload[1];
}  eth_rec_t;

/* GPP Type 3 */
typedef struct atm_rec {
	unsigned                header; 
	unsigned char           pload[1];
}  atm_rec_t;

/* GPP Type 4 */
typedef struct aal5_rec {
	unsigned                header; 
	unsigned char           pload[1];
}  aal5_rec_t;

typedef struct flags {
	unsigned char           iface:2;
	unsigned char           vlen:1;
	unsigned char           trunc:1;
	unsigned char           rxerror:1;
	unsigned char           dserror:1;
	unsigned char           pad:2;
} __attribute__((packed)) flags_t;

/* GPP Global type */
typedef struct dag_record {
	unsigned long long      ts;
	unsigned char           type;
	flags_t                 flags;
	unsigned short          rlen;
	unsigned short          lctr;
	unsigned short          wlen;
	union {
		pos_rec_t       pos;
		eth_rec_t       eth;
		atm_rec_t       atm;
		aal5_rec_t      aal5;
	} rec;
} __attribute__((packed)) dag_record_t;

#define dag_record_size         16


#endif // _DAGFORMAT_H_
