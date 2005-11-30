#ifndef DAG_LEGACY_H
#define DAG_LEGACY_H

typedef struct legacy_cell {
        uint64_t  ts;
        uint32_t  crc;
} __attribute__ ((packed)) legacy_cell_t;

typedef struct legacy_ether {
        uint64_t  ts;
        uint16_t  wlen;
} __attribute__ ((packed)) legacy_ether_t;

typedef struct legacy_pos {
        uint64_t  ts;
        uint32_t  slen;
        uint32_t  wlen;
} __attribute__ ((packed)) legacy_pos_t;

#endif
