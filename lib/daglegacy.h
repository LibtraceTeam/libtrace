#ifndef DAG_LEGACY_H
#define DAG_LEGACY_H

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

#endif
