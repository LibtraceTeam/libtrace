#ifndef FORMAT_NDAG_H_
#define FORMAT_NDAG_H_

#include <libtrace.h>

#define NDAG_MAX_DGRAM_SIZE (8900)

#define NDAG_MAGIC_NUMBER (0x4E444147)
#define NDAG_EXPORT_VERSION 1


enum {
        NDAG_PKT_BEACON = 0x01,
        NDAG_PKT_ENCAPERF = 0x02,
        NDAG_PKT_RESTARTED = 0x03,
        NDAG_PKT_ENCAPRT = 0x04,
};

/* == Protocol header structures == */

/* Common header -- is prepended to all exported records */
typedef struct ndag_common_header {
        uint32_t magic;
        uint8_t version;
        uint8_t type;
        uint16_t monitorid;
} PACKED ndag_common_t;

/* Beacon -- structure is too simple to be worth defining as a struct */
/*
 * uint16_t numberofstreams;
 * uint16_t firststreamport;
 * uint16_t secondstreamport;
 * ....
 * uint16_t laststreamport;
 */

/* Encapsulation header -- used by both ENCAPERF and ENCAPRT records */
typedef struct ndag_encap {
        uint32_t seqno;
        uint16_t streamid;
        uint16_t recordcount; /* acts as RT type for ENCAPRT records */
} PACKED ndag_encap_t;

#endif
