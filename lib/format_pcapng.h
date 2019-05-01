#define PCAPNG_SECTION_TYPE 0x0A0D0D0A
#define PCAPNG_INTERFACE_TYPE 0x00000001
#define PCAPNG_OLD_PACKET_TYPE 0x00000002
#define PCAPNG_SIMPLE_PACKET_TYPE 0x00000003
#define PCAPNG_NAME_RESOLUTION_TYPE 0x00000004
#define PCAPNG_INTERFACE_STATS_TYPE 0x00000005
#define PCAPNG_ENHANCED_PACKET_TYPE 0x00000006
#define PCAPNG_CUSTOM_TYPE 0x00000BAD
#define PCAPNG_CUSTOM_NONCOPY_TYPE 0x40000BAD
#define PCAPNG_DECRYPTION_SECRETS_TYPE 0x0000000A

#define PCAPNG_NRB_RECORD_END 0x0000
#define PCAPNG_NRB_RECORD_IP4 0x0001
#define PCAPNG_NRB_RECORD_IP6 0x0002

#define PCAPNG_CUSTOM_OPTION_UTF8 0xBAC
#define PCAPNG_CUSTOM_OPTION_BIN 0xBAD
#define PCAPNG_CUSTOM_OPTION_UTF8_NONCOPY 0x4BAC
#define PCAPNG_CUSTOM_OPTION_BIN_NONCOPY 0x4BAD


#define PCAPNG_OPTION_END 0
#define PCAPNG_OPTION_COMMENT 1
/* Custom option code containing a UTF-8 string */
#define PCAPNG_OPTION_CUSTOM_1 2988
/* Custom option code containing binary octets */
#define PCAPNG_OPTION_CUSTOM_2 2989
/* Custom option code containing a UTF-8 string
 * Should not be copied to a new file if manipulated */
#define PCAPNG_OPTION_CUSTOM_3 19372
/* Custom option code containing binary octets
 * Should not be copied to a new file if manipulated */
#define PCAPNG_OPTION_CUSTOM_4 19373

#define PACKET_IS_SECTION (pcapng_get_record_type(packet) == PCAPNG_SECTION_TYPE)
#define PACKET_IS_INTERFACE (pcapng_get_record_type(packet) == PCAPNG_INTERFACE_TYPE)
#define PACKET_IS_OLD (pcapng_get_record_type(packet) == PCAPNG_OLD_PACKET_TYPE)
#define PACKET_IS_SIMPLE (pcapng_get_record_type(packet) == PCAPNG_SIMPLE_PACKET_TYPE)
#define PACKET_IS_NAME_RESOLUTION (pcapng_get_record_type(packet) == PCAPNG_NAME_RESOLUTION_TYPE)
#define PACKET_IS_INTERFACE_STATS (pcapng_get_record_type(packet) == PCAPNG_INTERFACE_STATS_TYPE)
#define PACKET_IS_ENHANCED (pcapng_get_record_type(packet) == PCAPNG_ENHANCED_PACKET_TYPE)
#define PACKET_IS_CUSTOM (pcapng_get_record_type(packet) == PCAPNG_CUSTOM_TYPE)
#define PACKET_IS_CUSTOM_NONCOPY (pcapng_get_record_type(packet) == PCAPNG_CUSTOM_NONCOPY_TYPE)
#define PACKET_IS_DECRYPTION_SECRETS (pcapng_get_record_type(packet) == PCAPNG_DECRYPTION_SECRETS_TYPE)

#define PCAPNG_IFOPT_TSRESOL 9

#define PCAPNG_PKTOPT_DROPCOUNT 4

#define PCAPNG_STATOPT_START 2
#define PCAPNG_STATOPT_END 3
#define PCAPNG_STATOPT_IFRECV 4
#define PCAPNG_STATOPT_IFDROP 5
#define PCAPNG_STATOPT_FILTERACCEPT 6
#define PCAPNG_STATOPT_OSDROP 7
#define PCAPNG_STATOPT_USRDELIV 8

/* PCAPNG meta tag type codes */
/* SHB - Section header block */
#define PCAPNG_META_SHB_HARDWARE 2
#define PCAPNG_META_SHB_OS 3
#define PCAPNG_META_SHB_USERAPPL 4
/* Interface description block */
#define PCAPNG_META_IF_NAME 2
#define PCAPNG_META_IF_DESCR 3
#define PCAPNG_META_IF_IP4 4
#define PCAPNG_META_IF_IP6 5
#define PCAPNG_META_IF_MAC 6
#define PCAPNG_META_IF_EUI 7
#define PCAPNG_META_IF_SPEED 8
#define PCAPNG_META_IF_TSRESOL 9
#define PCAPNG_META_IF_TZONE 10
#define PCAPNG_META_IF_FILTER 11
#define PCAPNG_META_IF_OS 12
#define PCAPNG_META_IF_FCSLEN 13
#define PCAPNG_META_IF_TSOFFSET 14
#define PCAPNG_META_IF_HARDWARE 15
/* Enhanced block */
#define PCAPNG_META_EPB_FLAGS 2
#define PCAPNG_META_EPB_HASH 3
#define PCAPNG_META_EPB_DROPCOUNT 4
/* Name Resolution block */
#define PCAPNG_META_NRB_RECORD_END 0x0000
#define PCAPNG_META_NRB_RECORD_IP4 0x0001
#define PCAPNG_META_NRB_RECORD_IP6 0x0002
#define PCAPNG_META_NS_DNSNAME 2
#define PCAPNG_META_NS_DNS_IP4_ADDR 3
#define PCAPNG_META_NS_DNS_IP6_ADDR 4
/* Interface stats block */
#define PCAPNG_META_ISB_STARTTIME 2
#define PCAPNG_META_ISB_ENDTIME 3
#define PCAPNG_META_ISB_IFRECV 4
#define PCAPNG_META_ISB_IFDROP 5
#define PCAPNG_META_ISB_FILTERACCEPT 6
#define PCAPNG_META_ISB_OSDROP 7
#define PCAPNG_META_ISB_USRDELIV 8
/* Old packet type */
#define PCAPNG_META_OLD_FLAGS 2
#define PCAPNG_META_OLD_HASH 3

#define DATA(x) ((struct pcapng_format_data_t *)((x)->format_data))
#define DATAOUT(x) ((struct pcapng_format_data_out_t*)((x)->format_data))

typedef struct pcagng_section_header_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint32_t ordering;
        uint16_t majorversion;
        uint16_t minorversion;
        uint64_t sectionlen;
} PACKED pcapng_sec_t;

typedef struct pcapng_interface_header_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint16_t linktype;
        uint16_t reserved;
        uint32_t snaplen;
} PACKED pcapng_int_t;

typedef struct pcapng_nrb_header_t {
        uint32_t blocktype;
        uint32_t blocklen;
} PACKED pcapng_nrb_t;

typedef struct pcapng_enhanced_packet_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint32_t interfaceid;
        uint32_t timestamp_high;
        uint32_t timestamp_low;
        uint32_t caplen;
        uint32_t wlen;
} PACKED pcapng_epkt_t;

typedef struct pcapng_simple_packet_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint32_t wlen;
} PACKED pcapng_spkt_t;

typedef struct pcapng_old_packet_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint16_t interfaceid;
        uint16_t drops;
        uint32_t timestamp_high;
        uint32_t timestamp_low;
        uint32_t caplen;
        uint32_t wlen;
} PACKED pcapng_opkt_t;

typedef struct pcapng_stats_header_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint32_t interfaceid;
        uint32_t timestamp_high;
        uint32_t timestamp_low;
} PACKED pcapng_stats_t;

typedef struct pcapng_decryption_secrets_header_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint32_t secrets_type;
        uint32_t secrets_len;
} PACKED pcapng_secrets_t;

typedef struct pcapng_custom_header_t {
        uint32_t blocktype;
        uint32_t blocklen;
        uint32_t pen;
} PACKED pcapng_custom_t;

typedef struct pcapng_interface_t pcapng_interface_t;

struct pcapng_timestamp {
        uint32_t timehigh;
        uint32_t timelow;
};

struct pcapng_interface_t {

        uint16_t id;
        libtrace_dlt_t linktype;
        uint32_t snaplen;
        uint32_t tsresol;

        uint64_t received;
        uint64_t dropped;       /* as reported by interface stats */
        uint64_t dropcounter;   /* as reported by packet records */
        uint64_t accepted;
        uint64_t osdropped;
        uint64_t laststats;

};

struct pcapng_format_data_t {
        bool started;
        bool realtime;
        bool discard_meta;

        /* Section data */
        bool byteswapped;

        /* Interface data */
        pcapng_interface_t **interfaces;
        uint16_t allocatedinterfaces;
        uint16_t nextintid;

};

struct pcapng_format_data_out_t {
        iow_t *file;
        int compress_level;
        int compress_type;
        int flag;

        /* Section data */
        uint16_t sechdr_count;
        bool byteswapped;

        /* Interface data */
        uint16_t nextintid;
        libtrace_linktype_t lastdlt;
};

struct pcapng_optheader {
        uint16_t optcode;
        uint16_t optlen;
} PACKED;

struct pcapng_custom_optheader {
        uint16_t optcode;
        uint16_t optlen;
        uint32_t pen;
} PACKED;
struct pcapng_nrb_record {
        uint16_t recordtype;
        uint16_t recordlen;
} PACKED;
struct pcapng_peeker {
        uint32_t blocktype;
        uint32_t blocklen;
} PACKED;

typedef struct pcapng_peeker pcapng_hdr_t;

libtrace_meta_t *pcapng_get_all_meta(libtrace_packet_t *packet);
