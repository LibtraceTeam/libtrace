#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <map>
#include "tracedump.h"
#include <netinet/in.h>
#include <assert.h>

/* SCTP decoding by Sam Jansen, 31/08/2004
 *
 * Based on RFC 2960 - Stream Control Transmission Protocol
 */

struct sctp_common_hdr
{
    uint16_t src_port, dst_port;
    uint32_t verification_tag;
    uint32_t checksum;
} __attribute__((__packed__));

struct sctp_chunk_hdr
{
    uint8_t type;
    uint8_t flags;
    uint16_t length;
} __attribute__((__packed__));

static char *sctp_type_to_str(uint8_t type)
{
    switch(type)
    {
        case 0: return "DATA";
        case 1: return "INIT";
        case 2: return "INIT ACK";
        case 3: return "SACK";
        case 4: return "HEARTBEAT";
        case 5: return "HEARTBEAT ACK";
        case 6: return "ABORT";
        case 7: return "SHUTDOWN";
        case 8: return "SHUTDOWN ACK";
        case 9: return "ERROR";
        case 10: return "COOKIE ECHO";
        case 11: return "COOKIE ACK";
        case 12: return "Reserved for ECNE";
        case 13: return "Reserved for CWR";
        case 14: return "SHUTDOWN COMPLETE";
        case 63:
        case 127:
        case 191:
        case 255: return "IETF-defined Chunk Extensions";
    };

   return "reserved by IETF";
}

extern "C"
void decode(int link_type,char *packet,int len)
{
    struct sctp_common_hdr *hdr;
    struct sctp_chunk_hdr *chunk;
    int chunk_num = 1;
    
    if(len < (signed)sizeof(struct sctp_common_hdr)) {
        printf("SCTP: packet too short!\n");
        return;
    }

    hdr = (struct sctp_common_hdr *)packet;

    printf("SCTP: Header Src port %u Dst port %u\n",
            ntohs(hdr->src_port), ntohs(hdr->dst_port));
    printf("SCTP: Verification tag %u Checksum %u\n",
            ntohl(hdr->verification_tag), ntohl(hdr->checksum));

    len -= sizeof(struct sctp_common_hdr);
    packet += sizeof(struct sctp_common_hdr);

    while(len > 0) {
        chunk = (struct sctp_chunk_hdr *)packet;

        chunk->length = ntohs(chunk->length);

        printf("SCTP: Chunk %d Type %s Flags %u Len %u\n",
            chunk_num++,
            sctp_type_to_str(chunk->type), chunk->flags, chunk->length);

        //packet += sizeof(struct sctp_chunk_hdr);
        //len -= sizeof(struct sctp_chunk_hdr);

        if(chunk->length == 0) {
            printf("SCTP: Invalid chunk length, aborting.\n");
            break;
        }
        
        packet += chunk->length;
        len -= chunk->length;
    }
    printf("\n");
}
