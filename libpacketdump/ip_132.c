#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

struct sctp_data
{
    uint32_t tsn;
    uint16_t stream_id;
    uint16_t stream_seqno;
    uint32_t payload_proto_id;
} __attribute__((__packed__));

/* The following works for INIT and INIT ACK packets */
struct sctp_init_ack
{
    uint32_t init_tag;
    uint32_t rcv_wnd_credit;
    uint16_t outbound_streams;
    uint16_t inbound_streams;
    uint32_t init_tsn;
} __attribute__((__packed__));

struct sctp_sack
{
    uint32_t tsn_ack;
    uint32_t a_wnd;
    uint16_t num_gap_blocks;
    uint16_t num_dup_tsns;
} __attribute__((__packed__));

struct sctp_var_param_hdr
{
    uint16_t type;
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

static void parse_options(char *offset, int vlen)
{
    while(vlen > 0) {
        struct sctp_var_param_hdr *ph = (struct sctp_var_param_hdr *)(offset);
        char *data = (char *)(ph + 1);

        switch(ntohs(ph->type)) {
            case 5:
            {
                struct in_addr *ia = (struct in_addr *)data;
                printf(" SCTP: Option IP address %s\n", inet_ntoa(*ia));
            }
            break;
            case 6:
            {
                printf(" SCTP: Option IPv6 address (TODO)\n");
            }
            break;
            case 7:
            {
                printf(" SCTP: Option State cookie\n");
                /* // Prolly don't want to print this out :)
                for(int i = 0; i < ntohs(ph->length) - 8; i++)
                    printf("%02x", data[i]);
                printf("'\n");*/
            }
            break;
            case 9:
            {
                printf(" SCTP: Option Cookie preservative (TODO)\n");
            }
            break;
            case 11:
            {
                printf(" SCTP: Option Host name %s\n", data);
            }
            break;
            case 12:
            {
                uint16_t *p = (uint16_t *)data;
                int len = ntohs(ph->length) - 
                    sizeof(struct sctp_var_param_hdr);
                
                printf(" SCTP: Option Supported address types ");
                
                while(len) {
                    printf("%hu ", ntohs(*p));
                    p++;
                    len -= sizeof(*p);
                }
                printf("\n");
            }
            break;
            default:
                printf(" SCTP: Option Unknown type=%hu len=%hu\n", 
                        ntohs(ph->type), ntohs(ph->length));
        }

        vlen -= ntohs(ph->length);
        offset += ntohs(ph->length);
    }
}

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
    struct sctp_common_hdr *hdr;
    struct sctp_chunk_hdr *chunk;
    int chunk_num = 1;
    int vlen;

    if(len < (signed)sizeof(struct sctp_common_hdr)) {
        printf(" SCTP: packet too short!\n");
        return;
    }

    hdr = (struct sctp_common_hdr *)packet;

    printf(" SCTP: Header Src port %hu Dst port %hu Tag %u Csum %u\n",
            ntohs(hdr->src_port), ntohs(hdr->dst_port),
            ntohl(hdr->verification_tag), ntohl(hdr->checksum));

    len -= sizeof(struct sctp_common_hdr);
    packet += sizeof(struct sctp_common_hdr);

    while(len > 0) {
        chunk = (struct sctp_chunk_hdr *)packet;

        chunk->length = ntohs(chunk->length);

        printf(" SCTP: Chunk %d Type %s Flags %u Len %u\n",
            chunk_num++,
            sctp_type_to_str(chunk->type), chunk->flags, chunk->length);

        if(chunk->length == 0) {
            printf(" SCTP: Invalid chunk length, aborting.\n\n");
            break;
        }

        switch(chunk->type) {
            case 0: /* DATA */
            {
                struct sctp_data *data = (struct sctp_data *)(chunk + 1);

                printf(" SCTP: TSN %u Stream ID %hu Stream Seqno %hu "
                        "Payload ID %u\n",
                        ntohl(data->tsn), ntohs(data->stream_id),
                        ntohs(data->stream_seqno),
                        ntohl(data->payload_proto_id));
            }
            break;
            case 1: /* INIT and  */
            case 2: /* INIT ACK packets have the same structure */
            {
                /* INIT ACK */
                struct sctp_init_ack *ack = (struct sctp_init_ack *)
                    (chunk + 1);
                
                printf(" SCTP: Tag %u Credit %u Outbound %hu Inbound %hu "
                        "TSN %u\n",
                        ntohl(ack->init_tag),
                        ntohl(ack->rcv_wnd_credit),
                        ntohs(ack->outbound_streams),
                        ntohs(ack->inbound_streams),
                        ntohl(ack->init_tsn));

                vlen = chunk->length - (sizeof(struct sctp_init_ack) +
                        sizeof(struct sctp_chunk_hdr) +
                        sizeof(struct sctp_common_hdr)
                        );
                parse_options((char *)(ack + 1), vlen);

            }
            break;
            case 3: /* SACK */
            {
                struct sctp_sack *sack = (struct sctp_sack *)(chunk + 1);
                int i;

                printf(" SCTP: Ack %u Wnd %u\n", ntohl(sack->tsn_ack),
                        ntohl(sack->a_wnd));

                for(i = 0; i < ntohs(sack->num_gap_blocks); i++) {
                    uint16_t *p = (uint16_t *)(sack + 1);
                    p += i * 2;

                    printf(" SCTP: Gap ACK Start %hu End %hu\n",
                            ntohs(*p), ntohs(*(p + 1)));
                }
                for(i = 0; i < ntohs(sack->num_dup_tsns); i++) {
                    uint32_t *p = (uint32_t *)(sack + 1);
                    p += ntohs(sack->num_gap_blocks) + i;

                    printf(" SCTP: Duplicatate TSN %u\n", ntohl(*p));
                }
            }
            break;
        }
        
        packet += chunk->length;
        len -= chunk->length;
    }
    printf("\n");
}
