#include "libtrace.h"
#include "libpacketdump.h"
#include "format_ndag.h"
#include "lt_bswap.h"

DLLEXPORT void decode(int link_type UNUSED, const char *packet, unsigned len) {

	corsaro_packet_tags_t *tags;
	uint32_t prov_used;
        uint64_t filterbits;
        int i;

	tags = (corsaro_packet_tags_t *)packet;

	prov_used = ntohl(tags->providers_used);
        filterbits = bswap_be_to_host64(tags->filterbits);

	printf(" CorsaroTags: Protocol: %u  Source Port: %u  Dest Port: %u\n",
			tags->protocol, ntohs(tags->src_port),
			ntohs(tags->dest_port));
	printf(" CorsaroTags: Flowtuple hash: %u\n", ntohl(tags->ft_hash));
	if (prov_used & (1 << NDAG_IPMETA_PROVIDER_MAXMIND)) {
		printf(" CorsaroTags: Maxmind Continent: %c%c   Country: %c%c\n",
				(unsigned char)(tags->maxmind_continent & 0xff),
				(unsigned char)(tags->maxmind_continent >> 8),
				(unsigned char)(tags->maxmind_country & 0xff),
				(unsigned char)(tags->maxmind_country >> 8)
		);
	}
	if (prov_used & (1 << NDAG_IPMETA_PROVIDER_NETACQ_EDGE)) {
		printf(" CorsaroTags: Netacq-Edge Continent: %c%c   Country: %c%c\n",
				(unsigned char)(tags->netacq_continent & 0xff),
				(unsigned char)(tags->netacq_continent >> 8),
				(unsigned char)(tags->netacq_country & 0xff),
				(unsigned char)(tags->netacq_country >> 8)
		);
                printf(" CorsaroTags: Netacq-Edge Region Code: %u\n",
                                ntohs(tags->netacq_region));
                printf(" CorsaroTags: Netacq-Edge Polygon Ids: ");
                for (i = 0; i < MAX_NETACQ_POLYGONS; i++) {
                        uint32_t pgon = ntohl(tags->netacq_polygon[i]);
                        if ((pgon & 0x00ffffff) == 0) {
                                break;
                        }
                        printf("%u:%u ", (pgon >> 24), (pgon & 0x00ffffff));
                }
                printf("\n");

	}
        if (prov_used & (1 << NDAG_IPMETA_PROVIDER_PFX2AS)) {
                printf(" CorsaroTags: Source ASN: %u\n",
                                ntohl(tags->prefixasn));
        }

        printf(" CorsaroTags: Filters: ");
        /* Let's just cover the high-level filters here */
        printf("%s%s%s%s\n",
                        (filterbits & 0x01) ? "Spoofed " : "Not-Spoofed ",
                        (filterbits & 0x02) ? "Erratic " : "Not-Erratic ",
                        (filterbits & 0x04) ? "Not-Routable " : "Routable ",
                        (filterbits & 0x08) ? "LSScan ": "");

        if (len > sizeof(corsaro_packet_tags_t)) {
                decode_next(packet + sizeof(corsaro_packet_tags_t),
                        len - sizeof(corsaro_packet_tags_t), "link", 2);
        }
}
