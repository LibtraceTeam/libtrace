#include <assert.h>
#include "libtrace.h"
#include "libpacketdump.h"

#include <libwandder_etsili.h>

DLLEXPORT void decode(int link_type UNUSED, const char *packet, unsigned len) {

        char linespace[4096];
        char namesp[1024];
        int i;
        uint8_t *cchdr = NULL;
        uint8_t *iricontents = NULL;
        uint8_t ident;
        uint32_t rem = len;
        wandder_etsispec_t *dec;
        wandder_decoder_t *basedec = NULL;
        int lastlevel = 0;

        dec = wandder_create_etsili_decoder();
        wandder_attach_etsili_buffer(dec, (uint8_t *)packet, len, false);

        basedec = wandder_get_etsili_base_decoder(dec);
        while (wandder_etsili_get_next_fieldstr(dec, linespace, 4096)) {
                printf(" ETSILI: ");
                for (i = 0; i < wandder_get_level(basedec); i++) {
                        printf("  ");
                        lastlevel = i + 1;
                }
                printf("%s\n", linespace);
        }

        cchdr = wandder_etsili_get_cc_contents(dec, &rem, namesp, 1024);

        if (cchdr) {
                printf(" ETSILI: ");
                for (i = 0; i < lastlevel + 1; i++) {
                        printf("  ");
                }
                printf("%s: ...\n", namesp);
                wandder_free_etsili_decoder(dec);
                /* XXX What if there is an IPv7?? */
                decode_next((const char *)cchdr, rem, "eth",
                                ((*cchdr) & 0xf0) == 0x40 ? TRACE_ETHERTYPE_IP :
                                TRACE_ETHERTYPE_IPV6);
                return;
        }

        iricontents = wandder_etsili_get_iri_contents(dec, &rem, &ident,
                        namesp, 1024);
        if (iricontents) {
                printf(" ETSILI: ");
                /* hard-coded indentation, but easier than introducing
                 * yet another parameter to get_iri_contents()
                 */
                for (i = 0; i < 7; i++) {
                        printf("  ");
                }
                printf("%s: ...\n", namesp);
                wandder_free_etsili_decoder(dec);
                if (ident == WANDDER_IRI_CONTENT_IP) {
                        decode_next((const char *)iricontents, rem, "eth",
                                        ((*iricontents) & 0xf0) == 0x40 ?
                                        TRACE_ETHERTYPE_IP :
                                        TRACE_ETHERTYPE_IPV6);
                } else if (ident == WANDDER_IRI_CONTENT_SIP) {
                        decode_next((const char *)iricontents, rem, "udp",
                                        5060);
                }
        }

        return;
}
