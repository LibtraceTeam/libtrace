#include "libtrace.h"
#include "libpacketdump.h"

#include <libwandder_etsili.h>

DLLEXPORT void decode(int link_type UNUSED, const char *packet, unsigned len) {

        char linespace[4096];
        int i;
        uint8_t *cchdr = NULL;
        uint32_t rem = len;
        wandder_etsispec_t *dec;
        wandder_decoder_t *basedec = NULL;

        dec = wandder_create_etsili_decoder();
        wandder_attach_etsili_buffer(dec, (uint8_t *)packet, len, false);

        basedec = wandder_get_etsili_base_decoder(dec);
        while (wandder_etsili_get_next_fieldstr(dec, linespace, 4096)) {
                printf(" ETSILI: ");
                for (i = 0; i < wandder_get_level(basedec); i++) {
                        printf("  ");
                }
                printf("%s\n", linespace);
        }

        cchdr = wandder_etsili_get_cc_contents(dec, &rem);

        wandder_free_etsili_decoder(dec);

        if (cchdr) {
                /* XXX What if there is an IPv7?? */
                decode_next((const char *)cchdr, rem, "eth",
                                ((*cchdr) & 0xf0) == 0x40 ? TRACE_ETHERTYPE_IP :
                                TRACE_ETHERTYPE_IPV6);
        }
        return;
}
