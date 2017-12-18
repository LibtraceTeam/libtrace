#include "libtrace.h"
#include "libpacketdump.h"

#include <libwandder_etsili.h>

DLLEXPORT void decode(int link_type UNUSED, const char *packet, unsigned len) {

        wandder_decoder_t dec;
        wandder_etsi_stack_t *stack = NULL;
        char linespace[4096];
        int i;
        uint8_t *cchdr = NULL;
        uint32_t rem = len;

        init_wandder_decoder(&dec, (uint8_t *)packet, len, false);
        while (wandder_etsili_get_next_fieldstr(&dec, linespace, 4096, &stack)) {
                printf(" ETSILI: ");
                for (i = 0; i < wandder_get_level(&dec); i++) {
                        printf("  ");
                }
                printf("%s\n", linespace);
        }

        wandder_reset_decoder(&dec);
        cchdr = wandder_etsili_get_cc_contents(&dec, &rem);

        wandder_etsili_free_stack(stack);
        free_wandder_decoder(&dec);

        if (cchdr) {
                /* XXX What if there is an IPv7?? */
                decode_next((const char *)cchdr, rem, "eth",
                                ((*cchdr) & 0xf0) == 0x40 ? TRACE_ETHERTYPE_IP :
                                TRACE_ETHERTYPE_IPV6);
        }
        return;
}
