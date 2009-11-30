#include <stdio.h>
#include "libpacketdump.h"

#define LE(lhs,n)                                               \
        do {                                                    \
                uint64_t num=0;                                 \
                int size=0;                                     \
                if ((offset+n)>len*8) return;                   \
                if (n>16) {                                     \
                        num=htonl(*(uint32_t*)(packet+offset/8));\
                        size = 32;\
                } else if (n>8) {                               \
                        num=htons(*(uint16_t*)(packet+offset/8));\
                        size = 16;                              \
                } else {                                        \
                        num=*(uint8_t*)(packet+offset/8);       \
                        size = 8;                               \
                }                                               \
                num=num>>(size - (n + (offset % 8)));           \
                offset+=n;                                      \
                lhs=num&((1<<(n))-1);                           \
        } while(0)

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
        unsigned int offset=0;
        int value;
        uint16_t ethertype;

        LE(value, 3);   printf(" VLAN: User Priority: %d\n", value);
        LE(value, 1);   printf(" VLAN: Format Indicator: %d\n", value);
        LE(value, 12);  printf(" VLAN: ID: %d\n", value);
        LE(value, 16);  printf(" VLAN: EtherType: 0x%04x\n", (uint16_t)value);
        ethertype = (uint16_t) value;

        decode_next(packet + 4, len - 4, "eth", ethertype);

        return;
}

