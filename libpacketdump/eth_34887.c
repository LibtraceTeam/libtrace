#include <stdio.h>
#include "libpacketdump.h"

#define LE(lhs,n) 						\
	do {							\
		uint64_t num=0;					\
		int size=0;					\
		if ((offset+n)>len*8) return;			\
		if (n>16) {					\
			num=htonl(*(uint32_t*)(packet+offset/8));\
			size = 32;\
		} else if (n>8) {				\
			num=htons(*(uint16_t*)(packet+offset/8));\
			size = 16;				\
		} else { 					\
			num=*(uint8_t*)(packet+offset/8);	\
			size = 8;				\
		}						\
		num=num>>(size - (n + (offset % 8)));		\
		offset+=n;					\
		lhs=num&((1<<(n))-1);				\
	} while(0)

DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len)
{
	unsigned int offset=0;
	int value;
	int more = 0;
	LE(value,20); 	printf(" MPLS: Label: %d\n",value);
	LE(value,3); 	printf(" MPLS: Class of service: %d\n",value);
	LE(value,1);	printf(" MPLS: Stack: %s\n",value?"Last" :"More");
	if (value == 0) more = 1;
	LE(value,8);	printf(" MPLS: TTL: %d\n",value);
	
	/* MPLS doesn't say what it's encapsulating, so we make an educated
	 * guess and pray.
	 */
	if (more)
		decode_next(packet+offset/8,len-4,"eth",0x8847);
	else if ((*(packet+4)&0xF0) == 0x40)
		decode_next(packet+offset/8,len-4,"eth",0x0800);
	else if ((*(packet+4)&0xF0) == 0x60)
		decode_next(packet+offset/8,len-4,"eth",0x86DD);
	else
		decode_next(packet+offset/8,len-4,"link",1);

	return;
}
