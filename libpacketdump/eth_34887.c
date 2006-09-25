#include <stdio.h>
#include "libpacketdump.h"

#define LE(lhs,n) 						\
	do {							\
		uint64_t num=0;					\
		if ((offset+n)>len*8) return;			\
		if (n>16)					\
			num=htonl(*(uint32_t*)(packet+offset/8));\
		else if (n>8)					\
			num=htons(*(uint16_t*)(packet+offset/8));\
		else 						\
			num=*(uint8_t*)(packet+offset/8);	\
		num=num>>(32-n);				\
		offset+=n;					\
		lhs=num&((1<<(n+1))-1);				\
	} while(0)

void decode(int link_type,char *packet,int len)
{
	int offset=0;
	int value;
	LE(value,20); 	printf(" MPLS: Label: %d\n",offset);
	LE(value,3); 	printf(" MPLS: Class of service: %d\n",offset);
	LE(value,1);	printf(" MPLS: Stack: %s\n",offset?"Last" :"More");
	LE(value,8);	printf(" MPLS: TTL: %d\n",offset);
	/* MPLS doesn't say what it's encapsulating, so we make an educated
	 * guess and pray.
	 */
	if ((*(packet+32)&0xF0) == 0x40)
		decode_next(packet+offset/8,len-4,"eth",0x0800);
	else if ((*(packet+32)&0xF0) == 0x60)
		decode_next(packet+offset/8,len-4,"eth",0x86DD);
	else
		decode_next(packet+offset/8,len-4,"link",1);

	return;
}
