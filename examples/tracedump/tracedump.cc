#include "tracedump.h"

void per_packet(int link_type,char *data,int size)
{
	decode_next(data,size,"link",link_type);
}
