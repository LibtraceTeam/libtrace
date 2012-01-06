#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "libpacketdump.h"


DLLEXPORT void decode(int link_type UNUSED,const char *packet,unsigned len) {

	libtrace_ospf_hello_v2_t *hello = (libtrace_ospf_hello_v2_t *)packet;
	struct in_addr *neigh;

	if (len < 4) 
		return;
	printf(" OSPF Hello: Network Mask %s\n", inet_ntoa(hello->mask));
	if (len < 6)
		return;

	printf(" OSPF Hello: Interval %u ", ntohs(hello->interval));

	if (len < 7) {
		printf("\n");
		return;
	}

	printf("Options ");

	if (hello->hello_options.e_bit)
		printf("E ");
	if (hello->hello_options.mc_bit)
		printf("MC ");
	if (hello->hello_options.np_bit)
		printf("N/P ");
	if (hello->hello_options.ea_bit)
		printf("EA ");
	if (hello->hello_options.dc_bit)
		printf("DC ");
	printf("\n");

	if (len < 8) 
		return;

	printf(" OSPF Hello: Priority %u ", hello->priority);
	
	if (len < 12) {
		printf("\n");
		return;
	}

	printf("Dead Interval %u\n", ntohl(hello->deadint));
	
	if (len < 16) 
		return;

	printf(" OSPF Hello: Designated Router %s\n", inet_ntoa(hello->designated));

	if (len < 20)
		return;

	printf(" OSPF Hello: Backup Designated Router %s\n", inet_ntoa(hello->backup));

	neigh = (struct in_addr *)(packet + sizeof(libtrace_ospf_hello_v2_t));
	len -= sizeof(libtrace_ospf_hello_v2_t);
	while (len >= 4) {
		printf(" OSPF Hello: Neighbour %s\n", inet_ntoa(*neigh));
		neigh++;
		len -= sizeof(struct in_addr);
	}



	return;
}
