#include <libtrace.h>
#include <err.h>
#include <time.h>
#include "libpacketdump.h"
#include "config.h"
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <getopt.h>

#include <sys/socket.h>

#ifdef HAVE_NETINET_ETHER
#  include <netinet/ether.h>
#endif


#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
#  error "Can't find inttypes.h"
#endif

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#ifdef HAVE_SYS_LIMITS_H
#  include <sys/limits.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>

#include <net/if_arp.h>
#ifdef HAVE_NETINET_IF_ETHER_H
#  include <netinet/if_ether.h>
#endif 
#include <dlfcn.h>
#include <map>
#include <string>
#include <ctype.h>
#include "libpacketdump.h"

typedef void (*decode_t)(uint16_t type,char *packet,int len);

static std::map<std::string,std::map<uint16_t,decode_t> > decoders;

#define WIDTH 16

#ifndef DIRNAME
#define DIRNAME "./"
#warning "No DIRNAME set!"
#endif

void trace_dump_packet(struct libtrace_packet_t *packet)
{
	time_t sec = (time_t)trace_get_seconds(packet);
	char *link=(char *)trace_get_link(packet);

	printf("%s",ctime(&sec));
	decode_next(link,packet->size-trace_get_framing_length(packet),
			"link",
			trace_get_link_type(packet));
}

static void generic_decode(uint16_t type,char *packet, int len) {
	int i;
	printf(" Unknown Protocol: %i",type);
	for(i=0;i<len; /* Nothing */ ) {
		int j;
		printf("\n ");
		for(j=0;j<WIDTH;j++) {
			if (i+j<len)
				printf(" %02x",(unsigned char)packet[i+j]);
			else
				printf("   ");
		}
		printf("    ");
		for(j=0;j<WIDTH;j++) {
			if (i+j<len)
				if (isprint((unsigned char)packet[i+j]))
					printf("%c",(unsigned char)packet[i+j]);
				else
					printf(".");
			else
				printf("   ");
		}
		if (i+WIDTH>len)
			break;
		else
			i+=WIDTH;
	}
	printf("\n");
}

void decode_next(char *packet,int len,char *proto_name,int type)
{
	std::string sname(proto_name);
	if (decoders[sname].find(type)==decoders[sname].end()) {
		void *hdl;
		char name[1024];
		snprintf(name,sizeof(name),"%s/%s_%i.so",DIRNAME,sname.c_str(),type);
		hdl = dlopen(name,RTLD_LAZY);
		if (!hdl) 
			decoders[sname][type]=generic_decode;
		else {
			void *s=dlsym(hdl,"decode");
			if (!s) {
				decoders[sname][type]=generic_decode;
			}
			else
				decoders[sname][type]=(decode_t)s;
		}
	}
	decoders[sname][type](type,packet,len);
}


