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
extern "C"{
#include "parser/parser.h"
}

enum decode_style_t {
    DECODE_NORMAL,
    DECODE_PARSER
};

typedef void (*decode_norm_t)(uint16_t type,char *packet,int len);
typedef void (*decode_parser_t)(uint16_t type,char *packet,int len, element_t* el);

typedef union decode_funcs {
    decode_norm_t decode_n;
    decode_parser_t decode_p;
} decode_funcs_t;

typedef struct decoder {
    enum decode_style_t style;
    decode_funcs_t *func;
    element_t *el; // make a union of structs with all args in it for all funcs?
} decode_t;


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

	// if we haven't worked out how to decode this type yet, load the
	// appropriate files to do so
	if (decoders[sname].find(type)==decoders[sname].end()) {
		void *hdl;
		char name[1024];
		decode_funcs_t *func = new decode_funcs_t;
		decode_t dec;
		snprintf(name,sizeof(name),"%s/%s_%i.so",DIRNAME,sname.c_str(),type);
		hdl = dlopen(name,RTLD_LAZY);
		if (!hdl) {
			// if there is no shared library, try a protocol file
			snprintf(name,sizeof(name),"%s/%s_%i.protocol",
				DIRNAME,sname.c_str(),type);
			hdl = parse_protocol_file(name);

			if(!hdl)
			{
				// no protocol file either, use a generic one
				func->decode_n = generic_decode;
				dec.style = DECODE_NORMAL;
				dec.el = NULL;
			} else {
				// use the protocol file
				func->decode_p = decode_protocol_file;
				dec.style = DECODE_PARSER;
				dec.el = (element_t*)hdl;
			}
		} else {
			void *s=dlsym(hdl,"decode");
			if (!s) {
				// the shared library doesnt have a decode func
				// TODO should try the protocol file now
				func->decode_n = generic_decode;
				dec.style = DECODE_NORMAL;
				dec.el = NULL;
			}
			else
			{
				// use the shared library
				func->decode_n = (decode_norm_t)s;
				dec.style = DECODE_NORMAL;
				dec.el = NULL; 
			}
		}
		dec.func = func;
		decoders[sname][type] = dec;
	}

	// decode using the appropriate function
	switch(decoders[sname][type].style)
	{
		case DECODE_NORMAL:
			decoders[sname][type].func->decode_n(type,packet,len);
			break;

		case DECODE_PARSER:
			decoders[sname][type].func->decode_p(type,packet,len,
				decoders[sname][type].el);
			break;

	};
}
