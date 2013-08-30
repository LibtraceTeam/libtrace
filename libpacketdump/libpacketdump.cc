#include "config.h"
#include <libtrace.h>
#include <err.h>
#include <time.h>
#include "libpacketdump.h"
#include "lt_bswap.h"
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
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
#include "grammar.h"
}

enum decode_style_t {
    DECODE_NORMAL,
    DECODE_PARSER
};

typedef void (*decode_norm_t)(uint16_t type,const char *packet,int len);
typedef void (*decode_parser_t)(uint16_t type,const char *packet,int len, element_t* el);

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

static void formatted_hexdump(const char *packet, int len) {
	int i;

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

void trace_hexdump_packet(struct libtrace_packet_t *packet) {

	libtrace_linktype_t linktype;
	uint32_t length;
	const char *pkt_ptr = (char *)trace_get_packet_buffer(packet, &linktype, NULL);

	time_t sec = (time_t)trace_get_seconds(packet);
	
	length = trace_get_capture_length(packet);

	if (pkt_ptr == NULL || length == 0) {
		printf(" [No packet payload]\n");
		return;
	}

	printf("\n%s",ctime(&sec));
	printf(" Capture: Packet Length: %i/%i Direction Value: %i\n",
			(int)length,
			(int)trace_get_wire_length(packet),
			(int)trace_get_direction(packet));
	

	formatted_hexdump(pkt_ptr, (int)length);
	return;
}

void trace_dump_packet(struct libtrace_packet_t *packet)
{
	time_t sec = (time_t)trace_get_seconds(packet);
	libtrace_linktype_t linktype;
	uint32_t length;
	const char *link=(char *)trace_get_packet_buffer(packet,&linktype,NULL);
	
	length = trace_get_capture_length(packet);

	printf("\n%s",ctime(&sec));
	printf(" Capture: Packet Length: %i/%i Direction Value: %i\n",
			(int)length,
			(int)trace_get_wire_length(packet),
			(int)trace_get_direction(packet));
	if (!link) 
		printf(" [No link layer available]\n");
	else
		decode_next(link,length, "link",
			linktype);
}

static void generic_decode(uint16_t type,const char *packet, int len) {
	printf(" Unknown Protocol: %i",type);

	formatted_hexdump(packet, len);
}

static void *open_so_decoder(const char *name,int type)
{
	char path[1024];
	void *hdl;
	/* Only check LIBPKTDUMPDIR if we're not setuid.  Not bulletproof, but hopefully anyone who
	 * sets uid == euid will also clear the environment (eg sudo).
	 */
	if (getuid() == geteuid() && getenv("LIBPKTDUMPDIR")) {
		snprintf(path,sizeof(path),"%s/%s_%i.so",getenv("LIBPKTDUMPDIR"),name,type);
		hdl = dlopen(path,RTLD_LAZY);
		if (hdl)
			return hdl;
	}
	/* If the variable isn't set, *or* if we don't find anything, try the system location. */
	snprintf(path,sizeof(path),DIRNAME "/%s_%i.so",name,type);
	hdl = dlopen(path,RTLD_LAZY);
	if (hdl)
		return hdl;

	return hdl;
}

static void *open_protocol_decoder(const char *name, int type)
{
	char path[1024];
	void *hdl;
	/* Only check LIBPKTDUMPDIR if we're not setuid.  Not bulletproof, but hopefully anyone who
	 * sets uid == euid will also clear the environment (eg sudo).
	 */
	if (getuid() == geteuid() && getenv("LIBPKTDUMPDIR")) {
		snprintf(path,sizeof(path),"%s/%s_%i.protocol",getenv("LIBPKTDUMPDIR"),name,type);
		hdl = parse_protocol_file(path);
		if (hdl)
			return hdl;
	}
	/* Try the system directory */
	snprintf(path,sizeof(path),DIRNAME "/%s_%i.protocol",
		name,type);
	hdl = parse_protocol_file(path);

	if (!hdl)
		return hdl;

	return hdl;
}

void decode_next(const char *packet,int len,const char *proto_name,int type)
{
	std::string sname(proto_name);

	// if we haven't worked out how to decode this type yet, load the
	// appropriate files to do so
	if (decoders[sname].find(type)==decoders[sname].end()) {
		void *hdl;
		decode_funcs_t *func = new decode_funcs_t;
		decode_t dec;

		/* Try and find a .so to handle this protocol */
		hdl = open_so_decoder(sname.c_str(),type);
		if (hdl) {
			void *s=dlsym(hdl,"decode");
			if (s) {
				// use the shared library
				func->decode_n = (decode_norm_t)s;
				dec.style = DECODE_NORMAL;
				dec.el = NULL; 
			}
			else {
				dlclose(hdl);
				hdl = NULL;
			}
		}

		/* We didn't successfully open the .so, try finding a .protocol that we can use */
		if (!hdl) {
			hdl = open_protocol_decoder(sname.c_str(),type);
			if (hdl) {
				// use the protocol file
				func->decode_p = decode_protocol_file;
				dec.style = DECODE_PARSER;
				dec.el = (element_t*)hdl;
			}
		}

		/* No matches found, fall back to the generic decoder. */
		/* TODO: We should have a variety of fallback decoders based on the protocol. */
		if(!hdl)
		{
			// no protocol file either, use a generic one
			func->decode_n = generic_decode;
			dec.style = DECODE_NORMAL;
			dec.el = NULL;
		} 

		dec.func = func;
		decoders[sname][type] = dec;
	}

	/* TODO: Instead of haxing this here, we should provide a series of generic_decode's
	 * and let the code above deal with it.
	 */
	if (decoders[sname][type].func->decode_n == generic_decode) {
		/* We can't decode a link, so lets skip that and see if libtrace
		 * knows how to find us the ip header
		 */

		/* Also, don't try to skip if the linktype is not valid, 
		 * because libtrace will just assert fail and that's never
		 * good */
		if (sname=="link" && type != -1) {
			uint16_t newtype;
			uint32_t newlen=len;
			const char *network=(const char*)trace_get_payload_from_link((void*)packet,
					(libtrace_linktype_t)type,
					&newtype,&newlen);
			if (network) {
				printf("skipping unknown link header of type %i to network type %i\n",type,newtype);
				/* Should hex dump this too. */
				decode_next(network,newlen,"eth",newtype);
				return;
			}
		}
		else {
			printf("unknown protocol %s/%i\n",sname.c_str(),type);
		}
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

