%module libtrace
%{
#include <arpa/inet.h>
#include "libtrace.h"
%}
%include "carrays.i"
%include "cmalloc.i"

%nodefault;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

struct in_addr {
	int s_addr;
};

struct libtrace_ip
  {
    unsigned int ip_hl:4;		/**< header length */
    unsigned int ip_v:4;		/**< version */
    uint8_t ip_tos;			/**< type of service */
#define	IP_RF 0x8000			/**< reserved fragment flag */
#define	IP_DF 0x4000			/**< dont fragment flag */
#define	IP_MF 0x2000			/**< more fragments flag */
#define	IP_OFFMASK 0x1fff		/**< mask for fragmenting bits */
    uint8_t ip_ttl;			/**< time to live */
    uint8_t ip_p;			/**< protocol */
    %extend {
    // Needs ntohs
    const uint16_t ip_sum;		/**< checksum */
    const uint16_t ip_len;		/**< total length */
    const uint16_t ip_id;		/**< identification */
    const uint16_t ip_off;		/**< fragment offset field */
    // Needs ntoha
    %newobject ip_src;
    %newobject ip_dst;
    const char *const ip_src;
    const char *const ip_dst;
    }
  };




%{
#define MAKE_NTOHS(class,member) \
	    uint16_t class ## _ ## member ## _get (struct class *self) { \
	    	return ntohs(self->member); \
	    }

#define MAKE_NTOHL(class,member) \
	    uint32_t class ## _ ## member ## _get (struct class *self) { \
	    	return ntohl(self->member); \
	    }

	    MAKE_NTOHS(libtrace_ip,ip_sum);
	    MAKE_NTOHS(libtrace_ip,ip_len);
	    MAKE_NTOHS(libtrace_ip,ip_id);
	    MAKE_NTOHS(libtrace_ip,ip_off);
	    char *libtrace_ip_ip_src_get(struct libtrace_ip *self) {
	    	return strdup(inet_ntoa(self->ip_src));
	    }
	    char *libtrace_ip_ip_dst_get(struct libtrace_ip *self) {
	    	return strdup(inet_ntoa(self->ip_dst));
	    }
%};


struct libtrace_tcp
  {
    uint16_t res1:4;		/**< Reserved bits */
    uint16_t doff:4;		
    uint16_t fin:1;		/**< FIN */
    uint16_t syn:1;		/**< SYN flag */
    uint16_t rst:1;		/**< RST flag */
    uint16_t psh:1;		/**< PuSH flag */
    uint16_t ack:1;		/**< ACK flag */
    uint16_t urg:1;		/**< URG flag */
    uint16_t res2:2;		/**< Reserved */
%extend {
    // needs ntohs
    const uint16_t source;		/**< Source Port */
    const uint16_t dest;		/**< Destination port */
    const uint16_t window;		/**< Window Size */
    const uint16_t check;		/**< Checksum */
    const uint16_t urg_ptr;		/**< Urgent Pointer */
    // needs ntohl
    const uint32_t seq;		/**< Sequence number */
    const uint32_t ack_seq;		/**< Acknowledgement Number */
}
};

%{
 MAKE_NTOHS(libtrace_tcp,source)
 MAKE_NTOHS(libtrace_tcp,dest)
 MAKE_NTOHS(libtrace_tcp,window)
 MAKE_NTOHS(libtrace_tcp,check)
 MAKE_NTOHS(libtrace_tcp,urg_ptr)

 MAKE_NTOHL(libtrace_tcp,seq)
 MAKE_NTOHL(libtrace_tcp,ack_seq)
%}

/** UDP Header for dealing with UDP packets */
struct libtrace_udp {
  %extend {
  // Needs ntohs
  const uint16_t	source;		/**< Source port */
  const uint16_t	dest;		/**< Destination port */
  const uint16_t	len;		/**< Length */
  const uint16_t	check;		/**< Checksum */
  }
};

%{
 MAKE_NTOHS(libtrace_udp,source)
 MAKE_NTOHS(libtrace_udp,dest)
 MAKE_NTOHS(libtrace_udp,len)
 MAKE_NTOHS(libtrace_udp,check)
%}

struct libtrace_icmp
{
  uint8_t type;		/* message type */
  uint8_t code;		/* type sub-code */
  uint16_t checksum;
  union
  {
    struct
    {
      uint16_t	id;
      uint16_t	sequence;
    } echo;			/* echo datagram */
    uint32_t	gateway;	/* gateway address */
    struct
    {
      uint16_t	__unused;
      uint16_t	mtu;
    } frag;			/* path mtu discovery */
  } un;
};

%rename (Packet) libtrace_packet_t;
struct libtrace_packet_t {};

%extend libtrace_packet_t {
	libtrace_packet_t() { 
		struct libtrace_packet_t *packet = malloc(sizeof(struct libtrace_packet_t));
		return packet;
		}
	~libtrace_packet_t() { free(self);}
	struct libtrace_ip *trace_get_ip() {
		return trace_get_ip(self);
	}
	struct libtrace_tcp *trace_get_tcp() {
		return trace_get_tcp(self);
	}
	struct libtrace_udp *trace_get_udp() {
		return trace_get_udp(self);
	}
	struct libtrace_icmp *trace_get_icmp() {
		return trace_get_icmp(self);
	}
	double trace_get_seconds() {
		return trace_get_seconds(self);
	}
};

%rename (Trace) libtrace_t;
struct libtrace_t {};

%extend libtrace_t {
	libtrace_t(char *uri) { return trace_create(uri); };
	~libtrace_t() { trace_destroy(self); }
	int trace_read_packet(struct libtrace_packet_t *packet) { 
		return trace_read_packet(self,packet);
	}
}; 

