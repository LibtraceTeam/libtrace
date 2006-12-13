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
		struct libtrace_packet_t *packet = trace_create_packet();
		return packet;
		}
	~libtrace_packet_t() { 
		trace_destroy_packet(self);
		}
	libtrace_packet_t *copy_packet() {
		return trace_copy_packet(self);
	}
	void *get_link() {
		return trace_get_link(self);
	}
	void *get_transport(uint8_t *proto, uint32_t *remaining) {
		return trace_get_transport(self, proto, remaining);
	}
	struct libtrace_ip *get_ip() {
		return trace_get_ip(self);
	}
	struct libtrace_tcp *get_tcp() {
		return trace_get_tcp(self);
	}
	struct libtrace_udp *get_udp() {
		return trace_get_udp(self);
	}
	struct libtrace_icmp *get_icmp() {
		return trace_get_icmp(self);
	}
	char *get_destination_mac() {
		return trace_ether_ntoa(trace_get_destination_mac(self),0);
	}
	char *get_source_mac() {
		return trace_ether_ntoa(trace_get_source_mac(self),0);
	}
	char *ether_ntoa(uint8_t *mac) {
		return trace_ether_ntoa(mac, 0);
	}
	uint16_t get_source_port() {
		return trace_get_source_port(self);
	}
	uint16_t get_destination_port() {
		return trace_get_destination_port(self);
	}
	double get_seconds() {
		return trace_get_seconds(self);
	}
	uint64_t get_erf_timestamp() {
		return trace_get_erf_timestamp(self);
	}
	struct timeval get_timeval() {
		return trace_get_timeval(self);
	}
	int get_capture_length() {
		return trace_get_capture_length(self);
	}
	size_t set_capture_length(size_t size) {
		return trace_set_capture_length(self,size);
	}
	int get_wire_lenth() {
		return trace_get_wire_length(self);
	}
	int get_framing_length() {
		return trace_get_framing_length(self);
	}
	int get_wire_length() {
		return trace_get_wire_length(self);
	}
	libtrace_linktype_t get_link_type() {
		return trace_get_link_type(self);
	}
	int8_t get_direction() {
		return trace_get_direction(self);
	}
	int8_t set_direction(int8_t direction) {
		return trace_set_direction(self,direction);
	}
	int apply_filter(struct libtrace_filter_t *filter) {
		return trace_apply_filter(filter,self);
	}
	uint8_t get_server_port(uint8_t protocol, uint16_t source,
			uint16_t dest) {
		return trace_get_server_port(protocol,source,dest);
	}
	
};

%rename (Filter) libtrace_filter_t;
struct libtrace_filter_t {};

%extend libtrace_filter_t {
	libtrace_filter_t(char *filterstring) { 
		return trace_create_filter(filterstring); 
	};
	~libtrace_filter_t() {
		trace_destroy_filter(self);
	};
	int apply_filter(struct libtrace_packet_t *packet) {
		return trace_apply_filter(self,packet);
	}
};

%rename (Trace) libtrace_t;
struct libtrace_t {};

%extend libtrace_t {
	libtrace_t(char *uri) { return trace_create(uri); };
	~libtrace_t() { trace_destroy(self); }
	int read_packet(struct libtrace_packet_t *packet) { 
		return trace_read_packet(self,packet);
	}
	int start() {
		return trace_start(self);
	}
	int pause() {
		return trace_pause(self);
	}
	void help() {
		trace_help();
	}
	int config(trace_option_t option, void *value) {
		return trace_config(self, option, value); 
	}
	libtrace_err_t get_err() {
		return trace_get_err(self);
	}
	bool is_err() {
		return trace_is_err(self);
	}
}; 

%rename (OutputTrace) libtrace_out_t;
struct libtrace_out_t {};

%extend libtrace_out_t {
	libtrace_out_t(char *uri) { return trace_create_output(uri); };
	~libtrace_t() { trace_destroy_output(self); }
	int start_output() {
		return trace_start_output(self);
	}
	int config_output(trace_option_output_t option, void *value) {
		return trace_config_output(self, option, value);
	}
	libtrace_err_t get_err_output() {
		return trace_get_err_output(self);
	}
	bool is_err_output() {
		return trace_is_err_output(self);
	}
	int write_packet(libtrace_packet_t *packet) {
		return trace_write_packet(self, packet);
	}
};

