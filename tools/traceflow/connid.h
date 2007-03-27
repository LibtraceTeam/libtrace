#ifndef CONNID_H
#define CONNID_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

uint32_t connid_next = 0;


class Connid {
	private:
	int cmp(const Connid &b) const {
		
		
		if (port_b != b.port_b)
                        return port_b - b.port_b;
		if (port_a != b.port_a)
			return port_a - b.port_a;
		
		if (ip_b != b.ip_b)
			return (ip_b < b.ip_b);
		
		if (ip_b < b.ip_b)    return -1;
		if (ip_b > b.ip_b)    return 1;
		if (ip_a < b.ip_a)    return -1;
		if (ip_a > b.ip_a)    return 1;
		
		return proto - b.proto;
	}
        uint32_t ip_a;          
        uint32_t ip_b;
        uint16_t port_a;
        uint16_t port_b;
        uint8_t proto;
	uint32_t id_num;
	public:
	Connid() {
		ip_a = 0;
		ip_b = 0;
		port_a = 0;
		port_b = 0;
		proto = 0;
		id_num = connid_next;
		connid_next ++;
	}
	Connid(uint32_t ip_src, uint32_t ip_dst, uint16_t port_src,
			uint16_t port_dst, uint8_t protocol) {
		ip_a = ip_src;
		ip_b = ip_dst;
		port_a = port_src;
		port_b = port_dst;
		proto = protocol;
		id_num = connid_next;
		connid_next ++;
	}
	
	bool operator<(const Connid &b) const {
		
		if (port_b != b.port_b)
                        return port_b < b.port_b;
		if (port_a != b.port_a)
			return port_a < b.port_a;
		
		if (ip_b != b.ip_b)
			return (ip_b < b.ip_b);

		if (ip_a != b.ip_a)
			return ip_a < b.ip_a;

		return proto < b.proto;
		
	}

	uint32_t get_id_num() const {
		return id_num;
	}
	
	char *get_server_ip_str() const {
		struct in_addr inp;
		inp.s_addr = ip_a;
		return inet_ntoa(inp);
	}

	char *get_client_ip_str() const {
		struct in_addr inp;
		inp.s_addr = ip_b;
		return inet_ntoa(inp);
	}
		
	uint16_t get_server_port() const {
		return port_a;
	}

	uint16_t get_client_port() const {
		return port_b;
	}

	uint8_t get_protocol() const {
		return proto;
	}
	
};


#endif
