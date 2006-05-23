#ifndef REPORT_H
#define REPORT_H

void dir_per_packet(struct libtrace_packet_t *packet);
void error_per_packet(struct libtrace_packet_t *packet);
void flow_per_packet(struct libtrace_packet_t *packet);
void port_per_packet(struct libtrace_packet_t *packet);
void protocol_per_packet(struct libtrace_packet_t *packet);
void tos_per_packet(struct libtrace_packet_t *packet);
void ttl_per_packet(struct libtrace_packet_t *packet);

void dir_report(void);
void error_report(void);
void flow_report(void);
void port_report(void);
void protocol_report(void);
void tos_report(void);
void ttl_report(void);

#endif
