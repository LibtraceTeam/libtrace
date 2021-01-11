#include "libtrace.h"
#include <assert.h>

#define CASSERT(predicate, file) _impl_CASSERT_LINE(predicate,__LINE__,file)

#define _impl_PASTE(a,b) a##b
#define _impl_CASSERT_LINE(predicate, line, file) \
	typedef char _impl_PASTE(assertion_failed_##file##_,line)[2*!!(predicate)-1];

/*
 * Structures:
 * libtrace_ether_t						done
 * libtrace_ip_t						done
 * libtrace_ip6_t						done
 * libtrace_ip6_frag_t
 * libtrace_ip6_ext_t
 * libtrace_tcp_t						done
 * libtrace_udp_t						done
 * libtrace_icmp_t						done
 * libtrace_icmp6_t
 * libtrace_llcsnap_t
 * libtrace_8021q_t						broken - fields crossing byte boundaries
 * libtrace_atm_cell_t					broken - fields crossing byte boundaries
 * libtrace_atm_nni_cell_t				broken - fields crossing byte boundaries
 * libtrace_atm_capture_cell_t			broken - fields crossing byte boundaries
 * libtrace_atm_nni_capture_cell_t		broken - fields crossing byte boundaries
 * libtrace_ppp_t
 * libtrace_pppoe_t						done
 * libtrace_gre_t
 * libtrace_vxlan_t						done - check vni
 * libtrace_80211_t						done
 * libtrace_radiotap_t					done
 * libtrace_ospf_v2_t					done
 * libtrace_ospf_options_t				done
 * libtrace_ospf_lsa_v2_t				done
 * libtrace_ospf_hello_v2_t				done
 * libtrace_ospf_db_desc_v2_t			done
 * libtrace_ospf_ls_req_t				done
 * libtrace_ospf_ls_update_t			part done
 * libtrace_ospf_as_external_lsa_v2_t
 * libtrace_ospf_summary_lsa_v2_t
 * libtrace_ospf_network_lsa_v2_t
 * libtrace_ospf_link_v2_t
 * libtrace_ospf_router_lsa_v2_t
 * libtrace_sll_header_t
 */

int main() {
	uint8_t buf_eth[14] = {0x00, 0x02, 0x6f, 0x21, 0xec, 0x5f, 0x00,
						   0x02, 0x6f, 0x21, 0xec, 0x52, 0x88, 0x8e};
	libtrace_ether_t *eth = (libtrace_ether_t *)buf_eth;
	for (int i = 0; i < 6; i++) {
		assert(eth->ether_dhost[i] == buf_eth[i]);
		assert(eth->ether_shost[i] == buf_eth[i + 6]);
	}
	assert(ntohs(eth->ether_type) == TRACE_ETHERTYPE_8021X);

	uint8_t buf_ip4[20] = {0x45, 0x00, 0x05, 0x8c, 0x74, 0x9f, 0x40,
						   0x00, 0x31, 0x06, 0x00, 0x00, 0x82, 0xcb,
						   0xed, 0xc5, 0x61, 0x59, 0x5b, 0x9f};
	libtrace_ip_t *ip4 = (libtrace_ip_t *)buf_ip4;
	assert(ip4->ip_v == 4);
	assert(ip4->ip_hl == 5);
	assert(ip4->ip_tos == 0);
	assert(ntohs(ip4->ip_len) == 1420);
	assert(ntohs(ip4->ip_id) == 29855);
	assert(ntohs(ip4->ip_off) == 16384);
	assert(ip4->ip_ttl == 49);
	assert(ip4->ip_p == TRACE_IPPROTO_TCP);
	assert(ntohs(ip4->ip_sum) == 0);
	assert(ntohl(ip4->ip_src.s_addr) == 2194402757);
	assert(ntohl(ip4->ip_dst.s_addr) == 1633246111);
	// check flags
	buf_ip4[0] = 0x4f; assert(ip4->ip_hl == 15);
	buf_ip4[0] = 0xf5; assert(ip4->ip_v == 15);
	

	uint8_t buf_ip6[40] = {0x60, 0x00, 0x00, 0x00, 0x00,
						   0x54, 0x11, 0xff, 0x26, 0x07,
						   0xf2, 0xc0, 0xf0, 0x0f, 0xb0,
						   0x01, 0x00, 0x00, 0x00, 0x00,
						   0xfa, 0xce, 0xb0, 0x0c, 0x20,
						   0x01, 0x04, 0xf8, 0x00, 0x03,
						   0x00, 0x0d, 0x00, 0x00, 0x00,
						   0x00, 0x00, 0x00, 0x00, 0x61};
	libtrace_ip6_t *ip6 = (libtrace_ip6_t *)buf_ip6;
	assert(ntohl(ip6->flow) == 1610612736);
	assert(ntohs(ip6->plen) == 84);
	assert(ip6->nxt == TRACE_IPPROTO_UDP);
	assert(ip6->hlim == 255);
	for (int i = 0; i < 16; i++) {
		assert(ip6->ip_src.s6_addr[i] == buf_ip6[i + 8]);
		assert(ip6->ip_dst.s6_addr[i] == buf_ip6[i + 24]);
	}

	uint8_t buf_udp[8] = {0x44, 0x5c, 0x44, 0x5c, 0x00, 0x90, 0xba, 0x03};
	libtrace_udp_t *udp = (libtrace_udp_t *)buf_udp;
	assert(ntohs(udp->source) == 17500);
	assert(ntohs(udp->dest) == 17500);
	assert(ntohs(udp->len) == 144);
	assert(ntohs(udp->check) == 47619);

	uint8_t buf_tcp[20] = {0x06, 0xe0, 0x00, 0x19, 0x79, 0x43, 0xd3,
						   0xbb, 0x88, 0xa4, 0x36, 0xd2, 0x50, 0x18,
						   0xfe, 0x0a, 0xc3, 0xfc, 0x00, 0x00};
	libtrace_tcp_t *tcp = (libtrace_tcp_t *)buf_tcp;
	assert(ntohs(tcp->source) == 1760);
	assert(ntohs(tcp->dest) == 25);
	assert(ntohl(tcp->seq) == 2034488251);
	assert(ntohl(tcp->ack_seq) == 2292463314);
	assert(tcp->doff == 5);
	assert(tcp->res1 == 0);
	assert(tcp->ecn_ns == 0);
	assert(tcp->cwr == 0);
	assert(tcp->ece == 0);
	assert(tcp->urg == 0);
	assert(tcp->ack == 1);
	assert(tcp->psh == 1);
	assert(tcp->rst == 0);
	assert(tcp->syn == 0);
	assert(tcp->fin == 0);
	assert(ntohs(tcp->window) == 65034);
	assert(ntohs(tcp->check) == 50172);
	assert(ntohs(tcp->urg_ptr) == 0);
	// check flags
	buf_tcp[12] = 0xf0; assert(tcp->doff == 15);
	buf_tcp[12] = 0x0e; assert(tcp->res1 == 7);
	buf_tcp[12] = 0x01; assert(tcp->ecn_ns == 1);
	buf_tcp[13] = 0x80; assert(tcp->cwr == 1);
	buf_tcp[13] = 0x40; assert(tcp->ece == 1);
	buf_tcp[13] = 0x20; assert(tcp->urg == 1);
	buf_tcp[13] = 0x10; assert(tcp->ack == 1);
	buf_tcp[13] = 0x08; assert(tcp->psh == 1);
	buf_tcp[13] = 0x04; assert(tcp->rst == 1);
	buf_tcp[13] = 0x02; assert(tcp->syn == 1);
	buf_tcp[13] = 0x01; assert(tcp->fin == 1);
	

	uint8_t buf_icmp_req[8] = {0x08, 0x00, 0x87, 0x40, 0x70, 0xbf, 0x00, 0x00};
	libtrace_icmp_t *icmp_req = (libtrace_icmp_t *)buf_icmp_req;
	assert(icmp_req->type == 8); // echo (ping) request
	assert(icmp_req->code == 0);
	assert(ntohs(icmp_req->checksum) == 34624);
	assert(ntohs(icmp_req->un.echo.id) == 28863);
	assert(ntohs(icmp_req->un.echo.sequence) == 0);

	uint8_t buf_icmp_reply[8] = {0x00, 0x00, 0x54, 0x68, 0x00, 0x01, 0x00, 0xf3};
	libtrace_icmp_t *icmp_reply = (libtrace_icmp_t *)buf_icmp_reply;
	assert(icmp_reply->type == 0); // echo (ping) reply
	assert(icmp_reply->code == 0);
	assert(ntohs(icmp_reply->checksum) == 21608);
	assert(ntohs(icmp_reply->un.echo.id) == 1);
	assert(ntohs(icmp_reply->un.echo.sequence) == 243);

	uint8_t buf_pppoe[10] = {0x11, 0x09, 0x00, 0x00, 0x00,
							 0x04, 0x01, 0x01, 0x00, 0x00};
	libtrace_pppoe_t *pppoe = (libtrace_pppoe_t *)buf_pppoe;
	assert(pppoe->version == 1);
	assert(pppoe->type == 1);
	assert(pppoe->code == 9);
	assert(ntohs(pppoe->session_id) == 0);
	assert(ntohs(pppoe->length) == 4);
	// check flags
	buf_pppoe[0] = 0x0f; assert(pppoe->version == 15);
	buf_pppoe[0] = 0xf0; assert(pppoe->type == 15);

	uint8_t buf_vxlan[8] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x00};
	libtrace_vxlan_t *vxlan = (libtrace_vxlan_t *)buf_vxlan;
	assert(vxlan->flags == 8);
	assert(vxlan->reserved1[0] == 0);
	assert(vxlan->reserved1[1] == 0);
	assert(vxlan->reserved1[2] == 0);
	uint32_t vni = vxlan->vni[0] << 16 | vxlan->vni[1] << 8 | vxlan->vni[2];
	assert(vni == 123);
	assert(vxlan->reserved2 == 0);

	uint8_t buf_radiotap[25] = {0x00, 0x00, 0x19, 0x00, 0x6f, 0x08, 0x00, 0x00, 0x04,
								0x64, 0x90, 0x91, 0x00, 0x00, 0x00, 0x00, 0x10, 0x02,
								0x9e, 0x09, 0x80, 0x04, 0xcc, 0xa5, 0x00};
	libtrace_radiotap_t *radio_tap = (libtrace_radiotap_t *)buf_radiotap;
	/* radiotap using little endian byte order */
	assert(radio_tap->it_version == 0);
	assert(radio_tap->it_pad == 0);
	assert(radio_tap->it_len == 25);
	assert(radio_tap->it_present == 2159);

	uint8_t buf_80211[24] = {0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
							 0xff, 0x00, 0x16, 0xb6, 0xe3, 0xe9, 0x8f, 0x00, 0x16,
							 0xb6, 0xe3, 0xe9, 0x8f, 0x30, 0x95};
	libtrace_80211_t *radio = (libtrace_80211_t *)buf_80211;
	assert(radio->protocol == 0); // shouldnt this be version?
	assert(radio->type == 0); // management frame
	assert(radio->subtype == 8);
	assert(radio->to_ds == 0);
	assert(radio->from_ds == 0);
	assert(radio->more_frag == 0);
	assert(radio->retry == 0);
	assert(radio->power == 0);
	assert(radio->more_data == 0);
	assert(radio->wep == 0);
	assert(radio->order == 0);
	assert(ntohs(radio->duration) == 0);
	for (int i = 0; i < 6; i++) {
		assert(radio->mac1[i] == buf_80211[i + 4]);
		assert(radio->mac2[i] == buf_80211[i + 10]);
		assert(radio->mac3[i] == buf_80211[i + 16]);
	}
	assert(ntohs(radio->SeqCtl) == 12437);
	// check flags
	buf_80211[0] = 0x03; assert(radio->protocol == 3);
	buf_80211[0] = 0x0c; assert(radio->type == 3);
	buf_80211[0] = 0xf0; assert(radio->subtype == 15);
	buf_80211[1] = 0x01; assert(radio->to_ds == 1);
	buf_80211[1] = 0x02; assert(radio->from_ds == 1);
	buf_80211[1] = 0x04; assert(radio->more_frag == 1);
	buf_80211[1] = 0x08; assert(radio->retry == 1);
	buf_80211[1] = 0x10; assert(radio->power == 1);
	buf_80211[1] = 0x20; assert(radio->more_data == 1);
	buf_80211[1] = 0x40; assert(radio->wep == 1);
	buf_80211[1] = 0x80; assert(radio->order == 1);

	
	/************************* OSPF *************************/
	uint8_t buf_ospf[32] = {0x02, 0x01, 0x00, 0x34, 0xc0, 0xa8, 0xff, 0x0f,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
							0x00, 0x00, 0x01, 0x10, 0x5a, 0x83, 0x41, 0x12};
	libtrace_ospf_v2_t *ospf_hdr = (libtrace_ospf_v2_t *)buf_ospf;
	assert(ospf_hdr->ospf_v == 2);
	assert(ospf_hdr->type == TRACE_OSPF_HELLO); // hello packet
	assert(ntohs(ospf_hdr->ospf_len) == 52);
	assert(ntohl(ospf_hdr->router.s_addr) == 3232300815);
	assert(ntohl(ospf_hdr->area.s_addr) == 0);
	assert(ntohs(ospf_hdr->sum) == 0);
	assert(ntohs(ospf_hdr->au_type) == 2); // cryptographic
	assert(ntohs(ospf_hdr->zero) == 0);
	assert(ospf_hdr->au_key_id == 1);
	assert(ospf_hdr->au_data_len == 16);
	assert(ntohl(ospf_hdr->au_seq_num) == 1518551314);

	uint8_t buf_ospf_hello[28] = {0xff, 0xff, 0xff, 0x00, 0x00, 0x0a, 0x12, 0x01,
								  0x00, 0x00, 0x00, 0x28, 0xc0, 0xa8, 0x79, 0x04,
								  0xc0, 0xa8, 0x79, 0x05};
	libtrace_ospf_hello_v2_t *ospf_hello = (libtrace_ospf_hello_v2_t *)buf_ospf_hello;
	assert(ntohl(ospf_hello->mask.s_addr) == 4294967040);
	assert(ntohs(ospf_hello->interval) == 10);
	libtrace_ospf_options_t *ospf_opts = (libtrace_ospf_options_t *)&ospf_hello->hello_options;
	assert(ospf_opts->unused2 == 0);
	assert(ospf_opts->dc_bit == 0);
	assert(ospf_opts->ea_bit == 1);
	assert(ospf_opts->np_bit == 0);
	assert(ospf_opts->mc_bit == 0);
	assert(ospf_opts->e_bit == 1);
	assert(ospf_opts->unused1 == 0);
	assert(ospf_hello->priority == 1);
	assert(ntohl(ospf_hello->deadint) == 40);
	assert(ntohl(ospf_hello->designated.s_addr) == 3232266500);
	assert(ntohl(ospf_hello->backup.s_addr) == 3232266501);
	// check flags
	buf_ospf_hello[6] = 0x02; assert(ospf_opts->e_bit == 1);
	buf_ospf_hello[6] = 0x04; assert(ospf_opts->mc_bit == 1);
	buf_ospf_hello[6] = 0x08; assert(ospf_opts->np_bit == 1);
	buf_ospf_hello[6] = 0x10; assert(ospf_opts->ea_bit == 1);
	buf_ospf_hello[6] = 0x20; assert(ospf_opts->dc_bit == 1);

	uint8_t buf_ospf_db[8] = {0x05, 0xc4, 0x52, 0x07, 0x00, 0x00, 0x24, 0x8a};
	libtrace_ospf_db_desc_v2_t *ospf_db = (libtrace_ospf_db_desc_v2_t *)buf_ospf_db;
	assert(ntohs(ospf_db->mtu) == 1476);
	assert(*(uint8_t *)&ospf_db->db_desc_options == 82);
	assert(ospf_db->zero == 0);
	assert(ospf_db->db_desc_i == 1);
	assert(ospf_db->db_desc_m == 1);
	assert(ospf_db->db_desc_ms == 1);
	assert(ntohl(ospf_db->seq) == 9354);
	// check flags
	buf_ospf_db[3] = 0x01; assert(ospf_db->db_desc_ms == 1);
	buf_ospf_db[3] = 0x02; assert(ospf_db->db_desc_m == 1);
	buf_ospf_db[3] = 0x04; assert(ospf_db->db_desc_i == 1);
	buf_ospf_db[3] = 0xf8; assert(ospf_db->zero == 31);


	uint8_t buf_ospf_lsa[20] = {0x00, 0x28, 0x22, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
								0x01, 0x01, 0x80, 0x00, 0x00, 0x01, 0xbf, 0x62, 0x00, 0x24};
	libtrace_ospf_lsa_v2_t *ospf_lsa = (libtrace_ospf_lsa_v2_t *)buf_ospf_lsa;
	assert(ntohs(ospf_lsa->age) == 40);
	assert(*(uint8_t *)&ospf_lsa->lsa_options == 34);
	assert(ospf_lsa->lsa_type == TRACE_OSPF_LS_ROUTER);
	assert(ntohl(ospf_lsa->ls_id.s_addr) == 16843009); // 1.1.1.1
	assert(ntohl(ospf_lsa->adv_router.s_addr) == 16843009); // 1.1.1.1
	assert(ntohl(ospf_lsa->seq) == 2147483649);
	assert(ntohs(ospf_lsa->checksum) == 48994);
	assert(ntohs(ospf_lsa->length) == 36);

	uint8_t buf_ospf_ls_req[12] = {0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
	libtrace_ospf_ls_req_t *ospf_ls_req = (libtrace_ospf_ls_req_t *)buf_ospf_ls_req;
	assert(ntohl(ospf_ls_req->ls_type) == TRACE_OSPF_LS_ROUTER);
	assert(ntohl(ospf_ls_req->ls_id) == 16843009); // 1.1.1.1
	assert(ntohl(ospf_ls_req->advertising_router) == 16843009); // 1.1.1.1

	uint8_t buf_ospf_ls_update[40] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x29, 0x22, 0x01, 0x01, 0x01,
									  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00, 0x00, 0x01,
									  0xbf, 0x62, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0xc0, 0xa8,
									  0x0d, 0x00, 0xff, 0xff, 0xff, 0x00, 0x03, 0x00, 0x2b, 0x67};
	libtrace_ospf_ls_update_t *ls_update = (libtrace_ospf_ls_update_t *)buf_ospf_ls_update;
	assert(ntohl(ls_update->ls_num_adv) == 1);
	/* todo: use api functions to test rest of ls_update */


	/*uint8_t buf_8021q[4] = {0x20, 0x00, 0x00, 0x00};
	assert(((libtrace_8021q_t *) buf_8021q)->vlan_pri == 1);
	assert(((libtrace_8021q_t *) buf_8021q)->vlan_cfi == 0);
	assert(ntohs(((libtrace_8021q_t *) buf_8021q)->vlan_id) == 0);

	buf_8021q[0] = 0x10;
	assert(((libtrace_8021q_t *) buf_8021q)->vlan_pri == 0);
	assert(((libtrace_8021q_t *) buf_8021q)->vlan_cfi == 1);
	assert(ntohs(((libtrace_8021q_t *) buf_8021q)->vlan_id) == 0);
	
	buf_8021q[0] = 0x00;
	buf_8021q[1] = 0x01;
	assert(((libtrace_8021q_t *) buf_8021q)->vlan_pri == 0);
	assert(((libtrace_8021q_t *) buf_8021q)->vlan_cfi == 0);
	assert(((libtrace_8021q_t *) buf_8021q)->vlan_id == 1);
	
	buf_8021q[0] = 0x02;
	buf_8021q[1] = 0x01;
	assert(((libtrace_8021q_t *) buf_8021q)->vlan_pri == 0);
	assert(((libtrace_8021q_t *) buf_8021q)->vlan_cfi == 0);
	assert(((libtrace_8021q_t *) buf_8021q)->vlan_id == 0x0201);*/
}
