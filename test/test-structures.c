#include "libtrace.h"
#include <inttypes.h>
#include "lt_bswap.h"

/*
 * Structures:
 * libtrace_ether_t                     done
 * libtrace_ip_t                        done
 * libtrace_ip6_t                       done
 * libtrace_ip6_frag_t                  done
 * libtrace_ip6_ext_t                   done
 * libtrace_tcp_t                       done
 * libtrace_udp_t                       done
 * libtrace_icmp_t                      done
 * libtrace_icmp6_t                     done
 * libtrace_llcsnap_t                   done
 * libtrace_8021q_t                     done
 * libtrace_atm_cell_t                  done
 * libtrace_atm_nni_cell_t              done
 * libtrace_atm_capture_cell_t          done
 * libtrace_atm_nni_capture_cell_t      done
 * libtrace_ppp_t                       done
 * libtrace_pppoe_t                     done
 * libtrace_gre_t                       done
 * libtrace_vxlan_t                     done
 * libtrace_80211_t                     done
 * libtrace_radiotap_t                  done
 * libtrace_ospf_v2_t                   done
 * libtrace_ospf_options_t              done
 * libtrace_ospf_lsa_v2_t               done
 * libtrace_ospf_hello_v2_t             done
 * libtrace_ospf_db_desc_v2_t           done
 * libtrace_ospf_ls_req_t               done
 * libtrace_ospf_ls_update_t            done
 * libtrace_ospf_as_external_lsa_v2_t   done
 * libtrace_ospf_summary_lsa_v2_t       done
 * libtrace_ospf_network_lsa_v2_t       done
 * libtrace_ospf_link_v2_t              done
 * libtrace_ospf_router_lsa_v2_t        done
 * libtrace_sll_header_t                done
 */

bool tests_passed = true;

void test(bool pass, char *test)
{
    if (!pass) {
        fprintf(stderr, "failed: %s\n", test);
        tests_passed = false;
    }
}

void check_eth()
{
    uint8_t buf_eth[14] = {0x00, 0x02, 0x6f, 0x21, 0xec, 0x5f, 0x00,
                           0x02, 0x6f, 0x21, 0xec, 0x52, 0x88, 0x8e};
    libtrace_ether_t *eth = (libtrace_ether_t *)buf_eth;
    for (int i = 0; i < 6; i++) {
        test(eth->ether_dhost[i] == buf_eth[i], "check_eth - ether_dhost");
        test(eth->ether_shost[i] == buf_eth[i + 6], "check_eth - ether_shost");
    }
    test(ntohs(eth->ether_type) == TRACE_ETHERTYPE_8021X,
         "check_eth - ether_type");
}

void check_ip4()
{
    uint8_t buf_ip4[20] = {0x45, 0x00, 0x05, 0x8c, 0x74, 0x9f, 0x40,
                           0x00, 0x31, 0x06, 0x00, 0x00, 0x82, 0xcb,
                           0xed, 0xc5, 0x61, 0x59, 0x5b, 0x9f};
    libtrace_ip_t *ip4 = (libtrace_ip_t *)buf_ip4;
    test(ip4->ip_v == 4, "check_ip4 - ip_v");
    test(ip4->ip_hl == 5, "check_ip4 - ip_hl");
    test(ip4->ip_tos == 0, "check_ip4 - ip_tos");
    test(ntohs(ip4->ip_len) == 1420, "check_ip4 - ip_len");
    test(ntohs(ip4->ip_id) == 29855, "check_ip4 - ip_id");
    test(ntohs(ip4->ip_off) == 16384, "check_ip4 - ip_off");
    test(ip4->ip_ttl == 49, "check_ip4 - ip_ttl");
    test(ip4->ip_p == TRACE_IPPROTO_TCP, "check_ip4 - ip_p");
    test(ntohs(ip4->ip_sum) == 0, "check_ip4 - ip_sum");
    test(ntohl(ip4->ip_src.s_addr) == 2194402757, "check_ip4 - ip_src");
    test(ntohl(ip4->ip_dst.s_addr) == 1633246111, "ip_dst");
    // set/check bitfields
    buf_ip4[0] = 0xdc;
    test(ip4->ip_hl == 12, "check_ip4 - ip_hl");
    buf_ip4[0] = 0xdc;
    test(ip4->ip_v == 13, "check_ip4 - ip_v");
    // set/check values
    buf_ip4[1] = 0xce;
    test(ip4->ip_tos == 206, "check_ip4 - ip_tos");
    buf_ip4[2] = 0x01;
    buf_ip4[3] = 0x02;
    test(ntohs(ip4->ip_len) == 258, "check_ip4 - ip_len");
    buf_ip4[4] = 0x03;
    buf_ip4[5] = 0x04;
    test(ntohs(ip4->ip_id) == 772, "check_ip4 - ip_id");
    buf_ip4[6] = 0x05;
    buf_ip4[7] = 0x06;
    test(ntohs(ip4->ip_off) == 1286, "check_ip4 - ip_off");
    buf_ip4[8] = 0x07;
    test(ip4->ip_ttl == 7, "check_ip4 - ip_ttl");
    buf_ip4[9] = 0x08;
    test(ip4->ip_p == 8, "check_ip4 - ip_p");
    buf_ip4[10] = 0x09;
    buf_ip4[11] = 0x0a;
    test(ntohs(ip4->ip_sum) == 2314, "check_ip4 - ip_sum");

    buf_ip4[12] = 0x0b;
    buf_ip4[13] = 0x0c;
    buf_ip4[14] = 0x0d;
    buf_ip4[15] = 0x0e;
    test(ntohl(ip4->ip_src.s_addr) == 185339150, "check_ip4 - ip_src");

    buf_ip4[16] = 0x10;
    buf_ip4[17] = 0x11;
    buf_ip4[18] = 0x12;
    buf_ip4[19] = 0x13;
    test(ntohl(ip4->ip_dst.s_addr) == 269554195, "check_ip4 - ip_dst");
}

void check_ip6()
{
    uint8_t buf_ip6[40] = {0x60, 0x00, 0x00, 0x00, 0x00, 0x54, 0x11, 0xff,
                           0x26, 0x07, 0xf2, 0xc0, 0xf0, 0x0f, 0xb0, 0x01,
                           0x00, 0x00, 0x00, 0x00, 0xfa, 0xce, 0xb0, 0x0c,
                           0x20, 0x01, 0x04, 0xf8, 0x00, 0x03, 0x00, 0x0d,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61};
    libtrace_ip6_t *ip6 = (libtrace_ip6_t *)buf_ip6;
    test(ntohl(ip6->flow) == 1610612736, "check_ip6 - flow");
    test(ntohs(ip6->plen) == 84, "check_ip6 - plen");
    test(ip6->nxt == TRACE_IPPROTO_UDP, "check_ip6 - nxt");
    test(ip6->hlim == 255, "check_ip6 - hlim");
    for (int i = 0; i < 16; i++) {
        test(ip6->ip_src.s6_addr[i] == buf_ip6[i + 8], "check_ip6 - ip_src");
        test(ip6->ip_dst.s6_addr[i] == buf_ip6[i + 24], "check_ip6 - ip_dst");
    }
    // set/check values
    buf_ip6[0] = 0x01;
    buf_ip6[1] = 0x02;
    buf_ip6[2] = 0x03;
    buf_ip6[3] = 0x04;
    test(ntohl(ip6->flow) == 16909060, "check_ip6 - flow");

    buf_ip6[4] = 0x05;
    buf_ip6[5] = 0x06;
    test(ntohs(ip6->plen) == 1286, "check_ip6 - plen");
    buf_ip6[6] = 0x07;
    test(ip6->nxt == 7, "check_ip6 - nxt");
    buf_ip6[7] = 0x08;
    test(ip6->hlim == 8, "check_ip6 - hlim");
}

void check_ip6_frag()
{
    uint8_t buf_ip6_frag[8] = {0x11, 0x00, 0x00, 0x01, 0xf8, 0x8e, 0xb4, 0x66};
    libtrace_ip6_frag_t *ip6_frag = (libtrace_ip6_frag_t *)buf_ip6_frag;
    test(ip6_frag->nxt == 17, "check_ip6_frag - nxt");
    test(ip6_frag->res == 0, "check_ip6_frag - res");
    test(ntohs(ip6_frag->frag_off) == 1, "check_ip6_frag - frag_off");
    test(ntohl(ip6_frag->ident) == 4170101862, "check_ip6_frag - ident");
    // set/check values
    buf_ip6_frag[0] = 0x01;
    test(ip6_frag->nxt == 1, "check_ip6_frag - nxt");
    buf_ip6_frag[1] = 0x02;
    test(ip6_frag->res == 2, "check_ip6_frag - res");

    buf_ip6_frag[2] = 0x03;
    buf_ip6_frag[3] = 0x04;
    test(ntohs(ip6_frag->frag_off) == 772, "check_ip6_frag - frag_off");

    buf_ip6_frag[4] = 0x05;
    buf_ip6_frag[5] = 0x06;
    buf_ip6_frag[6] = 0x07;
    buf_ip6_frag[7] = 0x08;
    test(ntohl(ip6_frag->ident) == 84281096, "check_ip6_frag - ident");
}

void check_ip6_ext()
{
    uint8_t buf_ip6_ext[24] = {0x59, 0x04};
    libtrace_ip6_ext_t *ip6_ext = (libtrace_ip6_ext_t *)buf_ip6_ext;
    test(ip6_ext->nxt == 89, "check_ip6_ext - nxt");
    test(ip6_ext->len == 4, "check_ip6_ext - len");
    // set/check values
    buf_ip6_ext[0] = 0x01;
    test(ip6_ext->nxt == 1, "check_ip6_ext - nxt");
    buf_ip6_ext[1] = 0x02;
    test(ip6_ext->len == 2, "check_ip6_ext - len");
}

void check_udp()
{
    uint8_t buf_udp[8] = {0x44, 0x5c, 0x44, 0x5c, 0x00, 0x90, 0xba, 0x03};
    libtrace_udp_t *udp = (libtrace_udp_t *)buf_udp;
    test(ntohs(udp->source) == 17500, "check_udp - source");
    test(ntohs(udp->dest) == 17500, "check_udp - dest");
    test(ntohs(udp->len) == 144, "check_udp - len");
    test(ntohs(udp->check) == 47619, "check_udp - check");
    // set/check values
    buf_udp[0] = 0x01;
    buf_udp[1] = 0x02;
    test(ntohs(udp->source) == 258, "check_udp - source");
    buf_udp[2] = 0x03;
    buf_udp[3] = 0x04;
    test(ntohs(udp->dest) == 772, "check_udp - dest");
    buf_udp[4] = 0x05;
    buf_udp[5] = 0x06;
    test(ntohs(udp->len) == 1286, "check_udp - len");
    buf_udp[6] = 0x07;
    buf_udp[7] = 0x08;
    test(ntohs(udp->check) == 1800, "check_udp - check");
}

void check_tcp()
{
    uint8_t buf_tcp[20] = {0x06, 0xe0, 0x00, 0x19, 0x79, 0x43, 0xd3,
                           0xbb, 0x88, 0xa4, 0x36, 0xd2, 0x50, 0x18,
                           0xfe, 0x0a, 0xc3, 0xfc, 0x00, 0x00};
    libtrace_tcp_t *tcp = (libtrace_tcp_t *)buf_tcp;
    test(ntohs(tcp->source) == 1760, "check_tcp - source");
    test(ntohs(tcp->dest) == 25, "check_tcp - dest");
    test(ntohl(tcp->seq) == 2034488251, "check_tcp - seq");
    test(ntohl(tcp->ack_seq) == 2292463314, "check_tcp - ack_seq");
    test(tcp->doff == 5, "check_tcp - doff");
    test(tcp->res1 == 0, "check_tcp - res1");
    test(tcp->ecn_ns == 0, "check_tcp - ecn_ns");
    test(tcp->cwr == 0, "check_tcp - cwr");
    test(tcp->ece == 0, "check_tcp - ece");
    test(tcp->urg == 0, "check_tcp - urg");
    test(tcp->ack == 1, "check_tcp - ack");
    test(tcp->psh == 1, "check_tcp - psh");
    test(tcp->rst == 0, "check_tcp - rst");
    test(tcp->syn == 0, "check_tcp - syn");
    test(tcp->fin == 0, "check_tcp - fin");
    test(ntohs(tcp->window) == 65034, "check_tcp - window");
    test(ntohs(tcp->check) == 50172, "check_tcp - check");
    test(ntohs(tcp->urg_ptr) == 0, "check_tcp - urg_ptr");
    // check bitfields
    buf_tcp[12] = 0xf0;
    test(tcp->doff == 15, "check_tcp - doff");
    buf_tcp[12] = 0x0e;
    test(tcp->res1 == 7, "check_tcp - res1");
    buf_tcp[12] = 0x01;
    test(tcp->ecn_ns == 1, "check_tcp - ecn_ns");
    buf_tcp[13] = 0x80;
    test(tcp->cwr == 1, "check_tcp - cwr");
    buf_tcp[13] = 0x40;
    test(tcp->ece == 1, "check_tcp - ece");
    buf_tcp[13] = 0x20;
    test(tcp->urg == 1, "check_tcp - urg");
    buf_tcp[13] = 0x10;
    test(tcp->ack == 1, "check_tcp - ack");
    buf_tcp[13] = 0x08;
    test(tcp->psh == 1, "check_tcp - psh");
    buf_tcp[13] = 0x04;
    test(tcp->rst == 1, "check_tcp - rst");
    buf_tcp[13] = 0x02;
    test(tcp->syn == 1, "check_tcp - syn");
    buf_tcp[13] = 0x01;
    test(tcp->fin == 1, "check_tcp - fin");
    // set/check values
    buf_tcp[0] = 0x01;
    buf_tcp[1] = 0x02;
    test(ntohs(tcp->source) == 258, "check_tcp - source");
    buf_tcp[2] = 0x02;
    buf_tcp[3] = 0x03;
    test(ntohs(tcp->dest) == 515, "check_tcp - dest");

    buf_tcp[4] = 0x04;
    buf_tcp[5] = 0x05;
    buf_tcp[6] = 0x06;
    buf_tcp[7] = 0x07;
    test(ntohl(tcp->seq) == 67438087, "check_tcp - seq");

    buf_tcp[8] = 0x08;
    buf_tcp[9] = 0x09;
    buf_tcp[10] = 0x0a;
    buf_tcp[11] = 0x0b;
    test(ntohl(tcp->ack_seq) == 134810123, "check_tcp - ack_seq");

    buf_tcp[14] = 0x0c;
    buf_tcp[15] = 0x0d;
    test(ntohs(tcp->window) == 3085, "check_tcp - window");
    buf_tcp[16] = 0x0e;
    buf_tcp[17] = 0x0f;
    test(ntohs(tcp->check) == 3599, "check_tcp - check");
    buf_tcp[18] = 0x10;
    buf_tcp[19] = 0x11;
    test(ntohs(tcp->urg_ptr) == 4113, "check_tcp - urg_ptr");
}

void check_icmp()
{
    uint8_t buf_icmp_req[8] = {0x08, 0x00, 0x87, 0x40, 0x70, 0xbf, 0x00, 0x00};
    libtrace_icmp_t *icmp_req = (libtrace_icmp_t *)buf_icmp_req;
    test(icmp_req->type == 8, "check_icmp - type"); // echo (ping) request
    test(icmp_req->code == 0, "check_icmp - code");
    test(ntohs(icmp_req->checksum) == 34624, "check_icmp - checksum");
    test(ntohs(icmp_req->un.echo.id) == 28863, "check_icmp - un.echo.id");
    test(ntohs(icmp_req->un.echo.sequence) == 0,
         "check_icmp - un.echo.sequence");
    // set/check values
    buf_icmp_req[0] = 0x01;
    test(icmp_req->type == 1, "check_icmp - type");
    buf_icmp_req[1] = 0x02;
    test(icmp_req->code == 2, "check_icmp - code");
    buf_icmp_req[2] = 0x03;
    buf_icmp_req[3] = 0x04;
    test(ntohs(icmp_req->checksum) == 772, "check_icmp - checksum");
    buf_icmp_req[4] = 0x05;
    buf_icmp_req[5] = 0x06;
    test(ntohs(icmp_req->un.echo.id) == 1286, "check_icmp - un.echo.id");
    buf_icmp_req[6] = 0x07;
    buf_icmp_req[7] = 0x08;
    test(ntohs(icmp_req->un.echo.sequence) == 1800,
         "check_icmp - un.echo.sequence");
}

void check_icmp6()
{
    uint8_t buf_icmp6[8] = {0x80, 0x00, 0x86, 0x3c, 0x11, 0x0d, 0x00, 0x00};
    libtrace_icmp6_t *icmp6 = (libtrace_icmp6_t *)buf_icmp6;
    test(icmp6->type == 128, "check_icmp6 - type");
    test(icmp6->code == 0, "check_icmp6 - code");
    test(ntohs(icmp6->checksum) == 34364, "check_icmp6 - checksum");
    test(ntohs(icmp6->un.echo.id) == 4365, "check_icmp6 - un.echo.id");
    test(ntohs(icmp6->un.echo.sequence) == 0, "check_icmp6 - un.echo.sequence");
    // set/check values
    buf_icmp6[0] = 0x01;
    test(icmp6->type == 1, "check_icmp6 - type");
    buf_icmp6[1] = 0x02;
    test(icmp6->code == 2, "check_icmp6 - code");
    buf_icmp6[2] = 0x03;
    buf_icmp6[3] = 0x04;
    test(ntohs(icmp6->checksum) == 772, "check_icmp6 - checksum");
    buf_icmp6[4] = 0x05;
    buf_icmp6[5] = 0x06;
    test(ntohs(icmp6->un.echo.id) == 1286, "check_icmp6 - un.echo.id");
    buf_icmp6[6] = 0x07;
    buf_icmp6[7] = 0x08;
    test(ntohs(icmp6->un.echo.sequence) == 1800,
         "check_icmp6 - un.echo.sequence");
}

#if __BYTE_ORDER == __BIG_ENDIAN
#    define bswap_be_to_host24(num) (num)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#    define bswap_be_to_host24(num) bswap_be_to_host32(num << 8)
#endif

void check_llcsnap()
{
    uint8_t buf_llcsnap[8] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00};
    libtrace_llcsnap_t *llcsnap = (libtrace_llcsnap_t *)buf_llcsnap;
    test(llcsnap->dsap == 170, "check_llcsnap - dsap");
    test(llcsnap->ssap == 170, "check_llcsnap - ssap");
    test(llcsnap->control == 3, "check_llcsnap - control");
    test(bswap_be_to_host24(llcsnap->oui) == 12, "check_llcsnap - oui");
    // set/check values
    buf_llcsnap[0] = 0x01;
    test(llcsnap->dsap == 0x01, "check_llcsnap - dsap");
    buf_llcsnap[1] = 0x02;
    test(llcsnap->ssap == 0x02, "check_llcsnap - ssap");
    buf_llcsnap[2] = 0x03;
    test(llcsnap->control == 0x03, "check_llcsnap - control");

    buf_llcsnap[3] = 0x04;
    buf_llcsnap[4] = 0x05;
    buf_llcsnap[5] = 0x06;
    test(bswap_be_to_host24(llcsnap->oui) == 263430, "check_llcsnap - oui");

    buf_llcsnap[6] = 0x07;
    buf_llcsnap[7] = 0x08;
    test(ntohs(llcsnap->type) == 1800, "check_llcsnap - type");
}

void check_8021q()
{
    uint8_t buf[4] = {0x00, 0x64, 0x86, 0xdd};
    libtrace_8021q_t *vlan = (libtrace_8021q_t *)buf;
    test(LT_VLAN_PCP(vlan) == 0, "check_8021q - pcp");
    test(LT_VLAN_DEI(vlan) == 0, "check_8021q - dei");
    test(LT_VLAN_VID(vlan) == 100, "check_8021q - vid");
    // set/check values
    buf[0] = 0xe0;
    test(LT_VLAN_PCP(vlan) == 7, "check_8021q - pcp");
    buf[0] = 0x10;
    test(LT_VLAN_DEI(vlan) == 1, "check_8021q - dei");
    buf[0] = 0x02;
    buf[1] = 0xff;
    test(LT_VLAN_VID(vlan) == 767, "check_8021q - vid");
}

void check_atm_cell()
{
    uint8_t buf[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    libtrace_atm_cell_t *atm = (libtrace_atm_cell_t *)buf;
    test(LT_ATM_GFC(atm) == 0, "check_atm_cell - gfc");
    test(LT_ATM_VPI(atm) == 16, "check_atm_cell - vpi");
    test(LT_ATM_VCI(atm) == 8240, "check_atm_cell - vci");
    test(LT_ATM_PT(atm) == 2, "check_atm_cell - pt");
    test(LT_ATM_CLP(atm) == 0, "check_atm_cell - clp");
    test(atm->hec == 5, "check_atm_cell - hec");
}

void check_atm_nni_cell()
{
    uint8_t buf[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    libtrace_atm_nni_cell_t *atm = (libtrace_atm_nni_cell_t *)buf;
    test(LT_ATM_NNI_VPI(atm) == 16, "check_atm_nni - vpi");
    test(LT_ATM_NNI_VCI(atm) == 8240, "check_atm_nni - vci");
    test(LT_ATM_NNI_PT(atm) == 2, "check_atm_nni - pt");
    test(LT_ATM_NNI_CLP(atm) == 0, "check_atm_nni - clp");
    test(atm->hec == 5, "check_atm_nni - hec");
}

void check_atm_capture_cell()
{
    uint8_t buf[4] = {0x01, 0x02, 0x03, 0x04};
    libtrace_atm_capture_cell_t *atm = (libtrace_atm_capture_cell_t *)buf;
    test(LT_ATM_GFC(atm) == 0, "check_atm_capture_cell - gfc");
    test(LT_ATM_VPI(atm) == 16, "check_atm_capture_cell - vpi");
    test(LT_ATM_VCI(atm) == 8240, "check_atm_capture_cell - vci");
    test(LT_ATM_PT(atm) == 2, "check_atm_capture_cell - pt");
    test(LT_ATM_CLP(atm) == 0, "check_atm_capture_cell - clp");
}

void check_atm_nni_capture_cell()
{
    uint8_t buf[4] = {0x01, 0x02, 0x03, 0x04};
    libtrace_atm_nni_capture_cell_t *atm =
        (libtrace_atm_nni_capture_cell_t *)buf;
    test(LT_ATM_NNI_VPI(atm) == 16, "check_atm_nni_capture_cell - vpi");
    test(LT_ATM_NNI_VCI(atm) == 8240, "check_atm_nni_capture_cell - vci");
    test(LT_ATM_NNI_PT(atm) == 2, "check_atm_nni_capture_cell - pt");
    test(LT_ATM_NNI_CLP(atm) == 0, "check_atm_nni_capture_cell - clp");
}

void check_ppp()
{
    uint8_t buf[2] = {0x01, 0x02};
    libtrace_ppp_t *ppp = (libtrace_ppp_t *)buf;
    test(ntohs(ppp->protocol) == 258, "check_ppp - protocol");
}

void check_pppoe()
{
    uint8_t buf_pppoe[10] = {0x11, 0x09, 0x00, 0x00, 0x00,
                             0x04, 0x01, 0x01, 0x00, 0x00};
    libtrace_pppoe_t *pppoe = (libtrace_pppoe_t *)buf_pppoe;
    test(pppoe->version == 1, "check_pppoe - version");
    test(pppoe->type == 1, "check_pppoe - type");
    test(pppoe->code == 9, "check_pppoe - code");
    test(ntohs(pppoe->session_id) == 0, "check_pppoe - session_id");
    test(ntohs(pppoe->length) == 4, "check_pppoe - length");
    // check bitfields
    buf_pppoe[0] = 0x12;
    test(pppoe->version == 1, "check_pppoe - version");
    buf_pppoe[0] = 0x12;
    test(pppoe->type == 2, "check_pppoe - type");
    // set/check values
    buf_pppoe[1] = 0x03;
    test(pppoe->code == 3, "check_pppoe - code");
    buf_pppoe[2] = 0x04;
    buf_pppoe[3] = 0x05;
    test(ntohs(pppoe->session_id) == 1029, "check_pppoe - session_id");
    buf_pppoe[4] = 0x06;
    buf_pppoe[5] = 0x07;
    test(ntohs(pppoe->length) == 1543, "check_pppoe - length");
}

void check_gre()
{
    uint8_t buf[12] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                       0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    libtrace_gre_t *gre = (libtrace_gre_t *)buf;
    test(ntohs(gre->flags) == 258, "check_gre - flags");
    test(ntohs(gre->ethertype) == 772, "check_gre - ethertype");
    test(ntohs(gre->checksum) == 1286, "check_gre - checksum");
    test(ntohs(gre->reserved1) == 1800, "check_gre - reserved1");
    test(ntohs(gre->key) == 2314, "check_gre - key");
    test(ntohs(gre->seq) == 2828, "check_gre - seq");
}

void check_vxlan()
{
    uint8_t buf_vxlan[8] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x00};
    libtrace_vxlan_t *vxlan = (libtrace_vxlan_t *)buf_vxlan;
    test(vxlan->flags == 8, "check_vxlan - flags");
    test(vxlan->reserved1[0] == 0, "check_vxlan - reserved1[0]");
    test(vxlan->reserved1[1] == 0, "check_vxlan - reserved1[1]");
    test(vxlan->reserved1[2] == 0, "check_vxlan - reserved1[2]");
    uint32_t vni = vxlan->vni[0] << 16 | vxlan->vni[1] << 8 | vxlan->vni[2];
    test(vni == 123, "check_vxlan - vni");
    test(vxlan->reserved2 == 0, "check_vxlan - reserved2");
    // set/check values
    buf_vxlan[0] = 0x01;
    test(vxlan->flags == 1, "check_vxlan - flags");
    buf_vxlan[1] = 0x02;
    test(vxlan->reserved1[0] == 2, "check_vxlan - reserved1[0]");
    buf_vxlan[2] = 0x03;
    test(vxlan->reserved1[1] == 3, "check_vxlan - reserved1[1]");
    buf_vxlan[3] = 0x04;
    test(vxlan->reserved1[2] == 4, "check_vxlan - reserved1[2]");
    buf_vxlan[4] = 0x05;
    test(vxlan->vni[0] == 5, "check_vxlan - vni[0]");
    buf_vxlan[5] = 0x06;
    test(vxlan->vni[1] == 6, "check_vxlan - vni[1]");
    buf_vxlan[6] = 0x07;
    test(vxlan->vni[2] == 7, "check_vxlan - vni[2]");
    buf_vxlan[7] = 0x08;
    test(vxlan->reserved2 == 8, "check_vxlan - reserved2");
}

void check_radiotap()
{
    uint8_t buf_radiotap[25] = {0x00, 0x00, 0x19, 0x00, 0x6f, 0x08, 0x00,
                                0x00, 0x04, 0x64, 0x90, 0x91, 0x00, 0x00,
                                0x00, 0x00, 0x10, 0x02, 0x9e, 0x09, 0x80,
                                0x04, 0xcc, 0xa5, 0x00};
    libtrace_radiotap_t *radio_tap = (libtrace_radiotap_t *)buf_radiotap;
    /* radiotap using little endian byte order */
    test(radio_tap->it_version == 0, "check_radiotap - it_version");
    test(radio_tap->it_pad == 0, "check_radiotap - it_pad");
    test(bswap_le_to_host16(radio_tap->it_len) == 25,
         "check_radiotap - it_len");
    test(bswap_le_to_host32(radio_tap->it_present) == 2159,
         "check_radiotap it_present");
    // set/check values
    buf_radiotap[0] = 0x01;
    test(radio_tap->it_version == 1, "check_radiotap - it_version");
    buf_radiotap[1] = 0x02;
    test(radio_tap->it_pad == 2, "check_radiotap - it_pad");
    buf_radiotap[2] = 0x03;
    buf_radiotap[3] = 0x04;
    test(bswap_le_to_host16(radio_tap->it_len) == 1027,
         "check_radiotap - it_len");

    buf_radiotap[4] = 0x05;
    buf_radiotap[5] = 0x06;
    buf_radiotap[6] = 0x07;
    buf_radiotap[7] = 0x08;
    test(bswap_le_to_host32(radio_tap->it_present) == 134678021,
         "check_radiotap - it_present");
}

void check_80211()
{
    uint8_t buf_80211[24] = {0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0x00, 0x16, 0xb6, 0xe3, 0xe9, 0x8f,
                             0x00, 0x16, 0xb6, 0xe3, 0xe9, 0x8f, 0x30, 0x95};
    libtrace_80211_t *radio = (libtrace_80211_t *)buf_80211;
    test(radio->protocol == 0, "check_80211 - protocol");
    test(radio->type == 0, "check_80211 - type");
    test(radio->subtype == 8, "check_80211 - subtype");
    test(radio->to_ds == 0, "check_80211 - to_ds");
    test(radio->from_ds == 0, "check_80211 - from_ds");
    test(radio->more_frag == 0, "check_80211 - more_frag");
    test(radio->retry == 0, "check_80211 - retry");
    test(radio->power == 0, "check_80211 - power");
    test(radio->more_data == 0, "check_80211 - more_data");
    test(radio->wep == 0, "check_80211 - wep");
    test(radio->order == 0, "check_80211 - order");
    test(ntohs(radio->duration) == 0, "check_80211 - duration");
    for (int i = 0; i < 6; i++) {
        test(radio->mac1[i] == buf_80211[i + 4], "check_80211 - mac1");
        test(radio->mac2[i] == buf_80211[i + 10], "check_80211 - mac2");
        test(radio->mac3[i] == buf_80211[i + 16], "check_80211 - mac3");
    }
    test(ntohs(radio->SeqCtl) == 12437, "check_80211 - SeqCtl");
    // check bitfields
    buf_80211[0] = 0x03;
    test(radio->protocol == 3, "check_80211 - protocol");
    buf_80211[0] = 0x0c;
    test(radio->type == 3, "check_80211 - type");
    buf_80211[0] = 0xf0;
    test(radio->subtype == 15, "check_80211 - subtype");
    buf_80211[1] = 0x01;
    test(radio->to_ds == 1, "check_80211 - to_ds");
    buf_80211[1] = 0x02;
    test(radio->from_ds == 1, "check_80211 - from_ds");
    buf_80211[1] = 0x04;
    test(radio->more_frag == 1, "check_80211 - more_frag");
    buf_80211[1] = 0x08;
    test(radio->retry == 1, "check_80211 - retry");
    buf_80211[1] = 0x10;
    test(radio->power == 1, "check_80211 - power");
    buf_80211[1] = 0x20;
    test(radio->more_data == 1, "check_80211 - more_data");
    buf_80211[1] = 0x40;
    test(radio->wep == 1, "check_80211 - wep");
    buf_80211[1] = 0x80;
    test(radio->order == 1, "check_80211 - order");
    // set/check values
    buf_80211[2] = 0x01;
    buf_80211[3] = 0x02;
    test(ntohs(radio->duration) == 258, "check_80211 - duration");
    buf_80211[22] = 0x03;
    buf_80211[23] = 0x04;
    test(ntohs(radio->SeqCtl) == 772, "check_80211 - SeqCtl");
}

void check_ospf_v2()
{
    uint8_t buf_ospf[32] = {0x02, 0x01, 0x00, 0x34, 0xc0, 0xa8, 0xff, 0x0f,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                            0x00, 0x00, 0x01, 0x10, 0x5a, 0x83, 0x41, 0x12};
    libtrace_ospf_v2_t *ospf_hdr = (libtrace_ospf_v2_t *)buf_ospf;
    test(ospf_hdr->ospf_v == 2, "check_ospf_v2 - ospf_v");
    test(ospf_hdr->type == TRACE_OSPF_HELLO, "check_ospf_v2 - type");
    test(ntohs(ospf_hdr->ospf_len) == 52, "check_ospf_v2 - ospf_len");
    test(ntohl(ospf_hdr->router.s_addr) == 3232300815,
         "check_ospf_v2 - router");
    test(ntohl(ospf_hdr->area.s_addr) == 0, "check_ospf_v2 - area");
    test(ntohs(ospf_hdr->sum) == 0, "check_ospf_v2 - sum");
    test(ntohs(ospf_hdr->au_type) == 2, "check_ospf_v2 - au_type");
    test(ntohs(ospf_hdr->zero) == 0, "check_ospf_v2 - zero");
    test(ospf_hdr->au_key_id == 1, "check_ospf_v2 - au_key_id");
    test(ospf_hdr->au_data_len == 16, "check_ospf_v2 - au_data_len");
    test(ntohl(ospf_hdr->au_seq_num) == 1518551314,
         "check_ospf_v2 - au_seq_num");
    // set/check values
    buf_ospf[0] = 0x01;
    test(ospf_hdr->ospf_v == 1, "check_ospf_v2 - ospf_v");
    buf_ospf[1] = 0x02;
    test(ospf_hdr->type == 2, "check_ospf_v2 - type");
    buf_ospf[2] = 0x03;
    buf_ospf[3] = 0x04;
    test(ntohs(ospf_hdr->ospf_len) == 772, "check_ospf_v2 - ospf_len");

    buf_ospf[4] = 0x05;
    buf_ospf[5] = 0x06;
    buf_ospf[6] = 0x07;
    buf_ospf[7] = 0x08;
    test(ntohl(ospf_hdr->router.s_addr) == 84281096, "check_ospf_v2 - router");

    buf_ospf[8] = 0x09;
    buf_ospf[9] = 0x0a;
    buf_ospf[10] = 0x0b;
    buf_ospf[11] = 0x0c;
    test(ntohl(ospf_hdr->area.s_addr) == 151653132, "check_ospf_v2 - area");

    buf_ospf[12] = 0x0d;
    buf_ospf[13] = 0x0e;
    test(ntohs(ospf_hdr->sum) == 3342, "check_ospf_v2 - sum");
    buf_ospf[14] = 0x0f;
    buf_ospf[15] = 0x10;
    test(ntohs(ospf_hdr->au_type) == 3856, "check_ospf_v2 - au_type");
    buf_ospf[16] = 0x11;
    buf_ospf[17] = 0x12;
    test(ntohs(ospf_hdr->zero) == 4370, "check_ospf_v2 - zero");
    buf_ospf[18] = 0x13;
    test(ospf_hdr->au_key_id == 19, "check_ospf_v2 - au_key_id");
    buf_ospf[19] = 0x14;
    test(ospf_hdr->au_data_len == 20, "check_ospf_v2 - au_data_len");

    buf_ospf[20] = 0x15;
    buf_ospf[21] = 0x16;
    buf_ospf[22] = 0x17;
    buf_ospf[23] = 0x18;
    test(ntohl(ospf_hdr->au_seq_num) == 353769240,
         "check_ospf_v2 - au_seq_num");
}

void check_ospf_options()
{
    uint8_t buf[1] = {0x01};
    libtrace_ospf_options_t *opts = (libtrace_ospf_options_t *)buf;
    // check bitfields
    buf[0] = 0x01;
    test(opts->unused1 == 1, "check_ospf_options - unused1");
    buf[0] = 0x02;
    test(opts->e_bit == 1, "check_ospf_options - e_bit");
    buf[0] = 0x04;
    test(opts->mc_bit == 1, "check_ospf_options - mc_bit");
    buf[0] = 0x08;
    test(opts->np_bit == 1, "check_ospf_options - np_bit");
    buf[0] = 0x10;
    test(opts->ea_bit == 1, "check_ospf_options - ea_bit");
    buf[0] = 0x20;
    test(opts->dc_bit == 1, "check_ospf_options - dc_bit");
    buf[0] = 0xc0;
    test(opts->unused2 == 3, "check_ospf_options - unused2");
}

void check_ospf_hello()
{
    uint8_t buf_ospf_hello[28] = {0xff, 0xff, 0xff, 0x00, 0x00, 0x0a, 0x12,
                                  0x01, 0x00, 0x00, 0x00, 0x28, 0xc0, 0xa8,
                                  0x79, 0x04, 0xc0, 0xa8, 0x79, 0x05};
    libtrace_ospf_hello_v2_t *ospf_hello =
        (libtrace_ospf_hello_v2_t *)buf_ospf_hello;
    test(ntohl(ospf_hello->mask.s_addr) == 4294967040,
         "check_ospf_hello - mask");
    test(ntohs(ospf_hello->interval) == 10, "check_ospf_hello - interval");
    libtrace_ospf_options_t *ospf_opts =
        (libtrace_ospf_options_t *)&ospf_hello->hello_options;
    test(ospf_opts->unused2 == 0, "check_ospf_hello - unused2");
    test(ospf_opts->dc_bit == 0, "check_ospf_hello - dc_bit");
    test(ospf_opts->ea_bit == 1, "check_ospf_hello - ea_bit");
    test(ospf_opts->np_bit == 0, "check_ospf_hello - np_bit");
    test(ospf_opts->mc_bit == 0, "check_ospf_hello - mc_bit");
    test(ospf_opts->e_bit == 1, "check_ospf_hello - e_bit");
    test(ospf_opts->unused1 == 0, "check_ospf_hello - unused");
    test(ospf_hello->priority == 1, "check_ospf_hello - priority");
    test(ntohl(ospf_hello->deadint) == 40, "check_ospf_hello - deadint");
    test(ntohl(ospf_hello->designated.s_addr) == 3232266500,
         "check_ospf_hello - designated");
    test(ntohl(ospf_hello->backup.s_addr) == 3232266501,
         "check_ospf_hello - backup");
    // check bitfields
    buf_ospf_hello[6] = 0x01;
    test(ospf_opts->unused1 == 1, "check_ospf_hello - unused1");
    buf_ospf_hello[6] = 0x02;
    test(ospf_opts->e_bit == 1, "check_ospf_hello - e_bit");
    buf_ospf_hello[6] = 0x04;
    test(ospf_opts->mc_bit == 1, "check_ospf_hello - mc_bit");
    buf_ospf_hello[6] = 0x08;
    test(ospf_opts->np_bit == 1, "check_ospf_hello - np_bit");
    buf_ospf_hello[6] = 0x10;
    test(ospf_opts->ea_bit == 1, "check_ospf_hello - ea_bit");
    buf_ospf_hello[6] = 0x20;
    test(ospf_opts->dc_bit == 1, "check_ospf_hello - dc_bit");
    buf_ospf_hello[6] = 0xc0;
    test(ospf_opts->unused2 == 3, "check_ospf_hello - unused2");
    // set/check values
    buf_ospf_hello[0] = 0x01;
    buf_ospf_hello[1] = 0x02;
    buf_ospf_hello[2] = 0x03;
    buf_ospf_hello[3] = 0x04;
    test(ntohl(ospf_hello->mask.s_addr) == 16909060, "check_ospf_hello - mask");

    buf_ospf_hello[4] = 0x05;
    buf_ospf_hello[5] = 0x06;
    test(ntohs(ospf_hello->interval) == 1286, "check_ospf_hello - interval");

    buf_ospf_hello[7] = 0x07;
    test(ospf_hello->priority == 7, "check_ospf_hello - priority");

    buf_ospf_hello[8] = 0x08;
    buf_ospf_hello[9] = 0x09;
    buf_ospf_hello[10] = 0x0a;
    buf_ospf_hello[11] = 0x0b;
    test(ntohl(ospf_hello->deadint) == 134810123, "check_ospf_hello - deadint");

    buf_ospf_hello[12] = 0x0c;
    buf_ospf_hello[13] = 0x0d;
    buf_ospf_hello[14] = 0x0e;
    buf_ospf_hello[15] = 0x0f;
    test(ntohl(ospf_hello->designated.s_addr) == 202182159,
         "check_ospf_hello - designated");

    buf_ospf_hello[16] = 0x10;
    buf_ospf_hello[17] = 0x11;
    buf_ospf_hello[18] = 0x12;
    buf_ospf_hello[19] = 0x13;
    test(ntohl(ospf_hello->backup.s_addr) == 269554195,
         "check_ospf_hello - backup");
}

void check_ospf_db_desc()
{
    uint8_t buf_ospf_db[8] = {0x05, 0xc4, 0x52, 0x07, 0x00, 0x00, 0x24, 0x8a};
    libtrace_ospf_db_desc_v2_t *ospf_db =
        (libtrace_ospf_db_desc_v2_t *)buf_ospf_db;
    test(ntohs(ospf_db->mtu) == 1476, "check_ospf_db_desc - mtu");
    test(*(uint8_t *)&ospf_db->db_desc_options == 82,
         "check_ospf_db_desc - db_desc-options");
    test(ospf_db->zero == 0, "check_ospf_db_desc - zero");
    test(ospf_db->db_desc_i == 1, "check_ospf_db_desc - db_desc_i");
    test(ospf_db->db_desc_m == 1, "check_ospf_db_desc - db_desc_m");
    test(ospf_db->db_desc_ms == 1, "check_ospf_db_desc - db_desc_ms");
    test(ntohl(ospf_db->seq) == 9354, "check_ospf_db_desc - seq");
    // check bitfields
    buf_ospf_db[2] = 0x02;
    test(ospf_db->db_desc_options.e_bit == 1, "check_ospf_db_desc - e_bit");
    buf_ospf_db[2] = 0x04;
    test(ospf_db->db_desc_options.mc_bit == 1, "check_ospf_db_desc - mc_bit");
    buf_ospf_db[2] = 0x08;
    test(ospf_db->db_desc_options.np_bit == 1, "check_ospf_db_desc - np_bit");
    buf_ospf_db[2] = 0x10;
    test(ospf_db->db_desc_options.ea_bit == 1, "check_ospf_db_desc - ea_bit");
    buf_ospf_db[2] = 0x20;
    test(ospf_db->db_desc_options.dc_bit == 1, "check_ospf_db_desc - dc_bit");
    buf_ospf_db[3] = 0x01;
    test(ospf_db->db_desc_ms == 1, "check_ospf_db_desc - db_desc_ms");
    buf_ospf_db[3] = 0x02;
    test(ospf_db->db_desc_m == 1, "check_ospf_db_desc - db_desc_m");
    buf_ospf_db[3] = 0x04;
    test(ospf_db->db_desc_i == 1, "check_ospf_db_desc - db_desc_i");
    buf_ospf_db[3] = 0xf8;
    test(ospf_db->zero == 31, "check_ospf_db_desc - zerp");
    // set/check values
    buf_ospf_db[0] = 0x01;
    buf_ospf_db[1] = 0x02;
    test(ntohs(ospf_db->mtu) == 258, "check_ospf_db_desc - mtu");

    buf_ospf_db[4] = 0x03;
    buf_ospf_db[5] = 0x04;
    buf_ospf_db[6] = 0x05;
    buf_ospf_db[7] = 0x06;
    test(ntohl(ospf_db->seq) == 50595078, "check_ospf_db_desc - seq");
}

void check_ospf_lsa_v2()
{
    uint8_t buf_ospf_lsa[20] = {0x00, 0x28, 0x22, 0x01, 0x01, 0x01, 0x01,
                                0x01, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
                                0x00, 0x01, 0xbf, 0x62, 0x00, 0x24};
    libtrace_ospf_lsa_v2_t *ospf_lsa = (libtrace_ospf_lsa_v2_t *)buf_ospf_lsa;
    test(ntohs(ospf_lsa->age) == 40, "check_ospf_lsa_v2 - age");
    test(*(uint8_t *)&ospf_lsa->lsa_options == 34,
         "check_ospf_lsa_v2 - lsa_options");
    test(ospf_lsa->lsa_type == TRACE_OSPF_LS_ROUTER,
         "check_ospf_lsa_v2 - lsa_type");
    test(ntohl(ospf_lsa->ls_id.s_addr) == 16843009,
         "check_ospf_lsa_v2 - ls_id");
    test(ntohl(ospf_lsa->adv_router.s_addr) == 16843009,
         "check_ospf_lsa_v2 - adv_router");
    test(ntohl(ospf_lsa->seq) == 2147483649, "check_ospf_lsa_v2 - seq");
    test(ntohs(ospf_lsa->checksum) == 48994, "check_ospf_lsa_v2 - checksum");
    test(ntohs(ospf_lsa->length) == 36, "check_ospf_lsa_v2 - length");
    // check bitfields
    buf_ospf_lsa[2] = 0x02;
    test(ospf_lsa->lsa_options.e_bit == 1, "check_ospf_lsa_v2 - e_bit");
    buf_ospf_lsa[2] = 0x04;
    test(ospf_lsa->lsa_options.mc_bit == 1, "check_ospf_lsa_v2 - mc_bit");
    buf_ospf_lsa[2] = 0x08;
    test(ospf_lsa->lsa_options.np_bit == 1, "check_ospf_lsa_v2 - np_bit");
    buf_ospf_lsa[2] = 0x10;
    test(ospf_lsa->lsa_options.ea_bit == 1, "check_ospf_lsa_v2 - ea_bit");
    buf_ospf_lsa[2] = 0x20;
    test(ospf_lsa->lsa_options.dc_bit == 1, "check_ospf_lsa_v2 - dc_bit");
    // set/check values
    buf_ospf_lsa[0] = 0x01;
    buf_ospf_lsa[1] = 0x02;
    test(ntohs(ospf_lsa->age) == 258, "check_ospf_lsa_v2 - age");
    buf_ospf_lsa[3] = 0x03;
    test(ospf_lsa->lsa_type == 3, "check_ospf_lsa_v2 - lsa_type");

    buf_ospf_lsa[4] = 0x04;
    buf_ospf_lsa[5] = 0x05;
    buf_ospf_lsa[6] = 0x06;
    buf_ospf_lsa[7] = 0x07;
    test(ntohl(ospf_lsa->ls_id.s_addr) == 67438087,
         "check_ospf_lsa_v2 - ls_id");

    buf_ospf_lsa[8] = 0x08;
    buf_ospf_lsa[9] = 0x09;
    buf_ospf_lsa[10] = 0x0a;
    buf_ospf_lsa[11] = 0x0b;
    test(ntohl(ospf_lsa->adv_router.s_addr) == 134810123,
         "check_ospf_lsa_v2 - adv_router");

    buf_ospf_lsa[12] = 0x0c;
    buf_ospf_lsa[13] = 0x0d;
    buf_ospf_lsa[14] = 0x0e;
    buf_ospf_lsa[15] = 0x0f;
    test(ntohl(ospf_lsa->seq) == 202182159, "check_ospf_lsa_v2 - seq");

    buf_ospf_lsa[16] = 0x10;
    buf_ospf_lsa[17] = 0x11;
    test(ntohs(ospf_lsa->checksum) == 4113, "check_ospf_lsa_v2 - checksum");

    buf_ospf_lsa[18] = 0x12;
    buf_ospf_lsa[19] = 0x13;
    test(ntohs(ospf_lsa->length) == 4627, "check_ospf_lsa_v2 - length");
}

void check_ospf_ls_req()
{
    uint8_t buf_ospf_ls_req[12] = {0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
                                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    libtrace_ospf_ls_req_t *ospf_ls_req =
        (libtrace_ospf_ls_req_t *)buf_ospf_ls_req;
    test(ntohl(ospf_ls_req->ls_type) == TRACE_OSPF_LS_ROUTER,
         "check_ospf_ls_req - ls_type");
    test(ntohl(ospf_ls_req->ls_id) == 16843009, "check_ospf_ls_req - ls_id");
    test(ntohl(ospf_ls_req->advertising_router) == 16843009,
         "check_ospf_ls_req - advertising_router");
    // set/check values
    buf_ospf_ls_req[0] = 0x01;
    buf_ospf_ls_req[1] = 0x02;
    buf_ospf_ls_req[2] = 0x03;
    buf_ospf_ls_req[3] = 0x04;
    test(ntohl(ospf_ls_req->ls_type) == 16909060,
         "check_ospf_ls_req - ls_type");

    buf_ospf_ls_req[4] = 0x05;
    buf_ospf_ls_req[5] = 0x06;
    buf_ospf_ls_req[6] = 0x07;
    buf_ospf_ls_req[7] = 0x08;
    test(ntohl(ospf_ls_req->ls_id) == 84281096, "check_ospf_ls_req - ls_id");

    buf_ospf_ls_req[8] = 0x09;
    buf_ospf_ls_req[9] = 0x0a;
    buf_ospf_ls_req[10] = 0x0b;
    buf_ospf_ls_req[11] = 0x0c;
    test(ntohl(ospf_ls_req->advertising_router) == 151653132,
         "check_ospf_ls_req - advertising_router");
}

void check_ospf_ls_update()
{
    uint8_t buf_ospf_ls_update[4] = {0x01, 0x02, 0x03, 0x04};
    libtrace_ospf_ls_update_t *ls_update =
        (libtrace_ospf_ls_update_t *)buf_ospf_ls_update;
    test(ntohl(ls_update->ls_num_adv) == 16909060,
         "check_ospf_ls_update - ls_num_adv");
}

void check_ospf_external_lsa()
{
    uint8_t buf[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    libtrace_ospf_as_external_lsa_v2_t *ospf =
        (libtrace_ospf_as_external_lsa_v2_t *)buf;
    test(ntohl(ospf->netmask.s_addr) == 16909060,
         "check_ospf_external_lsa - netmask");
    test(ospf->tos == 5, "check_ospf_external_lsa - tos");
    test(ospf->e == 0, "check_ospf_external_lsa - e");
    test(ospf->metric_a == 6, "check_ospf_external_lsa - metric_a");
    test(ospf->metric_b == 7, "check_ospf_external_lsa - metric_b");
    test(ospf->metric_c == 8, "check_ospf_external_lsa - metric_c");
    test(ntohl(ospf->forwarding.s_addr) == 151653132,
         "check_ospf_external_lsa - forwarding");
    test(ntohl(ospf->external_tag) == 219025168,
         "check_ospf_external_lsa - external_tag");
}

void check_ospf_summary_lsa()
{
    uint8_t buf[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    libtrace_ospf_summary_lsa_v2_t *ospf =
        (libtrace_ospf_summary_lsa_v2_t *)buf;
    test(ntohl(ospf->netmask.s_addr) == 16909060,
         "check_ospf_summary_lsa - netmask");
    test(ospf->zero == 5, "check_ospf_summary_lsa - zero");
    test(ospf->metric_a == 6, "check_ospf_summary_lsa - metric_a");
    test(ospf->metric_b == 7, "check_ospf_summary_lsa - metric_b");
    test(ospf->metric_c == 8, "check_ospf_summary_lsa - metric_c");
}

void check_ospf_network_lsa()
{
    uint8_t buf[4] = {0x01, 0x02, 0x03, 0x04};
    libtrace_ospf_network_lsa_v2_t *ospf =
        (libtrace_ospf_network_lsa_v2_t *)buf;
    test(ntohl(ospf->netmask.s_addr) == 16909060,
         "check_ospf_network_lsa - netmask");
}

void check_ospf_link()
{
    uint8_t buf[12] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                       0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    libtrace_ospf_link_v2_t *ospf = (libtrace_ospf_link_v2_t *)buf;
    test(ntohl(ospf->link_id.s_addr) == 16909060, "check_ospf_link - link_id");
    test(ntohl(ospf->link_data.s_addr) == 84281096,
         "check_ospf_link - link_data");
    test(ospf->type == 9, "check_ospf_link - type");
    test(ospf->num_tos == 10, "check_ospf_link - num_tos");
    test(ntohs(ospf->tos_metric) == 2828, "check_ospf_link - tos_metric");
}

void check_ospf_router_lsa()
{
    uint8_t buf[4] = {0x01, 0x02, 0x03, 0x04};
    libtrace_ospf_router_lsa_v2_t *ospf = (libtrace_ospf_router_lsa_v2_t *)buf;
    buf[0] = 0x01;
    test(ospf->b == 1, "check_ospf_router_lsa - b");
    buf[0] = 0x02;
    test(ospf->e == 1, "check_ospf_router_lsa - e");
    buf[0] = 0x04;
    test(ospf->v == 1, "check_ospf_router_lsa - v");
    buf[0] = 0xf8;
    test(ospf->zero == 31, "check_ospf_router_lsa - zero");
    test(ospf->zero2 == 2, "check_ospf_router_lsa - zero2");
    test(ntohs(ospf->num_links) == 772, "check_ospf_router_lsa - num_links");
}

void check_sll_header()
{
    uint8_t buf[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    libtrace_sll_header_t *sll = (libtrace_sll_header_t *)buf;
    test(ntohs(sll->pkttype) == 258, "check_sll_header - pkttype");
    test(ntohs(sll->hatype) == 772, "check_sll_header - hatype");
    test(ntohs(sll->halen) == 1286, "check_sll_header - halen");
    for (int i = 0; i < 8; i++)
        test(sll->addr[i] == 7 + i, "check_sll_header - addr[]");
    test(ntohs(sll->protocol) == 3856, "check_sll_header - protocol");
}

int main()
{

    check_eth();
    check_ip4();
    check_ip6();
    check_ip6_frag();
    check_ip6_ext();
    check_udp();
    check_tcp();
    check_icmp();
    check_icmp6();
    check_llcsnap();
    check_8021q();
    check_atm_cell();
    check_atm_nni_cell();
    check_atm_capture_cell();
    check_atm_nni_capture_cell();
    check_ppp();
    check_pppoe();
    check_gre();
    check_vxlan();
    check_radiotap();
    check_80211();
    check_ospf_v2();
    check_ospf_hello();
    check_ospf_options();
    check_ospf_db_desc();
    check_ospf_lsa_v2();
    check_ospf_ls_req();
    check_ospf_ls_update();
    check_ospf_external_lsa();
    check_ospf_summary_lsa();
    check_ospf_network_lsa();
    check_ospf_link();
    check_ospf_router_lsa();
    check_sll_header();

    if (tests_passed)
        printf("success\n");
    else
        return 1;
}
