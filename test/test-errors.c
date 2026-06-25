/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson
 *          Perry Lorier
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: test-rtclient.c,v 1.2 2006/02/27 03:41:12 perry Exp $
 *
 */
#include "../config.h"
#include <libtrace.h>
#include <assert.h>
#include <string.h>

/* If you don't specify O_WONLY or O_RDWR on the fileflags, then this should
 * fail.
 */
void test_forgotten_wronly()
{
    libtrace_out_t *out;
    libtrace_t *trace;
    libtrace_packet_t *packet;
    int err;
    int zero = 0;

    out = trace_create_output("pcapfile:traces/100_packets_out.pcap");
    assert(out);
    assert(!trace_is_err_output(out));
    /* Note: no WRONLY/RDWR */
    err = trace_config_output(out, TRACE_OPTION_OUTPUT_FILEFLAGS, &zero);
    assert(err == 0);
    assert(!trace_is_err_output(out));

    err = trace_start_output(out);
    assert(err == 0);
    assert(!trace_is_err_output(out));

    trace = trace_create("pcapfile:traces/100_packets.pcap");
    assert(trace);
    assert(!trace_is_err(trace));

    err = trace_start(trace);
    assert(!trace_is_err(trace));
    assert(err == 0);

    packet = trace_create_packet();
    assert(packet);

    err = trace_read_packet(trace, packet);
    assert(err > 0);

    err = trace_write_packet(out, packet);
    assert(err == -1); /* Should fail */
    assert(trace_is_err_output(out));

    trace_destroy_output(out);
    trace_destroy_packet(packet);
    trace_destroy(trace);
}

#ifdef HAVE_DPDK
void test_dpdk_mtu_errors()
{
    libtrace_t *trace;
    libtrace_err_t err;

    /* 1. Test MTU too small */
    trace = trace_create("dpdkvdev:net_pcap1,iface=veth1?mtu=5");
    assert(trace);
    assert(trace_is_err(trace));
    err = trace_get_err(trace);
    assert(err.err_num == TRACE_ERR_INIT_FAILED);
    assert(strstr(err.problem, "outside valid range") != NULL);
    trace_destroy(trace);

    /* 2. Test MTU too large */
    trace = trace_create("dpdkvdev:net_pcap1,iface=veth1?mtu=70000");
    assert(trace);
    assert(trace_is_err(trace));
    err = trace_get_err(trace);
    assert(err.err_num == TRACE_ERR_INIT_FAILED);
    assert(strstr(err.problem, "outside valid range") != NULL);
    trace_destroy(trace);

    /* 3. Test invalid MTU format */
    trace = trace_create("dpdkvdev:net_pcap1,iface=veth1?mtu=abc");
    assert(trace);
    assert(trace_is_err(trace));
    err = trace_get_err(trace);
    assert(err.err_num == TRACE_ERR_INIT_FAILED);
    assert(strstr(err.problem, "invalid mtu parameter") != NULL);
    trace_destroy(trace);

    /* 4. Test valid MTU value doesn't trigger MTU syntax/range errors */
    trace = trace_create("dpdkvdev:net_pcap1,iface=veth1?mtu=1500");
    assert(trace);
    /* Since we're not running with live devices and root, trace_create could fail
     * (e.g. because EAL or the PMD initialization fails).
     * If it fails, the error message must NOT be about the MTU itself.
     */
    if (trace_is_err(trace)) {
        err = trace_get_err(trace);
        assert(strstr(err.problem, "outside valid range") == NULL);
        assert(strstr(err.problem, "invalid mtu parameter") == NULL);
    }
    trace_destroy(trace);

    /* 5. Test another valid jumbo MTU value doesn't trigger MTU syntax/range errors */
    trace = trace_create("dpdkvdev:net_pcap1,iface=veth1?mtu=9000");
    assert(trace);
    if (trace_is_err(trace)) {
        err = trace_get_err(trace);
        assert(strstr(err.problem, "outside valid range") == NULL);
        assert(strstr(err.problem, "invalid mtu parameter") == NULL);
    }
    trace_destroy(trace);
}
#endif

int main(int argc UNUSED, char *argv[] UNUSED)
{

    /* This test is no longer useful, as the new libtrace IO system
     * ensures that all output files are opened with WRONLY, so the
     * test will always assert fail when the write error does not
     * occur */

    /* test_forgotten_wronly(); */

#ifdef HAVE_DPDK
    test_dpdk_mtu_errors();
#endif

    return 0;
}
