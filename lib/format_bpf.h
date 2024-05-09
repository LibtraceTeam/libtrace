/*
 *
 * Copyright (c) 2007-2023 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * Libtrace was originally developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

/*
 * Copyright (c) 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/* Various net/bpf.h definitions that we still need for format_bpf.c.
 * We don't really want to be including net/bpf.h any more (because
 * we prefer pcap/bpf.h instead) so we need these definitions to be
 * available internally.
 *
 * It seems a bit silly, but pcap/bpf.h and net/bpf.h don't play nicely
 * together and we need definitions from both.
 */

#ifndef LIBTRACE_FORMAT_BPF_H_
#define LIBTRACE_FORMAT_BPF_H_

/*
 * Struct returned by BIOCGSTATS.
 */
struct bpf_stat {
    u_int bs_recv; /* number of packets received */
    u_int bs_drop; /* number of packets dropped */
};

/*
 * Struct return by BIOCVERSION.  This represents the version number of
 * the filter language described by the instruction encodings below.
 * bpf understands a program iff kernel_major == filter_major &&
 * kernel_minor >= filter_minor, that is, if the value returned by the
 * running kernel has the same major number and a minor number equal
 * equal to or less than the filter being downloaded.  Otherwise, the
 * results are undefined, meaning an error may be returned or packets
 * may be accepted haphazardly.
 * It has nothing to do with the source code version.
 */
struct bpf_version {
    u_short bv_major;
    u_short bv_minor;
};
/* Current version number of filter architecture. */
#define BPF_MAJOR_VERSION 1
#define BPF_MINOR_VERSION 1

/*
 * BPF ioctls
 */
#define BIOCGBLEN _IOR('B', 102, u_int)
#define BIOCSBLEN _IOWR('B', 102, u_int)
#define BIOCSETF _IOW('B', 103, struct bpf_program)
#define BIOCFLUSH _IO('B', 104)
#define BIOCPROMISC _IO('B', 105)
#define BIOCGDLT _IOR('B', 106, u_int)
#define BIOCGETIF _IOR('B', 107, struct ifreq)
#define BIOCSETIF _IOW('B', 108, struct ifreq)
#define BIOCSRTIMEOUT _IOW('B', 109, struct timeval)
#define BIOCGRTIMEOUT _IOR('B', 110, struct timeval)
#define BIOCGSTATS _IOR('B', 111, struct bpf_stat)
#define BIOCIMMEDIATE _IOW('B', 112, u_int)
#define BIOCVERSION _IOR('B', 113, struct bpf_version)
#define BIOCSRSIG _IOW('B', 114, u_int)
#define BIOCGRSIG _IOR('B', 115, u_int)
#define BIOCGHDRCMPLT _IOR('B', 116, u_int)
#define BIOCSHDRCMPLT _IOW('B', 117, u_int)
#define BIOCLOCK _IO('B', 118)
#define BIOCSETWF _IOW('B', 119, struct bpf_program)
#define BIOCGFILDROP _IOR('B', 120, u_int)
#define BIOCSFILDROP _IOW('B', 121, u_int)
#define BIOCSDLT _IOW('B', 122, u_int)
#define BIOCGDLTLIST _IOWR('B', 123, struct bpf_dltlist)
#define BIOCGDIRFILT _IOR('B', 124, u_int)
#define BIOCSDIRFILT _IOW('B', 125, u_int)
#define BIOCSWTIMEOUT _IOW('B', 126, struct timeval)
#define BIOCGWTIMEOUT _IOR('B', 126, struct timeval)
#define BIOCDWTIMEOUT _IO('B', 126)

#endif
