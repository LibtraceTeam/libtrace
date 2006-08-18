lib_LTLIBRARIES = libpacketdump.la
include_HEADERS = libpacketdump.h

plugindir = $(libdir)/libpacketdump

BIN_PROTOCOLS=
TXT_PROTOCOLS=

# Link layers supported
BIN_PROTOCOLS+=link_0.la        # Legacy
# 				# HDLC_POS
BIN_PROTOCOLS+=link_2.la	# Ethernet
TXT_PROTOCOLS+=link_3.protocol	# ATM
BIN_PROTOCOLS+=link_4.la	# 802.11
# 				# NONE
BIN_PROTOCOLS+=link_6.la	# Linux SLL
TXT_PROTOCOLS+=link_7.protocol	# PFLog
# 				# Obsolete legacy
BIN_PROTOCOLS+=link_9.la	# POS
#				# Obsolete Legacy ATM
BIN_PROTOCOLS+=link_10.la	# Obsolete Legacy Ethernet
BIN_PROTOCOLS+=link_11.la	# 802.11 Prism
#				# AAL5
#				# Duck

# Decoders for various ethertypes (in decimal)
BIN_PROTOCOLS+=eth_2048.la		# IPv4
BIN_PROTOCOLS+=eth_2054.la		# ARP
TXT_PROTOCOLS+=eth_33024.protocol	# IPv6

# IP Protocol decoders
BIN_PROTOCOLS+=ip_1.la  # ICMP
BIN_PROTOCOLS+=ip_6.la  # TCP
BIN_PROTOCOLS+=ip_17.la # UDP
BIN_PROTOCOLS+=ip_33.la # DCCP
TXT_PROTOCOLS+=ip_41.protocol # IPv6
TXT_PROTOCOLS+=ip_58.protocol # ICMP6
BIN_PROTOCOLS+=ip_132.la        # SCTP

# TCP protocol decoders
# (tcp_*.la)

# UDP protocol decoders
# (udp_*.la)

# I shouldn't need to do this
link_0_la_LDFLAGS=-module
link_2_la_LDFLAGS=-module
link_4_la_LDFLAGS=-module
link_6_la_LDFLAGS=-module
link_9_la_LDFLAGS=-module
link_10_la_LDFLAGS=-module
link_11_la_LDFLAGS=-module

eth_2048_la_LDFLAGS=-module
eth_2054_la_LDFLAGS=-module

ip_1_la_LDFLAGS=-module
ip_6_la_LDFLAGS=-module
ip_17_la_LDFLAGS=-module
ip_33_la_LDFLAGS=-module
ip_132_la_LDFLAGS=-module

SUBDIRS = parser

libpacketdump_la_SOURCES = libpacketdump.cc $(BIN_PROTOCOLS)

plugin_LTLIBRARIES = $(BIN_PROTOCOLS)
plugin_DATA = $(TXT_PROTOCOLS)

INCLUDES= @ADD_INCLS@ -I../lib -I../
libpacketdump_la_LIBADD = @ADD_LIBS@ -lparser
libpacketdump_la_LDFLAGS=\
        -version-info @LIBTRACE_MAJOR@:@LIBTRACE_MINOR@:@LIBTRACE_MID@ \
        @ADD_LDFLAGS@ \
        -L./parser

AM_CXXFLAGS=-g -Wall -DDIRNAME=\"$(plugindir)\" $(INCLUDES)

