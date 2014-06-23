lib_LTLIBRARIES = libpacketdump.la
include_HEADERS = libpacketdump.h

plugindir = $(libdir)/libpacketdump

BIN_PROTOCOLS=
TXT_PROTOCOLS=

# Link layers supported
# Legacy
BIN_PROTOCOLS+=link_0.la

# HDLC_POS
BIN_PROTOCOLS+=link_1.la

# Ethernet
BIN_PROTOCOLS+=link_2.la

# ATM
TXT_PROTOCOLS+=link_3.protocol

# 802.11
BIN_PROTOCOLS+=link_4.la

# NONE
#

# Linux SLL
#TXT_PROTOCOLS+=link_6.protocol	
BIN_PROTOCOLS+=link_6.la

# PFLog
#	

# Obsolete legacy
# 		

# Obsolete Legacy ATM
#				

# PoS 
BIN_PROTOCOLS+=link_9.la

# Obsolete Legacy Ethernet
BIN_PROTOCOLS+=link_10.la	

# 802.11 Prism
BIN_PROTOCOLS+=link_11.la	

# 13: AAL5
#			
# 14: Duck
#

# 15: Radiotap
BIN_PROTOCOLS+=link_15.la

# 16: LLC/SNAP
#
# 17: PPP
TXT_PROTOCOLS+=link_17.protocol

# Decoders for various ethertypes (in decimal)
# IPv4
BIN_PROTOCOLS+=eth_0.la
BIN_PROTOCOLS+=eth_2048.la
# ARP
BIN_PROTOCOLS+=eth_2054.la	
# VLAN (802.1Q)
BIN_PROTOCOLS+=eth_33024.la
# MPLS
BIN_PROTOCOLS+=eth_34887.la
# pppoe
BIN_PROTOCOLS+=eth_34916.la
# 802.1x
BIN_PROTOCOLS+=eth_34958.la

# IPv6
BIN_PROTOCOLS+=eth_34525.la

# IP Protocol decoders
# IPv6 Hop by Hop Options Header
BIN_PROTOCOLS+=ip_0.la
# ICMP
BIN_PROTOCOLS+=ip_1.la
# TCP
BIN_PROTOCOLS+=ip_6.la
# UDP
BIN_PROTOCOLS+=ip_17.la
# DCCP
BIN_PROTOCOLS+=ip_33.la 
# IPv6 Routing Header
BIN_PROTOCOLS+=ip_43.la
# IPv6 Fragment Header
BIN_PROTOCOLS+=ip_44.la
# GRE
BIN_PROTOCOLS+=ip_47.la
# ICMP6
TXT_PROTOCOLS+=ip_58.protocol 
# IPv6 Destination Options Header
BIN_PROTOCOLS+=ip_60.la
# OSPF
BIN_PROTOCOLS+=ip_89.la
# SCTP
BIN_PROTOCOLS+=ip_132.la        

# TCP protocol decoders
# (tcp_*.la)

# UDP protocol decoders
# (udp_*.la)

# OSPF decoders
BIN_PROTOCOLS+=ospf2_1.la
BIN_PROTOCOLS+=ospf2_4.la
BIN_PROTOCOLS+=ospf2_5.la

# Start numbering OSPF LSA types from 1000
BIN_PROTOCOLS+=ospf2_1000.la
BIN_PROTOCOLS+=ospf2_1001.la
BIN_PROTOCOLS+=ospf2_1002.la
BIN_PROTOCOLS+=ospf2_1003.la
BIN_PROTOCOLS+=ospf2_1004.la
BIN_PROTOCOLS+=ospf2_1005.la

# I shouldn't need to do this
modflags=-module -avoid-version -shared
link_0_la_LDFLAGS=$(modflags)
link_1_la_LDFLAGS=$(modflags)
link_2_la_LDFLAGS=$(modflags)
link_4_la_LDFLAGS=$(modflags)
link_6_la_LDFLAGS=$(modflags) 
link_9_la_LDFLAGS=$(modflags)
link_10_la_LDFLAGS=$(modflags)
link_11_la_LDFLAGS=$(modflags)
link_15_la_LDFLAGS=$(modflags) 
eth_0_la_LDFLAGS=$(modflags)
eth_2048_la_LDFLAGS=$(modflags)
eth_2054_la_LDFLAGS=$(modflags)
eth_33024_la_LDFLAGS=$(modflags)
eth_34887_la_LDFLAGS=$(modflags)
eth_34916_la_LDFLAGS=$(modflags)
eth_34958_la_LDFLAGS=$(modflags)
eth_34525_la_LDFLAGS=$(modflags)

ip_0_la_LDFLAGS=$(modflags)
ip_1_la_LDFLAGS=$(modflags)
ip_6_la_LDFLAGS=$(modflags)
ip_17_la_LDFLAGS=$(modflags)
ip_33_la_LDFLAGS=$(modflags)
ip_43_la_LDFLAGS=$(modflags)
ip_44_la_LDFLAGS=$(modflags)
ip_47_la_LDFLAGS=$(modflags)
ip_60_la_LDFLAGS=$(modflags)
ip_89_la_LDFLAGS=$(modflags)
ip_132_la_LDFLAGS=$(modflags)

ospf2_1_la_LDFLAGS=$(modflags)
ospf2_4_la_LDFLAGS=$(modflags)
ospf2_5_la_LDFLAGS=$(modflags)
ospf2_1000_la_LDFLAGS=$(modflags)
ospf2_1001_la_LDFLAGS=$(modflags)
ospf2_1002_la_LDFLAGS=$(modflags)
ospf2_1003_la_LDFLAGS=$(modflags)
ospf2_1004_la_LDFLAGS=$(modflags)
ospf2_1005_la_LDFLAGS=$(modflags)

libpacketdump_la_SOURCES = libpacketdump.cc ../lib/byteswap.c \
			lexer.l parser.y bitbuffer.c bitbuffer.h grammar.h

plugin_LTLIBRARIES = $(BIN_PROTOCOLS)
dist_plugin_DATA = $(TXT_PROTOCOLS)

AM_CPPFLAGS= @ADD_INCLS@ -I../lib -I../libwandio 

# NOTE: You CANNOT add @LEXLIBS@ here, as they are statically compiled
# which on non x86_32 platforms means that they cannot be linked into
# a shared library.
libpacketdump_la_LIBADD = @LIBPKTDUMP_LIBS@ 
libpacketdump_la_LDFLAGS=\
        -version-info @LIBTRACE_MAJOR@:@LIBTRACE_MINOR@:@LIBTRACE_MID@ \
        @ADD_LDFLAGS@

AM_CXXFLAGS=-g -Wall -DDIRNAME=\"$(plugindir)\" $(AM_CPPFLAGS)
BUILT_SOURCES=parser.h
AM_YFLAGS=-d
EXTRA_DIST=lexer.l parser.y

install-exec-hook:
	$(AM_V_GEN)mkdir -p $(DESTDIR)$(plugindir)
	$(AM_V_GEN)cd $(DESTDIR)$(plugindir) && $(LN_S) -f eth_2048.so ppp_33.so
	$(AM_V_GEN)cd $(DESTDIR)$(plugindir) && $(LN_S) -f eth_2048.so link_5.so
	$(AM_V_GEN)cd $(DESTDIR)$(plugindir) && $(LN_S) -f eth_34525.so ip_41.so

install-data-hook:
	rm -f $(DESTDIR)$(plugindir)/*.la
