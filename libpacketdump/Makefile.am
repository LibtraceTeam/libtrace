lib_LTLIBRARIES = libpacketdump.la
include_HEADERS = libpacketdump.h

plugindir = $(libdir)/libpacketdump

BIN_PROTOCOLS=
TXT_PROTOCOLS=

# Link layers supported
# Legacy
BIN_PROTOCOLS+=link_0.la

# HDLC_POS

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

# POS
BIN_PROTOCOLS+=link_9.la

# Obsolete Legacy ATM
#				

# Obsolete Legacy Ethernet
BIN_PROTOCOLS+=link_10.la	

# 802.11 Prisom
BIN_PROTOCOLS+=link_11.la	

# AAL5
#			
# Duck

#				

# Radiotap
BIN_PROTOCOLS+=link_15.la

# Decoders for various ethertypes (in decimal)
# IPv4
BIN_PROTOCOLS+=eth_2048.la
# ARP
BIN_PROTOCOLS+=eth_2054.la	
# IPv6
TXT_PROTOCOLS+=eth_33024.protocol	
# MPLS
BIN_PROTOCOLS+=eth_34887.la
# 802.1x
BIN_PROTOCOLS+=eth_34958.la

# IP Protocol decoders
# ICMP
BIN_PROTOCOLS+=ip_1.la
# TCP
BIN_PROTOCOLS+=ip_6.la
# UDP
BIN_PROTOCOLS+=ip_17.la
# DCCP
BIN_PROTOCOLS+=ip_33.la 
# IPv6
TXT_PROTOCOLS+=ip_41.protocol
# ICMP6
TXT_PROTOCOLS+=ip_58.protocol 
# SCTP
BIN_PROTOCOLS+=ip_132.la        

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
link_15_la_LDFLAGS=-module 
eth_2048_la_LDFLAGS=-module
eth_2054_la_LDFLAGS=-module
eth_34887_la_LDFLAGS=-module
eth_34958_la_LDFLAGS=-module

ip_1_la_LDFLAGS=-module
ip_6_la_LDFLAGS=-module
ip_17_la_LDFLAGS=-module
ip_33_la_LDFLAGS=-module
ip_132_la_LDFLAGS=-module

libpacketdump_la_SOURCES = libpacketdump.cc \
			lexer.l parser.y bitbuffer.c bitbuffer.h grammar.h

plugin_LTLIBRARIES = $(BIN_PROTOCOLS)
dist_plugin_DATA = $(TXT_PROTOCOLS)

INCLUDES= @ADD_INCLS@ -I../lib 

# NOTE: You CANNOT add @LEXLIBS@ here, as they are statically compiled
# which on non x86_32 platforms means that they cannot be linked into
# a shared library.
libpacketdump_la_LIBADD = @ADD_LIBS@ 
libpacketdump_la_LDFLAGS=\
        -version-info @LIBTRACE_MAJOR@:@LIBTRACE_MINOR@:@LIBTRACE_MID@ \
        @ADD_LDFLAGS@

AM_CXXFLAGS=-g -Wall -DDIRNAME=\"$(plugindir)\" $(INCLUDES)
BUILT_SOURCES=parser.h
AM_YFLAGS=-d
EXTRA_DIST=lexer.l parser.y
