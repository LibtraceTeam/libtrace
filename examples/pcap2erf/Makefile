include= /usr/local/dag/include
dagcdir= /usr/local/dag/utils/

CC=g++-3.0
CXX=g++-3.0
LD=g++-3.0
INCLUDE = -I$(include) -I/usr/local/wand/include -I$(dagcdir)
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g
CFLAGS += $(INCLUDE)
CPPFLAGS = -Wall -Wimplicit -Wformat -pipe -g
CPPFLAGS += $(INCLUDE)
LDLIBS = -L/usr/local/wand/lib -ltrace

BINS = pcap2erf
DAGCOBJ = pcapio.o utils.o erfio.o
PCAPFIFOOBJS = $(addprefix $(dagcdir), $(DAGCOBJ))
.PHONY: all clean distclean install depend

all: $(BINS) 

clean:
	$(RM) *~ *.o $(BINS) $(OBJS)

distclean:
	$(RM) *~ *.o $(BINS) $(OBJS)

install:
	@true

rtclient-pcap: $(OBJS) rtclient-pcap.o $(PCAPFIFOOBJS)

pcap2erf: $(OBJS) pcap2erf.o $(PCAPFIFOOBJS)

# vim: noet ts=8 sw=8
