include= /usr/local/dag/include
dagcdir= /usr/local/dag/utils/

CC=g++
CXX=g++
LD=g++
INCLUDE = -I$(include) -I/usr/local/include -I$(dagcdir)
CFLAGS = -Wall -Wimplicit -Wformat -pipe -g
CFLAGS += $(INCLUDE)
CPPFLAGS = -Wall -Wimplicit -Wformat -pipe -g
CPPFLAGS += $(INCLUDE)
LDLIBS = -L/usr/local/lib -ltrace

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
