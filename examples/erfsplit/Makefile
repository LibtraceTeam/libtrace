
CFLAGS= -Wall -Wimplicit -Wformat -O2 -pipe -g

INCLUDE = -I/usr/local/include -I/usr/local/dag/include
CFLAGS += $(INCLUDE)
LDLIBS =  -L/usr/local/lib -ltrace

BINS    = erfsplit

#LEX = flex -Pdagopt
#YACC = bison -y -p dagopt

.PHONY: all clean distclean install depend

all: $(BINS)

clean:
	$(RM) *~ *.o $(BINS) 

distclean:
	$(RM) *~ *.o $(BINS) 

erfsplit: erfsplit.o getdate.tab.o

getdate.tab.c: getdate.y
	bison -y -b getdate getdate.y


install:
	@true
