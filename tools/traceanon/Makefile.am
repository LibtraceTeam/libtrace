bin_PROGRAMS = traceanon

man1_MANS = traceanon.1
traceanon_SOURCES = traceanon.c rijndael.h rijndael.c panon.h panon.c ipenc.c ipenc.h
traceanon_LDADD = -ltrace 
traceanon_LDFLAGS = -L$(prefix)/lib/ -L$(top_srcdir)/lib/
