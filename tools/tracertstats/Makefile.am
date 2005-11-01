bin_PROGRAMS = tracertstats

tracertstats_SOURCES = tracertstats.c output.h output.c output_csv.c output_html.c output_png.c
tracertstats_LDADD = -ltrace -lgdc
tracertstats_LDFLAGS = -L$(prefix)/lib/ -L$(top_srcdir)/lib/
