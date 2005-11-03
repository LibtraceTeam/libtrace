bin_PROGRAMS = tracertstats

OUTPUT_MODULES=output_csv.c output_html.c
if LIBGDC
OUTPUT_MODULES+=output_png.c
OUTPUT_PNG_LD=-lgdc
endif

include ../Makefile.tools
tracertstats_SOURCES = tracertstats.c output.h output.c $(OUTPUT_MODULES)
tracertstats_LDADD = -ltrace $(OUTPUT_PNG_LD)
