bin_PROGRAMS = tracertstats tracertstats_parallel
man_MANS = tracertstats.1
EXTRA_DIST = $(man_MANS)

if HAVE_LIBGDC
LIBGDC_MODULES=output_png.c
OUTPUT_PNG_LD=-lgdc
else
LIBGDC_MODULES=
OUTPUT_PNG_LD=
endif

OUTPUT_MODULES=output_csv.c output_html.c output_txt.c $(LIBGDC_MODULES)

include ../Makefile.tools
tracertstats_SOURCES = tracertstats.c output.h output.c $(OUTPUT_MODULES)
tracertstats_LDADD = -ltrace $(OUTPUT_PNG_LD)
tracertstats_parallel_SOURCES = tracertstats_parallel.c output.h output.c $(OUTPUT_MODULES)
tracertstats_parallel_LDADD = -ltrace $(OUTPUT_PNG_LD)
