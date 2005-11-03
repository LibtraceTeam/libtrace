# tracedump depends on libpacketdump
if LIBPACKETDUMP
TRACEDUMP_DIR=tracedump
endif

if LIBTRACE_TOOLS
SUBDIRS=traceanon tracemerge tracesplit tracertstats $(TRACEDUMP_DIR) $(TRACERTSTATS_DIR)
else
SUBDIRS=
endif

EXTRA_DIST=tracereport

all-hook:
	for dir in $(SUBDIRS); do make -C $$dir; done

install-hook:
	for dir in $(SUBDIRS); do make -C $$dir install; done

clean-hook:
	for dir in $(SUBDIRS); do make -C $$dir clean; done
