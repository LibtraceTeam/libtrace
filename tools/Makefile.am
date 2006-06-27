# tracedump depends on libpacketdump
if LIBPACKETDUMP
TRACEDUMP_DIR=tracedump
endif

SUBDIRS=traceanon tracemerge tracesplit $(TRACEDUMP_DIR) tracertstats tracestats
SUBDIRS+=tracereport

all-hook:
	for dir in $(SUBDIRS); do make -C $$dir; done

install-hook:
	for dir in $(SUBDIRS); do make -C $$dir install; done

clean-hook:
	for dir in $(SUBDIRS); do make -C $$dir clean; done
