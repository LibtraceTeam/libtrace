#! /bin/sh

ACLOCAL_DIRS="-I m4"
if [ -d /usr/local/share/aclocal ]; then
  ACLOCAL_DIRS="${ACLOCAL_DIRS} -I /usr/local/share/aclocal"
fi

if [ -d /usr/share/aclocal ]; then
  ACLOCAL_DIRS="${ACLOCAL_DIRS} -I /usr/share/aclocal"
fi

set -x
# Prefer aclocal 1.9 if we can find it
aclocal-1.11 ${ACLOCAL_DIRS} ||
	aclocal-1.9 ${ACLOCAL_DIRS} || 
	aclocal ${ACLOCAL_DIRS}

# Darwin bizarrely uses glibtoolize
libtoolize --force --copy ||
	glibtoolize --force --copy

autoheader2.50 || autoheader

# Prefer automake-1.9 if we can find it
automake-1.11 --add-missing --copy --foreign ||
	automake-1.10 --add-missing --copy --foreign || 
	automake-1.9 --add-missing --copy --foreign || 
	automake --add-missing --copy --foreign

autoconf2.50 || autoconf 
