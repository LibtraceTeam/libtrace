#! /bin/sh

set -x
# Prefer aclocal 1.9 if we can find it
aclocal-1.9 -I m4 || 
	aclocal  -I m4

# Darwin bizarrely uses glibtoolize
libtoolize --force --copy ||
	glibtoolize --force --copy

autoheader

# Prefer automake-1.9 if we can find it
automake-1.9 --add-missing --copy --foreign || 
	automake --add-missing --copy --foreign

autoconf #-Wall
