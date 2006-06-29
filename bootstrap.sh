#! /bin/sh

set -x
aclocal-1.9 -I m4 || 
	aclocal  -I m4
libtoolize --force --copy
autoheader
automake-1.9 --add-missing --copy --foreign || 
	automake --add-missing --copy --foreign
autoconf
