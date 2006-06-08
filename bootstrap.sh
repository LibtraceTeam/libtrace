#! /bin/sh

set -x
aclocal-1.9 || aclocal 
libtoolize --force --copy
autoheader
automake-1.9 --add-missing --copy || automake --add-missing --copy
autoconf
