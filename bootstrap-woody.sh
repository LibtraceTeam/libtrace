#! /bin/sh

set -x
aclocal 
libtoolize --force --copy
autoheader2.50
automake --add-missing --copy
autoconf2.50
