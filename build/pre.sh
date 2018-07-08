#! /usr/bin/env bash

set -e
./autogen.sh
rm -rf aclocal

cat Makefile.in  | sed '/^mrproper:/,/^$/ d' > Makefile.in.new
cat Makefile.in.new > Makefile.in
rm -f Makefile.in.new

exit 0
