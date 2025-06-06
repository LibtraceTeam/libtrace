#!/bin/bash

set -x -e -o pipefail

export QA_RPATHS=$[ 0x0001 ]
SOURCENAME=`echo ${GITHUB_REF##*/} | cut -d '-' -f 1`

rm -rf ~/rpmbuild/BUILD/*
rm -rf ~/rpmbuild/RPMS/*

./bootstrap.sh && ./configure && make dist
cp libtrace-*.tar.gz ~/rpmbuild/SOURCES/${SOURCENAME}.tar.gz
cp rpm/libtrace4.spec ~/rpmbuild/SPECS/

if [[ -z "${RHEL_RELEASE:-}" ]]; then
    cd ~/rpmbuild && rpmbuild -bb --define "debug_package %{nil}" SPECS/libtrace4.spec
else
    cd ~/rpmbuild && rpmbuild -bb --define "debug_package %{nil}" --define "rhel_release ${RHEL_RELEASE}" SPECS/libtrace4.spec
fi


