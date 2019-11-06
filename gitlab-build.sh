#!/bin/bash

set -x -e -o pipefail

export DEBEMAIL='packaging@wand.net.nz'
export DEBFULLNAME='WAND Packaging'
export DEBIAN_FRONTEND=noninteractive

SOURCENAME=`echo ${CI_COMMIT_REF_NAME} | cut -d '-' -f 1`

apt-get update
apt-get install -y equivs devscripts dpkg-dev quilt curl apt-transport-https \
    apt-utils ssl-cert ca-certificates gnupg lsb-release debhelper git \
    pkg-config

DISTRO=$(lsb_release -sc)

echo "deb https://dl.bintray.com/wand/general ${DISTRO} main" | \
    tee -a /etc/apt/sources.list.d/wand.list


case ${DISTRO} in
        jessie | xenial | stretch )
                echo "deb https://dl.bintray.com/wand/libtrace ${DISTRO} main" \
                        | tee -a /etc/apt/sources.list.d/wand.list
        ;;
esac

curl --silent "https://bintray.com/user/downloadSubjectPublicKey?username=wand"\
    | apt-key add -

apt-get update
apt-get upgrade -y

dpkg-parsechangelog -S version | grep -q ${SOURCENAME} || debchange --newversion ${SOURCENAME} -b "New upstream release"
mk-build-deps -i -r -t 'apt-get -f -y --force-yes'
dpkg-buildpackage -b -us -uc -rfakeroot -j4
