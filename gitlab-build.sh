#!/bin/bash

set -x -e -o pipefail

export DEBEMAIL='packaging@wand.net.nz'
export DEBFULLNAME='WAND Packaging'
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y equivs devscripts dpkg-dev quilt curl apt-transport-https \
    apt-utils ssl-cert ca-certificates gnupg lsb-release debhelper git

echo "deb https://packages.wand.net.nz $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/wand.list
curl https://packages.wand.net.nz/keyring.gpg -o /etc/apt/trusted.gpg.d/wand.gpg

apt-get update
apt-get upgrade -y

dpkg-parsechangelog -S version | grep -q ${CI_COMMIT_REF_NAME} || debchange --newversion ${CI_COMMIT_REF_NAME} -b "New upstream release"
mk-build-deps -i -r -t 'apt-get -f -y --force-yes'
dpkg-buildpackage -b -us -uc -rfakeroot -j4
