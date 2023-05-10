#!/bin/bash

set -x -e -o pipefail

export DEBEMAIL='shane@alcock.co.nz'
export DEBFULLNAME='Shane Alcock'
export DEBIAN_FRONTEND=noninteractive

export SOURCENAME=`echo ${GITHUB_REF##*/} | cut -d '-' -f 1`

apt-get update
apt-get install -y equivs devscripts dpkg-dev quilt curl apt-transport-https \
    apt-utils ssl-cert ca-certificates gnupg lsb-release debhelper git \
    pkg-config sed clang

curl -1sLf 'https://dl.cloudsmith.io/public/wand/libwandio/cfg/setup/bash.deb.sh' | bash
curl -1sLf 'https://dl.cloudsmith.io/public/wand/libwandder/cfg/setup/bash.deb.sh' | bash

DISTRO=$(lsb_release -sc)

case ${DISTRO} in
        xenial )
                curl -1sLf 'https://dl.cloudsmith.io/public/wand/dpdk-wand/cfg/setup/bash.deb.sh' | bash
                apt-get install -y debhelper -t xenial-backports
                sed -i 's/debhelper-compat (= 12)/debhelper (>= 10)/' debian/control
                echo "10" > debian/compat
        ;;

        stretch )
                curl -1sLf 'https://dl.cloudsmith.io/public/wand/dpdk-wand/cfg/setup/bash.deb.sh' | bash
                sed -i 's/debhelper-compat (= 12)/debhelper (>= 10)/' debian/control
                echo "10" > debian/compat
        ;;

        bionic )
                apt-get install -y debhelper -t bionic-backports
        ;;
esac

apt-get update
apt-get upgrade -y
