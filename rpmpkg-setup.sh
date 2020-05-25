#!/bin/bash
set -x -e -o pipefail


DISTRO=fedora
if [ "$1" = "centos:8" ]; then
        DISTRO=centos
fi

if [ "$1" = "centos:7" ]; then
        DISTRO=centos
fi

mkdir -p /run/user/${UID}
chmod 0700 /run/user/${UID}
yum install -y wget make gcc

cat << EOF > /etc/yum.repos.d/bintray-wand-general-rpm.repo
#bintray-wand-general-rpm - packages by wand from Bintray
[bintray-wand-general-rpm]
name=bintray-wand-general-rpm
baseurl=https://dl.bintray.com/wand/general-rpm/${DISTRO}/\$releasever/\$basearch/
gpgkey=https://bintray.com/user/downloadSubjectPublicKey?username=wand
gpgcheck=0
repo_gpgcheck=1
enabled=1
EOF

yum update -y
cat << EOF > /etc/yum.repos.d/bintray-wand-libtrace-rpm.repo
#bintray-wand-libtrace-rpm - packages by wand from Bintray
[bintray-wand-libtrace-rpm]
name=bintray-wand-libtrace-rpm
baseurl=https://dl.bintray.com/wand/libtrace-rpm/${DISTRO}/\$releasever/\$basearch/
gpgkey=https://bintray.com/user/downloadSubjectPublicKey?username=wand
gpgcheck=0
repo_gpgcheck=1
enabled=1
EOF
yum update -y


if [ "$1" = "centos:8" ]; then
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm || true
        dnf install -y 'dnf-command(config-manager)' || true
        yum config-manager --set-enabled PowerTools || true
fi

if [ "$1" = "centos:7" ]; then
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm || true
fi

if [[ "$1" =~ fedora* ]]; then
        dnf install -y rpm-build rpmdevtools 'dnf-command(builddep)' which
        dnf group install -y "C Development Tools and Libraries"
        dnf builddep -y rpm/libtrace4.spec
else
        yum install -y rpm-build yum-utils rpmdevtools which
        yum groupinstall -y 'Development Tools'
        yum-builddep -y rpm/libtrace4.spec
        #yum-builddep -y rpm/libtrace4-dag.spec
fi

rpmdev-setuptree
