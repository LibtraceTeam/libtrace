#!/bin/bash
set -x -e -o pipefail

mkdir -p /run/user/${UID}
chmod 0700 /run/user/${UID}
dnf install -y wget make gcc clang
dnf update -y
dnf upgrade -y ca-certificates

dnf install -y dnf-plugins-core epel-release || true
dnf config-manager --set-enabled powertools || true
dnf module disable -y mariadb || true
/usr/bin/crb enable || true


curl -1sLf \
  'https://dl.cloudsmith.io/public/wand/libwandio/cfg/setup/bash.rpm.sh' \
    | bash

curl -1sLf \
  'https://dl.cloudsmith.io/public/wand/libwandder/cfg/setup/bash.rpm.sh' \
    | bash

dnf makecache

yum install -y rpm-build yum-utils rpmdevtools which
yum groupinstall -y 'Development Tools'

dnf builddep -y rpm/libtrace4.spec

rpmdev-setuptree
