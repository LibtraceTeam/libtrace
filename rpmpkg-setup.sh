#!/bin/bash
set -x -e -o pipefail

TARGET=$1

MAJOR=$(echo "${TARGET}" | grep -oP '(?<=almalinux:)[89]')
MINOR=$(echo "${TARGET}" | grep -oP '(?<=almalinux:[89]\.)\d+')

if [[ "${MAJOR}" == "8" ]]; then
    rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux
elif [[ "${MAJOR}" == "9" ]]; then
    rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9
fi

mkdir -p /run/user/${UID}
chmod 0700 /run/user/${UID}
dnf install -y wget make gcc clang

dnf install -y dnf-plugins-core
# Disable all repos first to avoid conflicts
dnf config-manager --disable '*'

# Enable base AlmaLinux repos for the specific minor release
dnf config-manager --enable baseos
dnf config-manager --enable appstream

if [[ "$MAJOR" == "8" ]]; then
  dnf config-manager --enable powertools || true
  dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
elif [[ "$MAJOR" == "9" ]]; then
  dnf config-manager --enable crb || true
  dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
fi

dnf group install -y "Development Tools"
dnf config-manager --set-enabled epel

curl -1sLf \
  'https://dl.cloudsmith.io/public/wand/libwandio/cfg/setup/bash.rpm.sh' \
    | bash

curl -1sLf \
  'https://dl.cloudsmith.io/public/wand/libwandder/cfg/setup/bash.rpm.sh' \
    | bash

dnf makecache

dnf install -y rpm-build rpmdevtools 'dnf-command(builddep)' which
dnf builddep -y rpm/libtrace4.spec

rpmdev-setuptree
