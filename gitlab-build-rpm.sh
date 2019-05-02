set -x -e -o pipefail

export QA_RPATHS=$[ 0x0001 ]

wget https://bintray.com/wand/general-rpm/rpm -O bintray-wand-general-rpm.repo
mv bintray-wand-general-rpm.repo /etc/yum.repos.d/

if [ "$1" = "centos7" ]; then
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
fi

if [ "$1" = "centos6" ]; then
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm
        yum install -y epel-rpm-macros
fi

if [[ "$1" =~ fedora* ]]; then
        dnf install -y rpm-build rpmdevtools
        dnf group install -y "C Development Tools and Libraries"
        dnf builddep -y rpm/libwandder1.spec
else
        yum install -y rpm-build yum-utils rpmdevtools which
        yum groupinstall -y 'Development Tools'
        yum-builddep -y rpm/libwandder1.spec
fi

rpmdev-setuptree

./bootstrap.sh && ./configure && make dist
cp libtrace-*.tar.gz ~/rpmbuild/SOURCES/${CI_COMMIT_REF_NAME}.tar.gz
cp rpm/libtrace4.spec ~/rpmbuild/SPECS/

cd ~/rpmbuild && rpmbuild -bb --define "debug_package %{nil}" SPECS/libtrace4.spec

