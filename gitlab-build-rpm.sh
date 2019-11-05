set -x -e -o pipefail

export QA_RPATHS=$[ 0x0001 ]
SOURCENAME=`echo ${CI_COMMIT_REF_NAME} | cut -d '-' -f 1`


DISTRO=fedora
if [ "$1" = "centos7" ]; then
        DISTRO=centos
fi

if [ "$1" = "centos6" ]; then
        DISTRO=centos
fi

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

yum install -y wget make gcc

if [ "$1" = "centos7" ]; then
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm || true
fi

if [ "$1" = "centos6" ]; then
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm || true
        yum install -y epel-rpm-macros
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

./bootstrap.sh && ./configure && make dist
cp libtrace-*.tar.gz ~/rpmbuild/SOURCES/${SOURCENAME}.tar.gz
cp rpm/libtrace4.spec ~/rpmbuild/SPECS/
#cp rpm/libtrace4-dag.spec ~/rpmbuild/SPECS/

cd ~/rpmbuild && rpmbuild -bb --define "debug_package %{nil}" SPECS/libtrace4.spec

#if [[ "$1" =~ centos* ]]; then
#	cd ~/rpmbuild && rpmbuild -bb --define "debug_package %{nil}" SPECS/libtrace4-dag.spec
#fi

