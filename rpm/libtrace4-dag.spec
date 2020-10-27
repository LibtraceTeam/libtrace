Name:           libtrace4-dag
Version:        4.0.10
Release:        1%{?dist}
Summary:        C Library for capturing and analysing network packets

License:        LGPLv3
URL:            https://github.com/LibtraceTeam/libtrace
Source0:        https://github.com/LibtraceTeam/libtrace/archive/%{version}.tar.gz

BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: bison
BuildRequires: doxygen
BuildRequires: flex
BuildRequires: libpcap-devel
BuildRequires: numactl-devel
BuildRequires: ncurses-devel
BuildRequires: openssl-devel
BuildRequires: libyaml-devel
BuildRequires: libwandder1-devel
BuildRequires: libwandio1-devel
BuildRequires: dpdk-wand-devel
BuildRequires: dag-devel

Requires: dpdk-wand
Provides: libtrace4%{?_isa} = %{version}-%{release}

%define _unpackaged_files_terminate_build 0

%description
libtrace is a library for trace processing. It supports multiple input
methods, including device capture, raw and gz-compressed trace, and sockets;
and multiple input formats, including pcap and DAG.

libtrace is developed by the WAND Network Research Group at Waikato
University in New Zealand.

%prep
%setup -q -n libtrace-%{version}

%build
%configure --disable-static --with-man=yes --mandir=%{_mandir} --with-dpdk=yes --with-dag=yes
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%license COPYING
%{_libdir}/libtrace.so.*


%changelog
* Fri Sep 20 2019 Shane Alcock <salcock@waikato.ac.nz> - 4.0.10-1
- Created DAG-specific spec file for 4.0.10 release

