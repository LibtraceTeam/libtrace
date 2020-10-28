Name:           libtrace4
Version:        4.0.15
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
BuildRequires: libwandder2-devel
BuildRequires: libwandio1-devel
BuildRequires: dpdk-devel

Requires: dpdk
Provides: libtrace4

%description
libtrace is a library for trace processing. It supports multiple input
methods, including device capture, raw and gz-compressed trace, and sockets;
and multiple input formats, including pcap and DAG.

libtrace is developed by the WAND Network Research Group at Waikato
University in New Zealand.

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       dpdk-devel

%package        tools
Summary:        Helper utilities for use with the %{name} library
Requires:       %{name}%{?_isa} = %{version}-%{release}, libpacketdump4%{?_isa} = %{version}-%{release}, dpdk

%package -n     libpacketdump4
Summary:        Network packet parsing and human-readable display library
Requires:       %{name}%{?_isa} = %{version}-%{release}

%package -n     libpacketdump4-devel
Summary:        Development files for libpacketdump
Requires:        %{name}-devel%{?_isa} = %{version}-%{release}, libpacketdump4%{?_isa} = %{version}-%{release}

%description devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.


%description tools
%{name} is a library for trace processing. These tools perform many common
tasks that are required when analysing and manipulating network traces.

Multiple input methods and formats are supported including device capture,
raw and gz-compressed traces, and sockets.

libtrace is developed by the WAND Network Research Group at Waikato
University in New Zealand.

%description -n libpacketdump4
libpacketdump provides a library which can parse packets and display the
packet contents in a nice human-readable form. The output is similar to that
produced by tcpdump, although the formatting is somewhat more verbose.

libpacketdump is developed by the WAND Network Research Group at Waikato
University in New Zealand.

%description -n libpacketdump4-devel
This package contains development headers and other ancillary files for
the libpacketdump library.

libpacketdump provides a library which can parse packets and display the
packet contents in a nice human-readable form. The output is similar to that
produced by tcpdump, although the formatting is somewhat more verbose.

libpacketdump is developed by the WAND Network Research Group at Waikato
University in New Zealand.

%prep
%setup -q -n libtrace-%{version}

%build
%configure --disable-static --with-man=yes --mandir=%{_mandir} --with-dpdk=yes --with-dag=no
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

%files devel
%{_includedir}/libtrace*
%{_libdir}/libtrace.so
%{_mandir}/man3/*

%files tools
%{_bindir}/*
%{_mandir}/man1/*

%files -n libpacketdump4
%{_libdir}/libpacketdump/*.so
%{_libdir}/libpacketdump/*.protocol
%{_libdir}/libpacketdump.so.*

%files -n libpacketdump4-devel
%{_libdir}/libpacketdump.so
%{_includedir}/libpacketdump.h


%changelog
* Wed Oct 28 2020 Shane Alcock <salcock@waikato.ac.nz> - 4.0.15-1
- Updated for 4.0.15 release

* Wed Sep 2 2020 Shane Alcock <salcock@waikato.ac.nz> - 4.0.14-2
- Remove dpdk-wand dependencies from libpacketdump

* Thu Aug 6 2020 Shane Alcock <salcock@waikato.ac.nz> - 4.0.14-1
- Updated for 4.0.14 release

* Fri Jun 26 2020 Shane Alcock <salcock@waikato.ac.nz> - 4.0.13-2
- Rebuild for Centos 8.2 release

* Tue May 26 2020 Shane Alcock <salcock@waikato.ac.nz> - 4.0.13-1
- Updated for 4.0.13 release

* Fri Mar 27 2020 Shane Alcock <salcock@waikato.ac.nz> - 4.0.12-1
- Updated for 4.0.12 release

* Thu Feb 13 2020 Shane Alcock <salcock@waikato.ac.nz> - 4.0.11-1
- Updated for 4.0.11 release

* Wed Nov 6 2019 Shane Alcock <salcock@waikato.ac.nz> - 4.0.10-1
- Go back to relying on standard DPDK packages

* Thu Sep 19 2019 Shane Alcock <salcock@waikato.ac.nz> - 4.0.10-1
- Updated for 4.0.10 release

* Fri Jul 26 2019 Shane Alcock <salcock@waikato.ac.nz> - 4.0.9-2
- Attempt to fix dpdk / dpdk-wand conflicts in subpackages

* Mon Jul 15 2019 Shane Alcock <salcock@waikato.ac.nz> - 4.0.9-1
- Updated for 4.0.9 release

* Mon Jul 1 2019 Shane Alcock <salcock@waikato.ac.nz> - 4.0.8-1
- Updated for 4.0.8 release

* Thu May 2 2019 Shane Alcock <salcock@waikato.ac.nz> - 4.0.7-1
- First libtrace package
