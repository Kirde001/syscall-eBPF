Name:           syscall-inspector
Version:        1.0
Release:        1
Summary:        eBPF-based syscall data collector
License:        GPL
Group:          System/Base
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz

Requires:       python3-module-bcc

%description
An eBPF-based service for monitoring suspicious syscalls.

%package -n alterator-syscall-inspector
Summary:        Alterator module for Syscall Inspector
Group:          System/Configuration
Requires:       %{name} = %{version}-%{release}
Requires:       alterator

%description -n alterator-syscall-inspector
Alterator module to view data collected by the Syscall Inspector service.

%prep
%setup -q -n %{_builddir_name}

%build

%install
make install DESTDIR=%{buildroot}

%files
/usr/sbin/syscall-inspector.py
/usr/lib/systemd/system/syscall-inspector.service
%config(noreplace) /etc/syscall-inspector/config.conf

%files -n alterator-syscall-inspector
/usr/share/alterator/applications/syscall-inspector.desktop
/usr/share/applications/syscall-inspector-launcher.desktop
/usr/share/alterator/ui/syscall-inspector/
/usr/lib/alterator/backend3/syscall-inspector

%post
%systemd_post syscall-inspector.service

%preun
%systemd_preun syscall-inspector.service

%postun
%systemd_postun_with_restart syscall-inspector.service
