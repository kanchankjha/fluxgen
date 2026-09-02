Name:           fluxgen
Version:        2.0.0
Release:        1%{?dist}
Summary:        Multi-client traffic generator inspired by hping3

License:        MIT
URL:            https://github.com/kanchankjha/fluxgen
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros

Requires:       python3dist(psutil)
Requires:       python3dist(pyyaml)
Requires:       python3dist(scapy)

%description
fluxgen is a multi-client traffic generator that simulates many clients on
a single Linux host, sending customizable network traffic with spoofed IP/MAC
addresses from the same subnet.

%prep
%autosetup -n %{name}-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files fluxgen

%files -f %{pyproject_files}
%{_bindir}/fluxgen
%license LICENSE
%doc README.md

%changelog
* Wed Sep 02 2026 Kanchan Kumar Jha <kanchankjha@gmail.com> - 2.0.0-1
- Add independent dual-stack responder mode
- Add bidirectional synthetic client transactions and application responses

* Wed Sep 02 2026 Kanchan Kumar Jha <kanchankjha@gmail.com> - 1.2.0-1
- Add 100 application-shaped traffic profiles and application selection

* Fri Aug 28 2026 Kanchan Kumar Jha <kanchankjha@gmail.com> - 1.1.2-1
- Add configurable starting index for simulated client IP allocation

* Wed Aug 19 2026 Kanchan Kumar Jha <kanchankjha@gmail.com> - 1.1.1-1
- Add paired normal and structure-aware fuzzed packet headers
- Add ARP, VRRPv2/v3, and OSPFv2/v3 protocol generation

* Thu Aug 13 2026 Kanchan Kumar Jha <kanchankjha@gmail.com> - 1.1.0-1
- Add Beast traffic mode
- Fix IPv6 interface prefix detection across Linux formats

* Fri Feb 13 2026 Kanchan Kumar Jha <kanchankjha@gmail.com> - 0.1.0-1
- Initial RPM package
