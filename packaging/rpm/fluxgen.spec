Name:           fluxgen
Version:        0.1.0
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
* Fri Feb 13 2026 Kanchan Kumar Jha <kanchankjha@gmail.com> - 0.1.0-1
- Initial RPM package
