# Packaging and Distribution

This repository supports package delivery for:
- Debian family (`.deb` via APT repo)
- RHEL family (`.rpm` via YUM repo)
- Python (`wheel` and `sdist`, with optional PyPI publish as `meraki-fluxgen`)

## Supported Linux Flavors

- Kali (APT)
- Ubuntu (APT)
- Parrot (APT)
- Debian (APT)
- CentOS Stream / RHEL-like (RPM)

## Build and Publish Pipeline

GitHub Actions workflow: `.github/workflows/release-packages.yml`

On pull requests and `main` pushes:
- Run unit tests (Python 3.10, 3.11, 3.12)
- Build Python artifacts (`sdist`, `wheel`)
- Build Debian package (`.deb`)
- Build RPM package (`.rpm`, `.src.rpm`)

On version tags (`v*`):
- Publish release artifacts to GitHub Releases
- Publish APT metadata/content to `apt-repo` branch
- Publish YUM metadata/content to `yum-repo` branch
- Publish Python artifacts to PyPI via trusted publishing

## Required Repository Setup

1. Enable GitHub Actions permissions to write contents.
2. Configure environment `pypi` for trusted publishing (if using PyPI).
3. Optionally set secret `APT_GPG_PRIVATE_KEY` to keep stable APT signing keys.
   - If unset, workflow generates an ephemeral key per tag.

## Local Build Commands

### Python artifacts

```bash
python3 -m pip install --upgrade build
python3 -m build
```

### Debian package

```bash
sudo apt-get update
sudo apt-get install -y build-essential fakeroot devscripts debhelper dh-python pybuild-plugin-pyproject python3-all
dpkg-buildpackage -us -uc -b
```

### RPM package

```bash
dnf -y install rpm-build rpmdevtools pyproject-rpm-macros python3-devel
rpmbuild -ba packaging/rpm/fluxgen.spec
```

### APT repo metadata

```bash
./scripts/packaging/build_apt_repo.sh apt-repo stable main
```

### YUM repo metadata

```bash
./scripts/packaging/build_yum_repo.sh yum-repo
```
