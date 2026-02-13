#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${1:-apt-repo}"
DIST="${2:-stable}"
COMPONENT="${3:-main}"

mkdir -p "${REPO_DIR}/pool/${COMPONENT}"
mkdir -p "${REPO_DIR}/dists/${DIST}/${COMPONENT}/binary-all"
mkdir -p "${REPO_DIR}/dists/${DIST}/${COMPONENT}/binary-amd64"
mkdir -p "${REPO_DIR}/dists/${DIST}/${COMPONENT}/binary-arm64"

find "${REPO_DIR}/pool/${COMPONENT}" -type f -name '*.deb' -delete
cp dist/*.deb "${REPO_DIR}/pool/${COMPONENT}/"

pushd "${REPO_DIR}" >/dev/null

dpkg-scanpackages --arch all "pool/${COMPONENT}" > "dists/${DIST}/${COMPONENT}/binary-all/Packages"
dpkg-scanpackages --arch amd64 "pool/${COMPONENT}" > "dists/${DIST}/${COMPONENT}/binary-amd64/Packages"
dpkg-scanpackages --arch arm64 "pool/${COMPONENT}" > "dists/${DIST}/${COMPONENT}/binary-arm64/Packages"

gzip -kf "dists/${DIST}/${COMPONENT}/binary-all/Packages"
gzip -kf "dists/${DIST}/${COMPONENT}/binary-amd64/Packages"
gzip -kf "dists/${DIST}/${COMPONENT}/binary-arm64/Packages"

cat > "dists/${DIST}/Release" <<EOF
Origin: Fluxgen
Label: Fluxgen APT Repository
Suite: ${DIST}
Codename: ${DIST}
Date: $(date -Ru)
Architectures: amd64 arm64 all
Components: ${COMPONENT}
Description: Fluxgen - Multi-client traffic generator
EOF

{
  echo "MD5Sum:"
  while IFS= read -r f; do
    size=$(stat -c%s "${f}")
    md5=$(md5sum "${f}" | awk '{print $1}')
    echo " ${md5} ${size} ${f}"
  done < <(find "dists/${DIST}/${COMPONENT}" -type f \( -name "Packages" -o -name "Packages.gz" \) | sort)
  echo "SHA256:"
  while IFS= read -r f; do
    size=$(stat -c%s "${f}")
    sha=$(sha256sum "${f}" | awk '{print $1}')
    echo " ${sha} ${size} ${f}"
  done < <(find "dists/${DIST}/${COMPONENT}" -type f \( -name "Packages" -o -name "Packages.gz" \) | sort)
} >> "dists/${DIST}/Release"

touch .nojekyll

popd >/dev/null
