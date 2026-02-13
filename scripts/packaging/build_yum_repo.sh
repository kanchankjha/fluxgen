#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${1:-yum-repo}"

mkdir -p "${REPO_DIR}"
find "${REPO_DIR}" -type f -name '*.rpm' -delete
cp dist/*.rpm "${REPO_DIR}/"

createrepo_c --update "${REPO_DIR}"
