#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Install the comparison tools on the transfer node into a private prefix (no project environment touched):
# zizmor (MIT) and checkov (Apache-2.0) from PyPI, hadolint (GPL-3.0) as a standalone binary. All three are run only
# as external programs for measurement; none is bundled, linked or copied into Kestrix.
set -euo pipefail
umask 077
B=/scratch/bandari.ru/kestrix/iac/tools
mkdir -p "$B" && cd "$B"
export PATH="$HOME/.local/bin:$PATH"
export UV_CACHE_DIR=/scratch/bandari.ru/kestrix/uv-cache TMPDIR=/scratch/bandari.ru/kestrix/iac  # the home quota is small
if [ ! -x venv/bin/checkov ]; then
  rm -rf venv
  uv venv --python /home/bandari.ru/.local/share/uv/python/cpython-3.12.15-linux-x86_64-gnu/bin/python3.12 venv
  uv pip install --python venv/bin/python --only-binary :all: zizmor checkov
fi
if [ ! -x hadolint ]; then
  curl -sSfL -o hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
  chmod +x hadolint
fi
venv/bin/zizmor --version
venv/bin/checkov --version
./hadolint --version
echo TOOLS_DONE
