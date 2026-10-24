#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Sync the round-2 code to /scratch/$USER/kestrix/vul2-code on the cluster (never ~/kestrix; the home quota is full) and record what was synced in GIT_SHA:
# the git HEAD plus a hash of the synced files, so uncommitted changes get their own id. Run from the repo root:
#   bash research/hpc/vul/vul2_sync.sh [HOST] [DIR]      (default explorer-01, /scratch/bandari.ru/kestrix/vul2-code)
set -euo pipefail
cd "$(dirname "$0")/../../.."
HOST="${1:-explorer-01}"
DIR="${2:-/scratch/bandari.ru/kestrix/vul2-code}"
FILES=(src packages/kestrix-scan/src research/hpc)
COPYFILE_DISABLE=1 tar --no-xattrs -czf - --exclude '__pycache__' --exclude '.DS_Store' "${FILES[@]}" |
  ssh "$HOST" "mkdir -p $DIR && cd $DIR && rm -rf src packages hpc research/hpc && tar -xzf -"
SHA="$(git rev-parse --short HEAD)+$(find "${FILES[@]}" -type f -not -path '*/__pycache__/*' -not -name .DS_Store | LC_ALL=C sort | xargs shasum | shasum | cut -c1-8)"
ssh "$HOST" "echo '$SHA' > $DIR/GIT_SHA"
echo "synced $SHA to $HOST:$DIR"
