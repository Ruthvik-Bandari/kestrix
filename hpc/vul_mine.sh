#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Fetch the GHSA fix commits listed by `sbatch hpc/vul_extend.sbatch targets`. Transfer node only
# (internet, CentOS 7, no Slurm), detached:
#   ssh explorer-xfer 'cd ~/kestrix && nohup bash -l hpc/vul_mine.sh > /scratch/$USER/kestrix/logs/vul-mine.log 2>&1 &'
# Anonymous HTTPS partial clones (--filter=blob:none --depth=2), then only the needed blobs. No GitHub
# API calls. 8 repositories at a time, at most one git request per second overall, backoff on errors,
# 300 s per git call, 500 MB per repository. Resumable: re-run the same command after an interruption.
# Extra arguments pass through (e.g. --limit 20 for a smoke run). Standard library only.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
module load git/2.19.0  # system git there is 1.8, too old for partial clone
VUL="${KESTRIX_VUL:-/scratch/$USER/kestrix/vul}"
umask 077
mkdir -p "$VUL/mine" "/scratch/$USER/kestrix/logs"
df -h "$VUL" | tail -1
PYTHONPATH=src:packages/kestrix-scan/src uv run --no-project --python 3.12 python -m kestrixvul mine-fetch --root "$VUL" "$@"
