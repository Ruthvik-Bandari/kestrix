#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Fetch the test2 fix commits. Transfer node only (internet, no Slurm), detached:
#   ssh explorer-xfer 'cd ~/kestrix-codebench2 && nohup bash -l hpc/codebench2_fetch.sh > /scratch/$USER/kestrix/codebench2/logs/fetch.log 2>&1 &'
# Anonymous HTTPS partial clones (--filter=blob:none --depth=2) then only the needed blobs, at most 3 changed source
# files per commit, no GitHub API call; resumable (re-run after an interruption). Extra arguments pass through.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
module load git/2.19.0  # system git there is 1.8, too old for partial clone
CODE="${KESTRIX_CODE:-$HOME/kestrix-codebench2}"
CB="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench2}"
umask 077
df -h "$CB" | tail -1
cd "$CODE"
PYTHONPATH="$CODE/src:$CODE/packages/kestrix-scan/src" uv run --no-project --python 3.12 python -m kestrixcodebench test2-fetch --root "$CB" "$@"
