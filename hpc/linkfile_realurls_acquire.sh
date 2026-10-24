#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Benign full-URL sample from the Common Crawl URL index. Run on the transfer node (internet, no Slurm), detached, after
# hpc/linkfile_acquire.sh (it needs raw/majestic):
#   ssh explorer-xfer 'cd $CODE_ROOT/final && nohup bash -l hpc/linkfile_realurls_acquire.sh > /scratch/$USER/kestrix/linkfilebench/logs/acquire-cc.log 2>&1 &'
# Downloads cluster.idx (about 100 MB) and the terms page, then a few thousand range requests of about 250 KB each for index
# blocks (text of URL index lines only; no page is fetched). Standard library only. Output: raw/commoncrawl/<crawl>/ (0700/0600):
# urls.jsonl (private, never committed), manifest.json (counts), terms-of-use.html.
set -euo pipefail
# Code trees live on /scratch (the home quota was full): $CODE_ROOT/final, base (shipped rules) and one per candidate.
CODE_ROOT="${CODE_ROOT:-/scratch/$USER/kestrix/forensics2-code}"
export PATH="$HOME/.local/bin:$PATH"
LB="${KESTRIX_LINKFILEBENCH:-/scratch/$USER/kestrix/linkfilebench}"
umask 077
mkdir -p "$LB/logs"
df -h "$LB" | tail -1
PYTHONPATH=src uv run --no-project --python 3.12 python -m kestrixlinkfilebench acquire-cc --root "$LB" "$@"
ls -l "$LB"/raw/commoncrawl/*/
