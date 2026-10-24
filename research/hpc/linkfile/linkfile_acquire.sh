#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Link and file benchmark datasets. Run on the transfer node (internet, no Slurm), detached:
#   ssh explorer-xfer 'mkdir -p /scratch/$USER/kestrix/linkfilebench/logs && cd ~/kestrix-linkfile && nohup bash -l research/hpc/linkfile/linkfile_acquire.sh > /scratch/$USER/kestrix/linkfilebench/logs/acquire.log 2>&1 &'
# About 10 GB: PhiUSIIL (UCI 967, CC BY 4.0), Majestic Million (CC BY 3.0) and 20 seeded Govdocs1 zip threads.
# Standard library only, through a uv-managed Python. raw/ is 0700 and its files 0600; the manifest
# (manifests/linkfilebench-manifest.json) records URL, size, SHA-256 and license per file.
# /scratch is purged on the first Tuesday of each month (next: 2026-11-03); the manifest makes every file re-fetchable.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
LB="${KESTRIX_LINKFILEBENCH:-/scratch/$USER/kestrix/linkfilebench}"
umask 077
mkdir -p "$LB/logs"
df -h "$LB" | tail -1
PYTHONPATH=src uv run --no-project --python 3.12 python -m kestrixlinkfilebench acquire --root "$LB" "$@"
ls -l "$LB/raw" "$LB/manifests"
