#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# C5 vulnerability data. Run on the transfer node (internet, CentOS 7, no Slurm), detached:
#   ssh explorer-xfer 'cd ~/kestrix && nohup bash -l hpc/vul_acquire.sh > /scratch/$USER/kestrix/logs/vul-acquire.log 2>&1 &'
# About 19 GB (CVEfixes 12.7 GB, MoreFixes 6.5 GB) plus two git checkouts. Downloads resume.
# Standard library only, through a uv-managed Python. raw/ is 0700 and its files 0600.
# /scratch is purged on the first Tuesday of each month; the pins make every file re-fetchable.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
module load git/2.19.0  # system git there is 1.8
VUL="${KESTRIX_VUL:-/scratch/$USER/kestrix/vul}"
umask 077
mkdir -p "$VUL" "/scratch/$USER/kestrix/logs"
df -h "$VUL" | tail -1
PYTHONPATH=src uv run --no-project --python 3.12 python -m kestrixvul acquire --root "$VUL" "$@"
