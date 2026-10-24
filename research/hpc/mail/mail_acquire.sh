#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Email benchmark corpora. Run on the transfer node (internet, CentOS 7, no Slurm), detached:
#   ssh explorer-xfer 'mkdir -p /scratch/$USER/kestrix/mailbench/logs && cd ~/kestrix && nohup bash -l research/hpc/mail/mail_acquire.sh > /scratch/$USER/kestrix/mailbench/logs/acquire.log 2>&1 &'
# About 0.5 GB: Nazario phishing mboxes, SpamAssassin tarballs and the Enron May 2015 tarball (443 MB).
# Standard library only, through a uv-managed Python. raw/ is 0700 and its files 0600; the manifest
# (manifests/mailbench-manifest.json) records URL, size, SHA-256 and licence per file.
# /scratch is purged on the first Tuesday of each month (next: 2026-11-03); the manifest makes every file re-fetchable.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
MB="${KESTRIX_MAILBENCH:-/scratch/$USER/kestrix/mailbench}"
umask 077
mkdir -p "$MB/logs"
df -h "$MB" | tail -1
PYTHONPATH=src uv run --no-project --python 3.12 python -m kestrixmailbench acquire --root "$MB" "$@"
ls -l "$MB/raw" "$MB/manifests"
