#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul-qc
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=32G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
# Offline. Re-verifies every pinned archive and checkout, streams the CVEfixes and MoreFixes dumps
# into private work/<source>.sqlite (both in parallel; skipped when already built from the pinned
# file), and writes the aggregate reports/qc.json. Run hpc/vul_acquire.sh first. Pass --rebuild to reload.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1
umask 077
VUL="${KESTRIX_VUL:-/scratch/$USER/kestrix/vul}"
/usr/bin/time -f "qc: %e s, max RSS %M KB" uv run --no-sync python -m kestrixvul qc --root "$VUL" "$@"
ls -l "$VUL/work" "$VUL/reports"
