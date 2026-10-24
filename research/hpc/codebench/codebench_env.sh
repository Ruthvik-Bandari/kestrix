# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Sourced by the code benchmark jobs: offline Python from the shared environment, the code tree being measured
# (KESTRIX_CODE, default ~/kestrix-codebench, synced by research/hpc/codebench/codebench_sync.sh), private files, one BLAS thread.
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
CODE="${KESTRIX_CODE:-$HOME/kestrix-codebench}"
export PYTHONPATH="$CODE/src:$CODE/packages/kestrix-scan/src:$CODE"
if [ -f "$CODE/CODEBENCH_SHA" ]; then export KESTRIX_CODEBENCH_SHA="$(cat "$CODE/CODEBENCH_SHA")"; fi
umask 077
cd "$CODE"
CB="${KESTRIX_CODEBENCH:-/scratch/$USER/kestrix/codebench}"
VUL="/scratch/$USER/kestrix/vul"
mkdir -p "$CB/logs"
cb() { /usr/bin/time -f "$1: %e s, max RSS %M KB" "$HOME/kestrix/.venv/bin/python" -m kestrixcodebench "${@:2}"; }
