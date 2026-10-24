# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Sourced by the mail benchmark jobs: offline Python, private files, one BLAS thread, code version marker.
# KESTRIX_CODE (default ~/kestrix) is the synced source tree; the shared virtual environment stays in ~/kestrix, so
# a rule round can run its own copy of the code beside the benchmark's without touching it.
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
CODE="${KESTRIX_CODE:-$HOME/kestrix}"
export PYTHONPATH="$CODE/src:$CODE/packages/kestrix-scan/src"
# MAILBENCH_SHA is written by the code sync (HEAD plus a hash of the synced files); GIT_SHA stays untouched.
if [ -f "$CODE/MAILBENCH_SHA" ]; then export KESTRIX_GIT_SHA="$(cat "$CODE/MAILBENCH_SHA")"; fi
umask 077
cd "$CODE"
MB="${KESTRIX_MAILBENCH:-/scratch/$USER/kestrix/mailbench}"
BASE_MB="/scratch/$USER/kestrix/mailbench"
mkdir -p "$MB/logs" "$BASE_MB/logs"
mb() { /usr/bin/time -f "$1: %e s, max RSS %M KB" "$HOME/kestrix/.venv/bin/python" -m kestrixmailbench "${@:2}"; }
