# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Sourced by the mail benchmark jobs: offline uv, private files, one BLAS thread, code version marker.
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
export PYTHONPATH="$HOME/kestrix/src:$HOME/kestrix/packages/kestrix-scan/src"
# MAILBENCH_SHA is written by the code sync (HEAD plus a hash of the synced files); GIT_SHA stays untouched.
if [ -f "$HOME/kestrix/MAILBENCH_SHA" ]; then export KESTRIX_GIT_SHA="$(cat "$HOME/kestrix/MAILBENCH_SHA")"; fi
umask 077
cd "$HOME/kestrix"
MB="${KESTRIX_MAILBENCH:-/scratch/$USER/kestrix/mailbench}"
mkdir -p "$MB/logs"
mb() { /usr/bin/time -f "$1: %e s, max RSS %M KB" uv run --no-sync python -m kestrixmailbench "${@:2}"; }
