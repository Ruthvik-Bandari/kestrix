# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Sourced by the link and file benchmark jobs: offline Python, private files, one BLAS thread, code version marker.
# KESTRIX_CODE (default ~/kestrix-linkfile) is the synced source tree; the shared virtual environment stays in
# ~/kestrix (never modified), so a rule round can run its own copy of the code beside the benchmark's.
# ~/kestrix-linkfile/pylib (optional) holds extra pure-wheel dependencies, for example Pillow for EXIF.
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
CODE="${KESTRIX_CODE:-$HOME/kestrix-linkfile}"
export PYTHONPATH="$CODE/src:$CODE/packages/kestrix-scan/src:$HOME/kestrix-linkfile/pylib"
if [ -f "$CODE/LINKFILEBENCH_SHA" ]; then export KESTRIX_GIT_SHA="$(cat "$CODE/LINKFILEBENCH_SHA")"; fi
umask 077
cd "$CODE"
LB="${KESTRIX_LINKFILEBENCH:-/scratch/$USER/kestrix/linkfilebench}"
BASE_LB="/scratch/$USER/kestrix/linkfilebench"
mkdir -p "$LB/logs" "$BASE_LB/logs"
lb() { /usr/bin/time -f "$1: %e s, max RSS %M KB" "$HOME/kestrix/.venv/bin/python" -m kestrixlinkfilebench "${@:2}"; }
