# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Sourced by the modern-mail jobs: code in /scratch/$USER/kestrix/mailmodern-code (the home quota was full), data under
# /scratch/$USER/kestrix/mailmodern (0700). Self-contained: never touches ~/kestrix or its GIT_SHA; the shared virtual
# environment is only read.
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
CODE="${KESTRIX_CODE:-/scratch/$USER/kestrix/mailmodern-code}"
export PYTHONPATH="$CODE/src:$CODE/packages/kestrix-scan/src"
umask 077
cd "$CODE"
MB="${KESTRIX_MAILBENCH:-/scratch/$USER/kestrix/mailmodern}"
mkdir -p "$MB/logs"
mm() { /usr/bin/time -f "$1: %e s, max RSS %M KB" "$HOME/kestrix/.venv/bin/python" -m kestrixmailbench.modern "${@:2}" --root "$MB"; }
