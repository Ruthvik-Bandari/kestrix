# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Sourced by the round-2 GPU jobs: code in /scratch/$USER/kestrix/vul2-code (never ~/kestrix), the GPU venv on scratch, offline.
CODE="${KESTRIX_CODE:-/scratch/$USER/kestrix/vul2-code}"
VUL2="${KESTRIX_VUL2:-/scratch/$USER/kestrix/vul2}"
PY="/scratch/$USER/kestrix/venv-gpu/bin/python"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
export PYTHONPATH="$CODE/src:$CODE/packages/kestrix-scan/src"
if [ -f "$CODE/GIT_SHA" ]; then export KESTRIX_GIT_SHA="$(cat "$CODE/GIT_SHA")"; fi
umask 077
mkdir -p "$VUL2/logs" "$VUL2/runs"
cd "$CODE"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
