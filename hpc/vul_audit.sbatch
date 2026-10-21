#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-vul-audit
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h200:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=128G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix/vul/logs/%x-%j.out
# Label audit by two open-weight Apache-2.0 reviewers on one H200 (src/kestrixvul/audit_llm.py):
# Granite-34B-Code-Instruct, then Qwen2.5-Coder-32B-Instruct, then Qwen adjudicates the disagreements.
# bf16, greedy, offline. Smoke first: sbatch --time=01:00:00 hpc/vul_audit.sbatch --limit 5
# The full run (no arguments) also combines the reviews and writes reports/audit.json. Resumable.
# Needs hpc/fetch_vul_audit_models.sh (transfer node) and the venv-gpu environment.
set -euo pipefail
source "$HOME/kestrix/hpc/gpu_env.sh"
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
export PYTHONPATH="$HOME/kestrix/src:$HOME/kestrix/packages/kestrix-scan/src"
umask 077
VUL="${KESTRIX_VUL:-/scratch/$USER/kestrix/vul}"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
/usr/bin/time -f "audit-review: %e s, max RSS %M KB" uv run --no-sync python -m kestrixvul audit-review --root "$VUL" "$@"
