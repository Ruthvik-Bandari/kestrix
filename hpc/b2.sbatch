#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-b2
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:v100-sxm2:1
#SBATCH --cpus-per-task=4
#SBATCH --mem=48G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
# B2 (unmodified open model) on the train + development cases: a 7B model in fp16 fits a 32 GB V100.
# Needs hpc/fetch_model.sh and `bash hpc/setup_env.sh gpu`. Add --locked only for the final test run.
set -euo pipefail
source "$HOME/kestrix/hpc/engine.sh"
source "$HOME/kestrix/hpc/gpu_env.sh"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
export KESTRIX_B2_SNAPSHOT="/scratch/$USER/kestrix/models/Qwen2.5-Coder-7B-Instruct@c03e6d358207e414f1eca0bb1891e29f1db0e242"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
uv run --no-sync python -m kestrixbench evaluate --root "$DATA" --es-url "$ES_URL" --system b2 "$@"
