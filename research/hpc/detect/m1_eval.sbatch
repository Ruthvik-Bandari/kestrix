#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-m1-eval
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:v100-sxm2:1
#SBATCH --cpus-per-task=4
#SBATCH --mem=48G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
# Evaluates M1 (base + LoRA adapter) like B2:  sbatch research/hpc/detect/m1_eval.sbatch m1-seed1 [--locked]
set -euo pipefail
source "$HOME/kestrix/research/hpc/detect/engine.sh"
source "$HOME/kestrix/research/hpc/common/gpu_env.sh"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
export KESTRIX_B2_SNAPSHOT="/scratch/$USER/kestrix/models/Qwen2.5-Coder-7B-Instruct@c03e6d358207e414f1eca0bb1891e29f1db0e242"
export KESTRIX_M1_ADAPTER="$DATA/models/${1:?adapter name, e.g. m1-seed1}"
uv run --no-sync python -m kestrixbench evaluate --root "$DATA" --es-url "$ES_URL" --system m1 --report-name "$1" "${@:2}"
