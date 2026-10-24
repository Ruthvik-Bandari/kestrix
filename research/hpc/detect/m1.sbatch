#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#SBATCH --job-name=kestrix-m1
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu
#SBATCH --gres=gpu:a100:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=08:00:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
# M1 LoRA fine-tuning of the B2 base model on an A100. bf16 keeps seeds comparable; a V100 would fall
# back to fp16 without loss scaling, which is unstable for this trainer. Smoke first to measure memory and
# throughput:  sbatch research/hpc/detect/m1.sbatch --max-steps 5      Full run:  sbatch research/hpc/detect/m1.sbatch --train-seed 1
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
source "$HOME/kestrix/research/hpc/common/gpu_env.sh"
export KESTRIX_B2_SNAPSHOT="/scratch/$USER/kestrix/models/Qwen2.5-Coder-7B-Instruct@c03e6d358207e414f1eca0bb1891e29f1db0e242"
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader
uv run --no-sync python -m kestrixbench train-m1 --root "${KESTRIX_DATA:-/scratch/$USER/kestrix/data}" "$@"
