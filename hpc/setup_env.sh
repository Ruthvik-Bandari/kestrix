#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Run on the login node (Rocky 9, same as the compute nodes) after cloning or pulling:
#   ssh explorer 'cd ~/kestrix && bash hpc/setup_env.sh'       # CPU jobs
#   ssh explorer 'cd ~/kestrix && bash hpc/setup_env.sh gpu'   # adds torch/transformers for B2/M1
#   ssh explorer 'cd ~/kestrix && bash hpc/setup_env.sh mail'  # adds numpy for the email benchmark
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
if [ "${1:-}" = "gpu" ]; then
  # torch + CUDA libraries are several GB: keep the GPU environment and uv's cache on scratch, not
  # in the home quota. Scratch is purged monthly; re-run this script after a purge.
  source "$(dirname "$0")/gpu_env.sh"
  uv sync --frozen --no-dev --group gpu
elif [ "${1:-}" = "mail" ]; then
  uv sync --frozen --no-dev --extra research   # numpy for the email benchmark (kestrixmailbench)
else
  uv sync --frozen --no-dev
fi
