#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Finishes `setup_env.sh gpu` offline on a CPU node. Installing torch and its CUDA libraries onto scratch takes
# longer than the login node lets a process run, so download on the login node, then install here:
#   ssh explorer 'cd ~/kestrix && bash research/hpc/common/setup_env.sh gpu'   # downloads into the uv cache; may be killed
#   ssh explorer 'cd ~/kestrix && sbatch research/hpc/common/install_gpu_env.sbatch'
#SBATCH --job-name=kestrix-gpu-install
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=8G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1 UV_LINK_MODE=copy
bash research/hpc/common/setup_env.sh gpu
source research/hpc/common/gpu_env.sh
uv run --no-sync python -c "import torch, transformers; print('torch', torch.__version__, 'transformers', transformers.__version__)"
