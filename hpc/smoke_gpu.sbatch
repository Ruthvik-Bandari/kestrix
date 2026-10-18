#!/bin/bash -l
#SBATCH --job-name=kestrix-smoke
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu-short
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=2
#SBATCH --mem=4G
#SBATCH --time=00:05:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
set -euo pipefail
hostname
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv
module load cuda/12.8.0 python/3.13.5
nvcc --version | tail -1
python3 --version
