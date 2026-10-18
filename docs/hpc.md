# HPC runbook (Northeastern Explorer)

## Access

Add an `explorer` host alias to `~/.ssh/config` pointing at `login.explorer.northeastern.edu`, and
install a key with `ssh-copy-id`. The repository is cloned at `$HOME/kestrix`; data lives under
`/scratch/$USER/kestrix/`. `uv` is installed per user (`python3 -m pip install --user uv` after
`module load python/3.13.5`).

## Jobs

Every job charges the Slurm account `aai6610.202610` (`#SBATCH --account`).

| Job | Partition | Resources | Purpose |
| --- | --- | --- | --- |
| `hpc/smoke_gpu.sbatch` | `gpu-short` | 1 GPU, 5 min | Record GPU, driver, CUDA and Python |
| `hpc/setup_env.sh [gpu]` | login node | n/a | Build the locked environment (`uv sync --frozen`) once per pull; `gpu` adds torch 2.6 (CUDA 12.4) and transformers for B2 and M1 |
| `hpc/acquire.sh` | transfer node | n/a | Fetch pinned sources and write manifests (standard library only) |
| `hpc/qc.sbatch` | `short` | 2 CPU, 8 GB, 1 h | Offline: verify manifests, write aggregate QC reports |
| `hpc/fetch_engine.sh` | transfer node | n/a | Download Elasticsearch 8.19.3 (Linux tarball, SHA-512 pinned in the script) to scratch |
| `hpc/replay.sbatch` | `short` | 4 CPU, 12 GB, 2 h | Start the pinned engine for this job only, replay every supported Sigma rule against the SigmaHQ regression and OTRF pools, and write `reports/replay-positives.json` |
| `hpc/review_split.sbatch` | `short` | 1 CPU, 4 GB, 30 min | Write the private OTRF review sheet (`review/`, mode 0600), report review progress, and write the split preview |
| `hpc/variants.sbatch [manifest]` | `short` | 4 CPU, 12 GB, 2 h | Generate and verify the impairment cases for every root in the split (`benchmark/cases/`, private), and write `reports/variants.json`. It uses the frozen split, or a manifest path relative to the data root |
| `hpc/evaluate.sbatch <system> [--locked]` | `short` | 4 CPU, 12 GB, 4 h | Score a repair system on the train and development cases and write `reports/eval-<system>.json`. `--locked` adds the test split; run it once, after a system is chosen |
| `hpc/fetch_model.sh` | transfer node | n/a | Download the B2 base model at its pinned revision (weights, config and tokenizer only) and write `MANIFEST.sha256` |
| `hpc/b2.sbatch [--locked]` | `gpu`, V100-SXM2 32 GB | 4 CPU, 48 GB, 8 h | Evaluate B2 (unmodified Qwen2.5-Coder-7B-Instruct, fp16, greedy decoding) on the cases; needs `bash hpc/setup_env.sh gpu` |
| `hpc/fetch_history.sh` | transfer node | n/a | Full-history bare clone of SigmaHQ for natural-fault mining; it checks that the pinned commit is present |
| `hpc/natural.sbatch` | `short` | 4 CPU, 12 GB, 2 h | Mine SigmaHQ history up to the pin (`reports/natural-mining.json`) and verify every pair against the global pool of verified positives (`reports/natural-verified.json`). Run it before `review_split.sbatch`; `variants.sbatch` then writes the natural cases |
| `hpc/sft.sbatch` | `short` | 4 CPU, 12 GB, 2 h | Build M1 training examples from the train and development cases (never test) into `sft/` |
| `hpc/m1.sbatch [--max-steps N] [--train-seed S]` | `gpu`, A100 | 8 CPU, 64 GB, 8 h | LoRA fine-tuning (bf16). Smoke with `--max-steps 5` first to measure memory and throughput. Writes the adapter to `models/` and `reports/m1-*-training.json` |
| `hpc/m1_eval.sbatch <adapter> [--locked]` | `gpu`, V100-SXM2 | 4 CPU, 48 GB, 8 h | Evaluate base model plus adapter, the same way as B2 |

The cluster has no Docker, so jobs run Elasticsearch from Elastic's official tarball with its
bundled JDK. That is the same 8.19.3 release the local Docker image pins by digest. The engine
listens on `127.0.0.1` with security disabled, uses a data directory scoped to the job, and is
stopped and deleted when the job ends (`hpc/engine.sh`, sourced by the engine jobs). Other users on the same compute node could reach it while it
runs, so it may hold only public benchmark data.

Compute nodes have no internet access. The login node (Rocky 9, like the compute nodes) builds the
environment. Data, model and dataset downloads run on the transfer node, `xfer.discovery.neu.edu`, which shares `/home` and
`/scratch` with Explorer: `ssh explorer-xfer 'cd ~/kestrix && bash -l hpc/acquire.sh'`. The transfer node runs
CentOS 7 (glibc 2.17), so never build the project environment there. Jobs then
run offline. Submit them from the repository root on the login node with `sbatch hpc/<job>.sbatch`.
Logs go to `/scratch/$USER/kestrix/logs/`.

## Choosing hardware by task

| Task | Hardware | Partition |
| --- | --- | --- |
| Download | transfer node | n/a |
| QC, cleaning, variant generation, Elasticsearch replay | CPU | `short` (48 h), `sharing` (1 h) |
| Smoke tests, B1 retrieval, small B2 inference | V100 32 GB or T4 | `gpu-short` (2 h), `gpu` (8 h) |
| M1 LoRA/QLoRA on a 7B to 14B model | A100 | `gpu` with `--gres=gpu:a100:1` |
| 24B to 32B comparison, long contexts, or A100 throughput measured too low | H200 (B200 if offered) | `gpu` with `--gres=gpu:h200:1` |

Always measure peak memory and throughput on a short run first, then request the smallest GPU
that fits. Measured on 2026-10-14: the `gpu` partitions expose V100 (PCIe and SXM2), T4, A100 and
H200 nodes; the smoke job ran on a Tesla V100-SXM2-32GB, driver 545.23.08, with modules
`cuda/12.8.0` and `python/3.13.5` available.

## Constraints

- No work on login nodes. Jobs only, via Slurm.
- The home quota cannot hold torch and its CUDA libraries. The GPU environment (`venv-gpu`) and uv's cache live on scratch (`hpc/gpu_env.sh`); re-run `bash hpc/setup_env.sh gpu` after a scratch purge.
- `/scratch` is purged on the first Tuesday of each month, and the cluster is unavailable during
  that maintenance. Sources are re-fetchable from pins; anything that must survive goes to `/work`.
- Batch scripts start with `#!/bin/bash -l` so `module` is available.

Policy context: `docs/data/policy.md`, `docs/data/compliance.md`.
