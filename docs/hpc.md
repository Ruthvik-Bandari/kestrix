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
| `hpc/vul_acquire.sh` | transfer node | n/a | C5 code-vulnerability data: download CVEfixes, MoreFixes, the reviewed GitHub advisories and SVEN at their pins (resumable; size, MD5 and SHA-256 checked) into `/scratch/$USER/kestrix/vul/raw` (0700) |
| `hpc/vul_qc.sbatch [--rebuild]` | `short` | 4 CPU, 32 GB, 8 h | Re-verify the pins, stream both dumps into private `vul/work/*.sqlite`, write `vul/reports/qc.json` |
| `hpc/vul_build.sbatch [candidates\|split]` | `short` | 2 CPU, 32 GB, 4 h | `candidates`: PrimeVul relabelling, deduplication, repository list for the local license lookup; `split`: license import and the frozen split manifest. No training |
| `hpc/vul_extend.sbatch targets\|extract\|split\|audit` | `short` | 2 CPU, 16 GB, 4 h | Extends the C5 pool without touching the frozen test split: `targets` lists the GHSA fix commits CVEfixes and MoreFixes lack (plus the pool commits, for negatives); `extract` labels the fetched commits, deduplicates them against the pool and lists new repositories for the license lookup; `split` merges the licenses, writes split manifest v2, samples negatives and the audit packets; `audit` imports the AI audit verdicts |
| `hpc/vul_mine.sh` | transfer node | n/a | Fetches the listed fix commits: anonymous HTTPS partial clones (`--filter=blob:none --depth=2`), then only the needed blobs; 8 repositories at a time, one git request per second, backoff on errors, 300 s per git call, 500 MB per repository, resumable. No GitHub API calls |
| `hpc/fetch_vul_student_model.sh` | transfer node | n/a | C6 student base model (UniXcoder-base, pinned revision, Apache-2.0) with `MANIFEST.sha256` |
| `hpc/vul_smoke.sbatch` | `gpu`, H200 | 8 CPU, 64 GB, 20 min | C6 smoke: teacher 20 steps on 200 examples, student 20 steps, dev evaluation on 100 examples |
| `hpc/vul_train_teacher.sbatch` | `gpu`, H200 | 8 CPU, 96 GB, 6 h | C6 teacher LoRA (Qwen2.5-Coder-7B, bf16); `--array=1-3` for three seeds |
| `hpc/vul_train_student.sbatch --teacher-run ID` | `gpu`, A100 | 8 CPU, 48 GB, 3 h | C6 student distillation, permissive pool only; fp32 and int8 state dicts |
| `hpc/vul_eval.sbatch [--split test --locked]` | `gpu`, H200 | 8 CPU, 96 GB, 8 h | C6 metrics and baselines on dev; `--locked` runs the held-out test once (`reports/LOCKED_EVAL.json`) |
| `hpc/mail_acquire.sh` | transfer node | n/a | Email benchmark corpora (Nazario phishing mboxes, SpamAssassin tarballs, Enron May 2015 tarball, about 0.5 GB) into `/scratch/$USER/kestrix/mailbench/raw` (0700); records URL, size, SHA-256 and licence in `manifests/` |
| `hpc/mail_chain.sh smoke\|full` | login node | n/a | Submits the email benchmark: `smoke` is one small job; `full` chains build, features (array), dev-metrics and learn with `--dependency=afterok`. Never submits the locked test |
| `hpc/mail_smoke.sbatch` | `short` | 2 CPU, 8 GB, 40 min | The whole chain on a few hundred messages under `mailbench/smoke/` |
| `hpc/mail_build.sbatch` | `short` | 2 CPU, 24 GB, 6 h | Unpack, filter, deduplicate, label, group and split; writes private `work/` and the aggregate `reports/build.json`, `reports/split-manifest.json` |
| `hpc/mail_features.sbatch` | `short` | 1 CPU, 8 GB, 4 h, `--array=0-15` | `kestrix.mail.analyze` over one shard per task; writes finding ids, severities and counts only |
| `hpc/mail_dev_metrics.sbatch` | `short` | 1 CPU, 16 GB, 4 h | Baseline catch and false-alarm rates with grouped bootstrap intervals, leakage controls and miss causes on dev |
| `hpc/mail_learn.sbatch` | `short` | 1 CPU, 16 GB, 4 h | Non-negative L2 logistic-regression weights on dev (three leakage-controlled feature sets), grouped cross-validation |
| `hpc/mail_locked.sbatch --weights FILE [--name N]` | `short` | 1 CPU, 16 GB, 4 h | The one-time locked test evaluation (`mailbench/reports/LOCKED_EVAL.json` is claimed exclusively) |

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
