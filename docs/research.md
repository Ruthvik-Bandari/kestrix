# Research pipeline: benchmark, baselines and fine-tuning

This runbook covers the detection-repair research track from plan sections 11 to 14, from public data to a locked comparison of B0, B1, B2 and M1. Every step is one `python -m kestrixbench <command>` run inside a Slurm job on Explorer (`docs/hpc.md`). Data lives under `/scratch/$USER/kestrix/data`. Only aggregate reports, which hold ids, counts and hashes, are copied into `docs/data/qc/`.

## Pipeline

| # | Step | Command / job | Output |
| --- | --- | --- | --- |
| 1 | Fetch pinned sources | `hpc/acquire.sh` (transfer node) | `manifests/*.json` |
| 2 | Quality checks | `hpc/qc.sbatch` | `reports/qc-*.json` |
| 3 | Replay every supported rule | `hpc/fetch_engine.sh`, `hpc/replay.sbatch` | `reports/replay-positives.json` |
| 4 | Review OTRF candidates (owner) | `review-next` / `review-label` ([`data/review.md`](data/review.md)) | `review/labels.csv` (private) |
| 4b | Natural faults: mine and verify SigmaHQ history | `hpc/fetch_history.sh`, then `hpc/natural.sbatch` | `reports/natural-mining.json`, `reports/natural-verified.json`; verified rules become extra roots for step 5 |
| 5 | Split preview, then freeze | `hpc/review_split.sbatch`, then `split --freeze` | `benchmark/split-manifest.json` |
| 6 | Impairment variants and natural cases | `hpc/variants.sbatch` | `benchmark/cases/` (private), `reports/variants.json`, `reports/natural-cases.json` |
| 7 | Baselines B0, B1 | `hpc/evaluate.sbatch b0`, `hpc/evaluate.sbatch b1` | `reports/eval-b0.json`, `reports/eval-b1.json` |
| 8 | Baseline B2 | `hpc/fetch_model.sh`, `bash hpc/setup_env.sh gpu`, `hpc/b2.sbatch` | `reports/eval-b2.json` |
| 9 | M1 data and training | `hpc/sft.sbatch`, `hpc/m1.sbatch --max-steps 5` (smoke), then `hpc/m1.sbatch --train-seed {1,2,3}` | `sft/*.jsonl`, `models/m1-seed*`, `reports/m1-*-training.json` |
| 10 | M1 evaluation | `hpc/m1_eval.sbatch m1-seed1` | `reports/eval-m1.json` |
| 11 | Paired comparison | `compare --systems b0 b1 b2 m1` | `reports/comparison.{json,md}` |
| 12 | Locked test, once | Re-run 7, 8 and 10 for the chosen system and its baselines with `--locked`, then `compare --locked` | `reports/*-locked.*` |

## The systems

All four systems go through the same workflow (`kestrix.detect.workflow.run`). They differ only in the candidate generator. Every candidate meets the same contract:

- at most 3 AST edits and 4 kept candidates;
- no selection is ever dropped;
- each candidate is screened on development fixtures;
- one candidate is selected and frozen;
- that candidate is then validated once on independent fixtures.

| System | Candidate generator | Learns from |
| --- | --- | --- |
| B0 | Deterministic mapping, noise and logic generators (`kestrix.detect.repair`) | Nothing |
| B1 | TF-IDF retrieval over the rule structure and diagnosis, which proposes edits that solved similar train cases (`kestrixbench.b1`) | Train cases only |
| B2 | An unmodified Qwen2.5-Coder-7B-Instruct (pinned revision, Apache-2.0) that writes JSON patches from the rule, mapping, coverage, diagnosis and replay counts (`kestrixbench.b2`) | Nothing |
| M1 | B2 plus a LoRA adapter fine-tuned on reference repairs from train cases (`kestrixbench.sft`, `kestrixbench.m1`) | Train cases only; development loss for monitoring |

## Metrics

`evaluate` scores each case against its expected outcome. Section 13 of the plan defines the metrics:

- **Validated repair success:**
  - a `repaired` case counts only when its repair passed independent validation;
  - provisional repairs do not count;
  - a mapping case needs a mapping patch;
  - healthy and missing-telemetry cases count when the system leaves the rule unchanged or reports insufficient evidence.
- **Wrong change:** any repair where none was expected, or a repair with the wrong patch kind.
- **Abstention:** no repair. Abstentions and errors stay in the denominator. An engine error is a failure, never a pass.

Confidence intervals come from a bootstrap that resamples *roots*, because the variants of one root are correlated. `compare` pairs systems on identical case ids and refuses anything else.

## Rules that keep the result honest

- The split is assigned by root, and frozen before any variant is generated (`split --freeze`). Related rules and rules that share an event stay in one split.
- B1's memory and M1's training data come from the train split only. Development is used for monitoring and selection. The test split is read only with `--locked`, after a system is chosen. `sft` refuses to read it.
- Prompts hold rule text, field names, coverage and counts, but never event values.
- Two fault provenances, always reported separately (plan section 11):
  - `synthetic` faults are generated, and measure controlled robustness;
  - `natural` faults are real SigmaHQ maintenance commits. The rule before the commit is the impaired one, and the maintainers' version after it is the reference.
- A natural pair becomes a case only when the fix detects a verified positive that the earlier version misses. False-positive fixes are counted but not used until reviewed benign events exist.
- If M1 does not credibly beat B2, the stronger baseline ships and the result is reported as it is (plan section 13).
