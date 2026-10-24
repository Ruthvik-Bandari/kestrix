# Model card: M1 detection-repair adapter (research, not released)

**Status: research result, not shipped.** Under plan section 13, adaptation ships only if it credibly beats the strongest baseline, and M1 does not (see Results). The shipped `kestrix detect` uses the deterministic generator; B1 retrieval is the recommended research baseline.

## Model

| | |
| --- | --- |
| Base model | [Qwen/Qwen2.5-Coder-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct), revision `c03e6d358207e414f1eca0bb1891e29f1db0e242`, Apache-2.0 |
| Adapter | LoRA on `q,k,v,o,gate,up,down` projections; r 16, alpha 32, dropout 0.05 |
| Training | Supervised fine-tuning on completions only; AdamW with learning rate 2e-4 and a cosine schedule (5% warmup); effective batch 8; 3 epochs; bf16; context 4,096 with no truncation observed |
| Hardware | One A100-SXM4-80GB. Peak memory 18.9 GB, about 2,100 tokens per second, 4.5 minutes per seed |
| Seeds | 1, 2, 3; identical validated success, development loss 0.019 to 0.020 |
| Code | `src/kestrixbench/m1.py` (training), `src/kestrixbench/sft.py` (data), `src/kestrixbench/hf.py` (inference) |
| Run records | `reports/m1-seed*-training.json`, which hold the configuration, loss history, memory, throughput, base revision and data SHA-256 |

## Intended use

The adapter proposes **candidate repairs** for a broken Sigma rule, as structured JSON patches under the candidate contract: at most 3 AST edits and at most 4 candidates, and it never drops a selection. Its input is the rule, the field mapping, field coverage, the deterministic diagnosis and replay counts.

Every proposal is then screened, frozen and validated on the pinned Elasticsearch by the same workflow used for B0. The model's output is never applied without that validation.

**Not intended for:**
- applying rule changes automatically;
- free-text security advice;
- any task outside the candidate contract.

The model has no tools and no network access. It loads with `trust_remote_code=False` from a local, revision-pinned snapshot.

## Training data

126 train and 43 development examples come from the benchmark's train and development splits, never test; see the [dataset card](../research/results/dataset-card.md). Each example pairs the exact B2 prompt with the reference repair recovered from the healthy rule. Missing-telemetry and healthy cases have the target `{"candidates": []}`. Six natural fixes that cannot be written within the contract were skipped. The prompts hold no event values.

## Results

All comparisons are paired, and the intervals come from a root-resampling bootstrap. Full tables are in [`research/results/qc/README.md`](../research/results/qc/README.md), under "Final results on the frozen split".

**Best possible success.** A case with one recorded attack has no validation suite, so the best possible validated success is 0.591 on development and 0.648 on test.

**Locked test split, evaluated once** (54 cases, 14 roots):

| System | Validated success | Of provable cases | Outcome match | Weakened rules | Δ vs B0 (95% CI) |
| --- | --- | --- | --- | --- | --- |
| B0, deterministic | 0.630 | 0.971 | 0.982 | 0 | — |
| B1, retrieval | 0.630 | 0.971 | 0.982 | 0 | ±0 |
| B2, unmodified model | 0.556 | 0.857 | 0.741 | 3 | −0.074 (−0.135 to −0.018) |
| M1, seeds 1/2/3 | 0.630 each | 0.971 each | 0.944 / 0.963 / 0.944 | 0 | ±0 |

**Development split** (44 cases, 12 roots), on the frozen split:

| System | Validated success | Outcome match | Weakened rules | Abstained | Δ vs B0 (95% CI) |
| --- | --- | --- | --- | --- | --- |
| B0, deterministic | 0.591 | 0.932 | 3 | 0% | — |
| B1, retrieval | 0.591 | 0.932 | 0 | 7% | ±0 |
| B2, unmodified model | 0.523 | 0.659 | 3 | 27% | −0.068 (−0.139 to 0) |
| M1, seeds 1/2/3 | 0.568 / 0.568 / 0.545 | 0.886 / 0.864 / 0.864 | 0 | 11–14% | −0.023 to −0.045 (CIs include 0) |

- **M1 vs B2:** on test, +0.074 for every seed (B2 loses 4 cases that M1 gets right); on development, +0.045 (seeds 1 and 2) and +0.023 (seed 3). Logic outcome match on development rose from 0.00 to between 0.73 and 0.82.
- **M1 vs B0:** within noise on development, and tied on test with every seed. M1 closes the untrained model's gap; B2 is the only system measurably worse on test. M1 does not beat the strongest baseline, so **M1 does not ship** (plan section 13). B1 is the recommended baseline: it matches B0's success and never weakened a rule in any run.
- **Sensitivity:** without AI-assisted labels, M1 reaches the same 0.476 ceiling as every baseline, with outcome match 0.929 and no weakened rules.

## Limitations and risks

- **The benchmark is small and partly synthetic.** Its logic faults mirror B0's own search space, which favors B0. Natural faults are few. Results are exploratory.
- **The labels are AI-assisted.** The owner waived the human check; a sensitivity run without those labels reaches the same conclusions. The split is frozen.
- **A model proposal can be wrong or weaken a rule.** The validation policy is the guard, and it needs reviewed benign events to detect weakening. Provisional repairs (no validation suite) are less trustworthy.
- **Prompt injection.** Rule text is passed to the model, and a malicious rule could try to steer it. The model has no tools, and every output passes the candidate contract and engine validation, so the worst case is a rejected or abstained repair.

## Reproduce

Follow [`docs/research/detect-runbook.md`](research/detect-runbook.md), steps 9 to 11. The commands are:

- `research/hpc/detect/sft.sbatch`;
- `research/hpc/detect/m1.sbatch --max-steps 5`, then `research/hpc/detect/m1.sbatch --train-seed N`;
- `research/hpc/detect/m1_eval.sbatch m1-seedN`;
- `compare --systems b0 b1 b2 m1-seed1 m1-seed2 m1-seed3`.
