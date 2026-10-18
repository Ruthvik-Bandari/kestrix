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

126 train and 43 development examples come from the benchmark's train and development splits, never test; see the [dataset card](data/dataset-card.md). Each example pairs the exact B2 prompt with the reference repair recovered from the healthy rule. Missing-telemetry and healthy cases have the target `{"candidates": []}`. Six natural fixes that cannot be written within the contract were skipped. The prompts hold no event values.

## Results

The comparison is paired on the held-out **development** split: 44 cases from 12 roots. The test split is locked, and the intervals come from a root-resampling bootstrap. Full tables are in [`data/qc/README.md`](data/qc/README.md), under "Corrected results".

| System | Validated success | Outcome match | Weakened rules | Abstained | Δ vs B0 (95% CI) |
| --- | --- | --- | --- | --- | --- |
| B0, deterministic | 0.591 | 0.932 | 3 | 0% | — |
| B1, retrieval | 0.591 | 0.932 | 0 | 7% | ±0 |
| B2, unmodified model | 0.523 | 0.659 | 3 | 27% | −0.068 (−0.139 to 0) |
| M1, mean of 3 seeds | 0.568 (identical across seeds) | 0.879 | 0 | 12% | −0.023 (−0.073 to 0) |

- **M1 vs B2:** +0.045 (CI 0 to +0.111) for every seed, with 2 cases won and 0 lost. Logic outcome match rose from 0.00 to between 0.73 and 0.82.
- **M1 vs B0:** within noise, and below it. **M1 does not ship;** B1 is the recommended baseline, matching B0's success without weakening any rule.

## Limitations and risks

- **The benchmark is small and partly synthetic.** Its logic faults mirror B0's own search space, which favors B0. Natural faults are few. Results are exploratory.
- **The labels are AI-assisted,** and the human check is pending. The split is a preview and not yet frozen.
- **A model proposal can be wrong or weaken a rule.** The validation policy is the guard, and it needs reviewed benign events to detect weakening. Provisional repairs (no validation suite) are less trustworthy.
- **Prompt injection.** Rule text is passed to the model, and a malicious rule could try to steer it. The model has no tools, and every output passes the candidate contract and engine validation, so the worst case is a rejected or abstained repair.

## Reproduce

Follow [`docs/research.md`](research.md), steps 9 to 11. The commands are:

- `hpc/sft.sbatch`;
- `hpc/m1.sbatch --max-steps 5`, then `hpc/m1.sbatch --train-seed N`;
- `hpc/m1_eval.sbatch m1-seedN`;
- `compare --systems b0 b1 b2 m1-seed1 m1-seed2 m1-seed3`.
