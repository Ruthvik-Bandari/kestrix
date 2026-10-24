# QC results, 2026-10-14

This folder records the benchmark data checks in the order they ran. The JSON reports are from the latest runs: `python -m kestrixbench qc` (Slurm job 11105891) and `python -m kestrixbench replay` (job 11105959) on Explorer. The SigmaHQ section below describes the first run (job 11085056). They contain counts, reason codes, rule IDs and repository paths only, with no event values. Before reading anything, QC re-verified every file against its acquisition manifest.

| Source | Commit | Content SHA-256 (prefix) |
| --- | --- | --- |
| SigmaHQ `rules/windows/process_creation` and its `regression_data` | `552f3fee420e` | `dacdaa87c9f4` |
| OTRF `datasets/atomic/windows` and `_metadata` | `d9d40ef123d2` | `034b77c5b7e7` |
| Atomic Red Team `atomics/` | `388942adbd96` | `ba04ee420a90` |

## SigmaHQ

- 1,182 process_creation rules: 0 load errors, 0 missing IDs, 0 duplicate IDs and 0 exact duplicate detection blocks.
- Status: 1,075 `test`, 87 `experimental`, 20 `stable`.
- **192 rules (16%) fit the v1 subset.** The causes for the rest:

| Rules | Cause |
| --- | --- |
| 636 | A selection is a list of maps (OR of field maps), the most common SigmaHQ idiom |
| 161 | The `contains\|all` modifier |
| 86 | `1 of selection_*` conditions |
| 47 | `all of selection_*` conditions |
| 20 | The `windash` modifier |
| 12 | The `re` modifier |
| 11 | Null matching |
| 8 | Wildcards in values |

A rule can have several of these causes; each rule is counted once, under the first one found.

- 128 rules have positive regression data, giving 137 Sysmon EID 1 events in all. **Only 12 of the 192 supported rules have such data.**

## OTRF

Corrected on 2026-10-15 (Slurm job 11105891). OTRF reuses 37 archive names under several tactic folders, and every one of those archives has different contents. The first QC run keyed archives by file name, so it collapsed 155 archives into 118. QC now keys each archive by its path below `datasets/atomic/windows`.

- 100 Windows metadata files and 155 zip archives, covering 33 ATT&CK techniques.
- 788,932 records, of which 1,540 are Sysmon EID 1 (process creation). Those come from 107 archives.
- 13 archives have no metadata file. Two metadata links have no archive at this commit: `credential_access/host/cmd_copy_ntds_from_volume_shadow_copy` and `lateral_movement/network/empire_dcom_shellwindows_stager`.
- macOS `__MACOSX/._*` members are skipped, since they are not telemetry.

## Atomic Red Team

- 344 techniques and 1,878 tests, of which 1,260 run on Windows.
- Windows executors: 689 PowerShell, 562 command prompt, 9 manual.
- These test definitions are data only; none of them has been run.

## After ADR 0002 (Slurm job 11086173)

[ADR 0002](../../../docs/adr/0002-sigma-subset-common-idioms.md) widened the subset to lists of field maps, `|all`, and `1 of` / `all of`. QC now also requires each supported rule to convert with the pinned pySigma Lucene backend.

- **997 of 1,182 rules (84%) are supported, and every one of them converts.** Before the change, 192 rules were supported.
- **101 supported rules have SigmaHQ positive regression events.** Before the change, 12 did.
- The 185 remaining rules are excluded for these reasons:
  - `windash` (78)
  - `re` (41)
  - null matching (23)
  - wildcards (21)
  - value-count and empty-value limits (17)
  - `base64offset` (4)
  - more than 16 alternative maps (1)

## Replay on the pinned engine (Slurm job 11105959, 2026-10-15)

`python -m kestrixbench replay` (`research/hpc/detect/replay.sbatch`) ran Elasticsearch 8.19.3 on a compute node. It loaded one disposable index with 137 SigmaHQ regression events and 1,540 OTRF process-creation events, reduced to the v1 fields. Every supported rule was then replayed against that index. `replay-positives.json` lists, for each rule, its own regression matches, SigmaHQ's declared match count, any other regression events it matched, and its OTRF candidate events and dataset paths. It holds no field values.

- **997 rules replayed, 0 engine errors.**
- **Fidelity: 83 of 83 rules match exactly the number of events SigmaHQ declares (`match_count`).** Single-rule regression folders are the only ones with an unambiguous declared count. Two regression files hold 3 recorded events each but declare one match, and the replay found exactly one for each. The extra events are context, not missed detections.
- **176 rules have at least one positive event.**
  - 91 have only their own regression events.
  - 75 have only OTRF candidates.
  - 10 have both.
- **43 rules have two or more positive events.** The number of positive events per rule is:

| Positive events | Rules |
| --- | --- |
| 1 | 133 |
| 2 | 19 |
| 3 | 9 |
| 4 | 6 |
| 5 | 2 |
| 6 | 1 |
| 10 or more | 6 |

An OTRF match is a *candidate* positive. OTRF captures are attack simulations recorded on hosts that also ran background activity, so a match can be benign. Each candidate needs a reviewer's label (malicious, benign or unknown) before it enters the benchmark. Rules with many candidates (up to 46 events) are the most likely to include benign matches.

## What this means for the benchmark

The plan targets 60 clean roots with at least two attack variants each "where feasible". After the subset widening and the replay:

- **43 roots have two or more positive events** (own regression events plus unreviewed OTRF candidates).
- **176 roots have at least one.**

To reach 60 roots with two variants, the remaining options are:

1. Review the OTRF candidates. This both confirms the 43 roots and shows which candidates are benign; benign candidates become confounders.
2. Accept roots with a single verified positive. Record them as single-variant roots and report results separately.
3. Add a second variant by authoring a documented synthetic event for each single-positive root, labeled with provenance `synthetic`, and report those results separately.
4. Capture Atomic Red Team runs in an authorized, isolated lab (`policy.md` section 7). Those would be labeled `lab_introduced`.

## Review sheet and split preview (Slurm jobs 11107577 and 11107581, 2026-10-15)

- **The review sheet holds 175 distinct OTRF candidate events, matched by 85 rules across 73 archives.** It is written privately on the cluster. How to label it is in [`../review.md`](../review.md).
- **Before any review**, only SigmaHQ regression matches count as verified positives:
  - 101 roots have at least one verified positive;
  - 3 have two or more.
- **The split preview** (`split-preview.json`, seed `aegis-bench-v1`) puts roots in the same group when they share a rule family or a positive event:
  - test: 12 roots in 10 groups;
  - development: 12 roots in 6 groups;
  - train: 37 roots in 25 groups;
  - reserve: 40 roots in 14 groups.

  Train has 37 roots rather than 36 because groups are never split. The largest group is 19 `wmic` rules, which landed in reserve.
- The preview is not frozen. It changes once labels are added, and it is frozen only after review is complete.

## Impairment variants from the split preview (Slurm job 11108295, 2026-10-15)

`python -m kestrixbench variants` (`research/hpc/detect/variants.sbatch`) injected faults into every root in the preview split. It verified each one on the pinned engine. The aggregate report is `variants.json`; the case folders hold raw events and stay private on the cluster.

- **153 cases from 61 roots, with no root left without a variant.** By fault:
  - logic: 61;
  - mapping drift: 46;
  - missing telemetry: 46.
- By split: test 32, development 28 and train 93.
- **Discarded because the fault did not change engine behavior:**
  - 29 logic edits;
  - 15 mapping faults and 15 missing-telemetry faults. These are mostly rules whose preferred field is not what decides the match.
- **144 of the 153 cases have no validation suite.** Their root has a single verified positive, so there is no independent attack event to hold out. The workflow reports their repairs as provisional.

Only reviewed OTRF positives, or documented synthetic second variants, can close that gap. This run used the unreviewed preview, so the cases are regenerated after review and the split freeze.

## First baselines: B0 and B1 (Slurm jobs 11138719, 11138730, 11138731, 2026-10-16)

The variants were regenerated with healthy controls and the fairness rule that every fault must lose a detection. That gave 214 cases: 61 healthy, 61 logic, 46 mapping and 46 missing telemetry. B0 and B1 then ran on the 170 train and development cases from 49 roots. The test split was not read. The full results are in `comparison.md`.

| System | Validated success | Outcome match (incl. provisional) | Wrong change | Abstained |
| --- | --- | --- | --- | --- |
| B0 | 0.529 (95% CI 0.494–0.574) | 0.988 | 0.000 | 0.006 |
| B1 | 0.529 | 0.988 | 0.000 | 0.006 |

Outcome match by fault, for both systems:

- healthy 1.00;
- logic 1.00;
- mapping 0.97;
- missing telemetry 0.97.

**What this shows.**

1. **The synthetic benchmark is too easy for B0, and it is circular.**
   - The logic faults are made with the same one-edit condition mutations that B0 searches, so B0 always finds the inverse edit.
   - The mapping faults use a stale `winlog.event_data.*` name, while the right field is observed in the data, which is exactly B0's alternative-field diagnosis.
   - With the deterministic baseline at 0.99 outcome match, B1, B2 and M1 have no room to show a gain on these faults. This is the measured gap gate in plan section 12: M1 is not justified on this benchmark.
2. **Validated success is capped by evidence, not by repair ability.** 78 of 84 repairs were correct but provisional, because their root has a single verified positive and no validation suite. Reviewed OTRF positives raise this number directly.
3. **The next benchmark needs faults B0 does not generate:**
   - natural maintenance faults mined from SigmaHQ's own history, where a rule was later fixed (plan section 11 provenance `natural`);
   - multi-edit faults;
   - mappings where the replacement field is renamed differently from the stale one.

## Natural faults from SigmaHQ history, and the second baseline run (2026-10-16)

### Mining

Jobs 11139335 (mining and verification), 11140135 (cases) and 11140597/8 (evaluation). `python -m kestrixbench natural-mine` walked SigmaHQ's history up to the pinned commit (`natural-mining.json`). It found **1,403 detection-changing maintenance commits across 568 supported rules**, and 739 of them fit the repair contract. It skipped:

- 6,508 metadata-only edits;
- 3,920 versions outside the supported subset;
- 2,181 changes to rules that are not supported at the pin;
- selection renames, which are refactors rather than faults.

Classified by AST diff, the change kinds are:

| Kind | Changes |
| --- | --- |
| condition | 522 |
| selection added | 472 |
| values added | 437 |
| selection removed | 376 |
| values changed | 305 |
| field | 149 |
| modifier | 129 |
| values removed | 86 |

### Verification

`natural-verify` replayed every pair against all 137 SigmaHQ regression recordings (`natural-verified.json`).

- **27 pairs in 26 rules are verified.** In each, the maintainers' fix catches a recorded attack that the earlier version missed.
- In 1,156 pairs the fix matches no recording. These are unobservable with the current positives, not refuted.
- 216 pairs are not coverage fixes. Most of these are false-positive fixes, which need reviewed benign events to verify.
- 4 pairs failed pySigma conversion and were counted as errors.

The verified rules joined the split preview as roots, so 112 roots are eligible. Six verified pairs landed in the open and test splits (3 train, 2 development, 1 test); the others are in reserve.

### Reference negatives (fixed)

Background events used to be labeled `unknown`, so a repair that *weakened* a rule until it caught a missed attack was never charged with a false alarm. Negatives are now labeled benign relative to the rule, using the healthy reference as the oracle (plan section 10). A plan section 9 negative-control test proves that an always-true style candidate now fails validation.

### Results

These are paired results on 173 train and development cases from 48 roots. The test split was not read.

| System | Validated success | Outcome match | Wrong change | Abstained |
| --- | --- | --- | --- | --- |
| B0 | 0.520 (95% CI 0.480–0.572) | 0.977 | 0.000 | 0.006 |
| B1 | 0.520 | 0.977 | 0.000 | 0.017 |

| Kind (cases) | B0 success / outcome match | B1 success / outcome match |
| --- | --- | --- |
| healthy (48) | 1.00 / 1.00 | 1.00 / 1.00 |
| logic (48) | 0.06 / 1.00 | 0.06 / 1.00 |
| mapping (36) | 0.08 / 0.97 | 0.08 / 0.97 |
| missing telemetry (36) | 0.97 / 0.97 | 0.97 / 0.97 |
| **natural (5)** | **0.20 / 0.60** | **0.20 / 0.60** |

**Reading the natural row.** On 2 natural cases, B0's selected repair bought coverage with new false alarms on development events, so it weakened the rule (`adds_false_alarms`). B1 abstained on the same 2 cases. Their scores are equal, but B1's behavior is the safe one.

Natural faults are where the deterministic baseline stops being perfect. For example, a fix that adds a new value cannot be produced by B0's operators. Five open natural cases are far too few for a conclusion, though. Every reviewed malicious OTRF event enlarges the positive pool and lets more of the 1,156 currently unobservable fixes be verified.

## AI-assisted labeling of the OTRF candidates (2026-10-16)

The owner approved AI-assisted labeling for this public dataset; the procedure is in [`../review.md`](../review.md#ai-assisted-labeling).

The 175 candidates were split into four chunks. Two independent AI reviewers labeled each chunk from the same written criteria.

- **Agreement:** 165 of 175 events (94.3%); Cohen's κ = 0.53, which is depressed by the skew toward "malicious".
- **All 10 disagreements had the same shape:** reviewer A said malicious and reviewer B said unknown. Most were `conhost.exe` launched by a bare shell. A third reviewer adjudicated all 10 as `unknown`, because nothing tied the parent shell to the attack step.
- **Imported labels:**
  - malicious: 159 (`ai-consensus`);
  - benign: 3 (`ai-consensus`);
  - unknown: 13 (3 `ai-consensus`, 10 `ai-adjudicated`).
- **Still to do before the split is frozen:** the human check. The owner re-labels the 10 adjudicated events and a seeded 10% sample of the consensus labels (17 events). The 27 event ids are in `review/human-check.txt` on the cluster. A human label always replaces an AI one, and results built on these labels report `ai_assisted` separately.

## B2: unmodified open model (Slurm job 11142209, V100, 37 min)

Qwen2.5-Coder-7B-Instruct (pinned revision, fp16, greedy decoding) was run on the same 173 cases as B0 and B1, before the relabeling. The snapshot is in `pre-relabel/`.

| System | Validated success | Outcome match | Wrong change | Abstained | Δ vs B0 (95% CI) |
| --- | --- | --- | --- | --- | --- |
| B0 | 0.520 | 0.977 | 0 | 0.006 | — |
| B1 | 0.520 | 0.977 | 0 | 0.017 | +0.000 |
| B2 | 0.503 | 0.832 | 0 | 0.162 | −0.017 (−0.039 to +0.000), 0 won and 3 lost |

B2's outcome match by fault:

- mapping: 0.97, the same as B0, because the prompt carries the diagnosis's observed alternative fields;
- logic: 0.52 (25 repaired, 23 abstained);
- natural: 0.20 (4 of 5 abstained);
- healthy: 1.00;
- missing telemetry: 0.97.

Across 89 model calls, B2 proposed 263 candidates; 250 were valid and 13 malformed proposals were dropped. B2 never weakened a rule: no repair added false alarms.

**Reading.** An untrained 7B model is safe but weaker than the deterministic baseline on logic and natural faults. That remaining gap is the plan's precondition (section 12) for trying M1 LoRA fine-tuning on the train-split repairs.

## Rebuilt benchmark with labels (2026-10-16, preview split)

Labeling added 159 malicious OTRF positives (296 pool events in all).

- **Natural verification:** 42 fixes in 40 rules, up from 27.
- **Split preview:** 187 eligible roots, grouped by rule family, with every positive event exclusive to one split. That dropped 5 shared positives and moved 2 roots to reserve.
  - test: 14 roots (5 with two or more positives);
  - development: 12 (3);
  - train: 39 (7).
- **Cases:** 216 synthetic plus 13 natural. Cases without a validation suite fell from 198 to 168.

Paired results on 175 train and development cases:

| System | Validated success | Outcome match | Wrong change | Abstained | Weakened rules | Δ vs B0 (95% CI) |
| --- | --- | --- | --- | --- | --- | --- |
| B0 | 0.560 | 0.949 | 0 | 0.011 | 6 | — |
| B1 | 0.560 | 0.943 | 0 | 0.051 | 0 | +0.000 |
| B2 | 0.509 | 0.760 | 0 | 0.234 | 0 | −0.051 (−0.084 to −0.023), 0 won and 9 lost |

| Kind (cases) | B0 success / match | B1 success / match | B2 success / match |
| --- | --- | --- | --- |
| healthy (48) | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |
| logic (48) | 0.19 / 1.00 | 0.19 / 1.00 | 0.02 / 0.38 |
| mapping (34) | 0.21 / 0.97 | 0.21 / 0.97 | 0.21 / 0.97 |
| missing telemetry (34) | 0.97 / 0.97 | 0.97 / 0.97 | 0.97 / 0.97 |
| natural (11) | 0.09 / 0.36 | 0.09 / 0.27 | 0.00 / 0.09 |

On the 34 cases with a validation suite, validated success is B0 0.97 and B2 0.71.

**Reading.**

1. **B2 is significantly worse than B0**, with an interval that excludes zero. The unmodified model is weakest on logic and natural faults.
2. **B0 and B1 tie on success, but they are not equally safe.** B0 reached its score by weakening 6 rules, so that the repaired rule also matched benign development events. B1 never weakened a rule.
3. **Natural faults remain the hard frontier.** No system exceeds 0.09 validated success on them, which leaves room for M1.

All labels behind these results are AI-assisted (`ai_assisted`: 175), and the 27-event human check is pending.

## M1: LoRA fine-tuning (Slurm jobs 11145586, 11145591 and 11145596)

The SFT data comes from the train and development cases only, never test.

- **Examples:** 126 train and 43 development. Six natural fixes that cannot be written as candidate operations within the contract were skipped (5 train, 1 development).
- **Smoke run on an A100-80GB:**
  - peak memory 18.9 GB, at 1,676 tokens per second;
  - no example truncated at the 4,096-token limit.
- **Training on an A100:**
  - LoRA with r 16 and alpha 32 on all attention and MLP projections, bf16;
  - learning rate 2e-4 with a cosine schedule, effective batch 8, 3 epochs, 48 optimizer steps, seed 1;
  - 4.5 minutes, at about 2,100 tokens per second;
  - development loss 0.034, then 0.019, then 0.020 by epoch.

  Peak memory also fits a 32 GB V100, the smallest-GPU option for further seeds.
- **Evaluation on a V100:** the base model plus the adapter, otherwise identical to B2.

Paired on 175 train and development cases:

| System | Validated success | Outcome match | Wrong change | Abstained | Weakened rules | Δ vs B0 (95% CI) |
| --- | --- | --- | --- | --- | --- | --- |
| B0 | 0.560 | 0.949 | 0 | 0.011 | 6 | — |
| B1 | 0.560 | 0.943 | 0 | 0.051 | 0 | +0.000 |
| B2 | 0.509 | 0.760 | 0 | 0.234 | 0 | −0.051 (−0.084 to −0.023) |
| **M1** | **0.549** | **0.920** | 0 | 0.074 | **0** | −0.011 (−0.028 to +0.000) |

**M1 vs B2:** +0.040 (95% CI +0.017 to +0.072). M1 won 7 cases and lost none. Across 93 model calls, no proposal was malformed (B2 had 13).

| Kind (cases) | B0 | B2 | M1 |
| --- | --- | --- | --- |
| logic (48), success / match | 0.19 / 1.00 | 0.02 / 0.38 | 0.17 / 0.94 |
| natural (11), success / match | 0.09 / 0.36 | 0.00 / 0.09 | 0.00 / 0.18 |

On the 34 cases with a validation suite, validated success is B0 0.97, M1 0.91 and B2 0.71.

**Reading.**

- **Fine-tuning helps.** M1 is significantly better than the unmodified model (B2): logic outcome match rose from 0.38 to 0.94, abstention fell from 23% to 7%, and malformed output went to zero.
- **M1 is not better than the deterministic baseline.** Its interval against B0 touches zero from below. It matches B0 within noise while never weakening a rule, which B0 did 6 times.
- **Natural faults remain unsolved by every system.** The best validated success is 0.09.

Per plan section 13, the stronger validated baseline ships unless adaptation credibly improves on it. On this evidence, M1 does not justify replacing B0 or B1. B1 matches B0's success with zero weakened rules, which makes it the safest choice.

Caveats:

- This is one seed.
- All labels are AI-assisted, and the human check is pending.
- The split is a preview, not frozen.
- The locked test split has not been run.

## Correction (2026-10-17): earlier comparison tables are superseded

An independent code review found two defects that affect every comparison table above.

1. **The comparisons pooled train cases with development cases.** B1's retrieval memory and M1's training data come from the train split, so both were partly scored on their own data. The B1 and M1 numbers above are therefore optimistic.
2. **Natural cases could include positives owned by another split.** A fix gained against the global pool could put a test root's attack event into a train case. Background negatives could likewise include other roots' positives.

Other fixes in the same review:

- SFT targets are now verified through the real candidate contract.
- B1 skips out-of-contract proposals instead of crashing.
- Engine failures are error rows, not abstentions.
- Weakening is judged against the healthy reference.
- `classify` handles repeated fields.

All of it is fixed in commits 48b5b06 and 2869a39, with regression tests. The full pipeline was re-run: natural verification, split, variants, B0, B1, B2, SFT and M1 seeds 1 to 3. Comparisons are now on held-out cases only: development, or test when locked. The corrected results are in the next section, and they replace every table above.

### Corrected results (held-out development only)

These are Slurm jobs 11158116 to 11158128. The comparison covers the development split only: 44 cases from 12 roots. The test split remains locked.

| System | Validated success | Outcome match | Wrong change | Abstained | Weakened rules | Δ vs B0 (95% CI) |
| --- | --- | --- | --- | --- | --- | --- |
| B0, deterministic | 0.591 | 0.932 | 0 | 0.000 | 3 | — |
| B1, retrieval | 0.591 | 0.932 | 0 | 0.068 | 0 | +0.000 |
| B2, unmodified Qwen2.5-Coder-7B | 0.523 | 0.659 | 0 | 0.273 | 3 | −0.068 (−0.139 to +0.000) |
| M1 seed 1 | 0.568 | 0.886 | 0 | 0.114 | 0 | −0.023 (−0.073 to +0.000) |
| M1 seed 2 | 0.568 | 0.864 | 0 | 0.136 | 0 | −0.023 (−0.073 to +0.000) |
| M1 seed 3 | 0.568 | 0.886 | 0 | 0.114 | 0 | −0.023 (−0.073 to +0.000) |

**M1 vs B2:** +0.045 (95% CI +0.000 to +0.111) for each seed, with 2 cases won and 0 lost.

**M1 development loss by epoch:**

| Seed | Epoch 1 | Epoch 2 | Epoch 3 |
| --- | --- | --- | --- |
| 1 | 0.038 | 0.019 | 0.020 |
| 2 | 0.035 | 0.022 | 0.020 |
| 3 | 0.023 | 0.019 | 0.019 |

All three seeds trained on 126 contract-verified examples, about 4.5 minutes each on an A100.

**By fault kind (development):**

| Kind (cases) | B0 success / match | B2 success / match | M1 success / match (seeds 1, 2, 3) |
| --- | --- | --- | --- |
| healthy (11) | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |
| logic (11) | 0.27 / 1.00 | 0.00 / 0.00 | 0.18 / 0.82, 0.73, 0.82 |
| mapping (9) | 0.33 / 1.00 | 0.33 / 1.00 | 0.33 / 1.00 |
| missing telemetry (9) | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |
| natural (4) | 0.00 / 0.25 | 0.00 / 0.00 | 0.00 / 0.25 |

**Conclusions** (exploratory, n = 44 development cases):

1. **No learned system beats the deterministic baseline.** B1 ties B0, and M1 and B2 are within noise below it. Under plan section 13, the stronger baseline ships.
2. **Fine-tuning moves the model in the right direction, and does so consistently.** Logic outcome match rose from 0.00 (B2) to between 0.73 and 0.82 (M1), and all three seeds reach the same validated success. On this small held-out set, the difference against B2 is not significant.
3. **Safety separates the systems more than success does.** B0 and B2 each weakened 3 rules to reach their scores. B1 and M1 never weakened a rule. That makes **B1 the recommended research baseline**: B0's success with zero weakening.
4. **Natural faults are unsolved:** 0 validated success for every system. This is the open problem, and a larger frozen split and test evaluation are needed before any claim.

## Final results on the frozen split (2026-10-18)

The split was frozen on 2026-10-17 ([`split-manifest.json`](../split-manifest.json), SHA-256 `0353bc1e…48bd4`). The owner waived the human label check, so every result is reported twice: once with all labels, and once in a sensitivity run that drops every AI-assisted label (`AEGIS_IGNORE_AI_LABELS=1`, a separate data root). The test split was evaluated exactly once, after the development results were in.

Slurm jobs:
- main pipeline: 11177252 to 11177301 and 11190540 to 11190542;
- sensitivity run: 11177550 to 11178192, 11190538 and 11190539.

Comparison files:
- [`comparison-frozen-development.md`](comparison-frozen-development.md)
- [`comparison-locked-test.md`](comparison-locked-test.md)
- [`comparison-sensitivity-development.md`](comparison-sensitivity-development.md)

Each has a matching `.json`.

**Reading the tables:**
- **Validated success has a ceiling below 1.** A broken rule with only one recorded attack has nothing left to validate a repair on, so any repair is provisional by design. The ceiling is the "best possible" figure.
- **"Of provable cases"** is success divided by the number of cases that can be proven.
- **Weakened rules** counts repairs that raised false alarms above the healthy rule's on the development events.

### Development (44 cases, 12 roots; best possible 0.591)

| System | Validated success | Of provable | Outcome match | Abstained | Weakened rules | Δ vs B0 (95% CI) |
| --- | --- | --- | --- | --- | --- | --- |
| B0, deterministic | 0.591 | 1.000 | 0.932 | 0.000 | 3 | — |
| B1, retrieval | 0.591 | 1.000 | 0.932 | 0.068 | 0 | +0.000 |
| B2, unmodified model | 0.523 | 0.885 | 0.659 | 0.273 | 3 | −0.068 (−0.139 to +0.000) |
| M1 seed 1 | 0.568 | 0.962 | 0.886 | 0.114 | 0 | −0.023 (−0.073 to +0.000) |
| M1 seed 2 | 0.568 | 0.962 | 0.864 | 0.136 | 0 | −0.023 (−0.073 to +0.000) |
| M1 seed 3 | 0.545 | 0.923 | 0.864 | 0.136 | 0 | −0.045 (−0.108 to +0.000) |

### Test, locked, evaluated once (54 cases, 14 roots; best possible 0.648)

| System | Validated success | Of provable | Outcome match | Abstained | Weakened rules | Δ vs B0 (95% CI) |
| --- | --- | --- | --- | --- | --- | --- |
| B0, deterministic | 0.630 | 0.971 | 0.982 | 0.018 | 0 | — |
| B1, retrieval | 0.630 | 0.971 | 0.982 | 0.018 | 0 | +0.000 |
| B2, unmodified model | 0.556 | 0.857 | 0.741 | 0.204 | 3 | **−0.074 (−0.135 to −0.018)** |
| M1 seed 1 | 0.630 | 0.971 | 0.944 | 0.056 | 0 | +0.000 |
| M1 seed 2 | 0.630 | 0.971 | 0.963 | 0.037 | 0 | +0.000 |
| M1 seed 3 | 0.630 | 0.971 | 0.944 | 0.056 | 0 | +0.000 |

### Sensitivity: no AI-assisted labels (development, 42 cases, 13 roots; best possible 0.476)

| System | Validated success | Of provable | Outcome match | Abstained | Weakened rules |
| --- | --- | --- | --- | --- | --- |
| B0, deterministic | 0.476 | 1.000 | 0.952 | 0.000 | 1 |
| B1, retrieval | 0.476 | 1.000 | 0.929 | 0.048 | 0 |
| B2, unmodified model | 0.476 | 1.000 | 0.643 | 0.143 | 8 |
| M1 seed 1 | 0.476 | 1.000 | 0.929 | 0.048 | 0 |

### Conclusions (exploratory)

1. **On the provable cases, the deterministic and retrieval baselines are near-perfect.** They reach 1.000 on development and 0.971 on test, so they sit at the benchmark's ceiling. The benchmark cannot show a learned system beating them. That limit belongs to the benchmark, not evidence about the systems.
2. **The unmodified model (B2) is the only system that is measurably worse.** On test, its difference from B0 has a 95% interval that excludes zero (−0.135 to −0.018). It abstains most often and weakens rules: 3 in development, 3 in test, and 8 in the sensitivity run.
3. **Fine-tuning closes B2's gap.** M1 ties B0 and B1 on test with all three seeds, and never weakens a rule. Under plan section 13 a learned system ships only if it credibly beats the strongest baseline, and M1 does not, so **M1 does not ship**.
4. **B1 is the recommended baseline.** It matches B0's success everywhere, and it never weakened a rule in any run, while B0 weakened 3 in development and 1 in the sensitivity run.
5. **The AI-assisted labels do not drive the conclusions.** Without them every system reaches the lower ceiling of 0.476. The ordering on outcome match and on weakening is the same: B2 is clearly worst, and B1 and M1 never weaken a rule.
6. **Next step for the benchmark: more recorded attacks per rule.** Most failed validations come from rules with a single positive. More recorded attacks would turn provisional cases into provable ones and give harder cases where the systems can differ. Natural faults also remain unproven, since each has only one recorded attack.
