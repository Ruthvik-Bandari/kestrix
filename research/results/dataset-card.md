# Dataset card: Kestrix detection-repair benchmark (v1)

**Status: frozen 2026-10-17.** The frozen split is in [`split-manifest.json`](split-manifest.json), SHA-256 `0353bc1e84787150eab2c13a0ca9fa4d2967227bc55a4df726a12cde5fc48bd4`. It holds ids and source hashes only, and is never overwritten. The owner waived the human label check. A sensitivity analysis that excludes every AI-assisted label replaces it (see "Labels").

## Purpose

The benchmark evaluates systems that repair broken SIEM detections. Each system gets a Sigma rule that misbehaves, plus labeled telemetry, and must restore the rule's coverage, report missing telemetry, or abstain. It also must not weaken the rule. It supports the comparison of B0 (deterministic), B1 (retrieval), B2 (an open model) and M1 (fine-tuned) in plan sections 12 and 13.

**Out of scope:**
- training or evaluating malware or attack classifiers;
- telemetry from any organization;
- rules outside the supported single-event Sigma subset ([ADR 0002](../../docs/adr/0002-sigma-subset-common-idioms.md)).

## Sources

All sources are public and pinned; licenses are recorded in [`sources.md`](sources.md).

| Source | Revision | License | Role |
| --- | --- | --- | --- |
| SigmaHQ `rules/windows/process_creation`, `regression_data` and full git history | r2026-07-01 (`552f3fee`) | DRL 1.1 | Rules, attack recordings, natural maintenance fixes |
| OTRF Security-Datasets `datasets/atomic/windows` | `d9d40ef1` | MIT | Recorded attack simulations, which supply candidate positives and background negatives |
| Atomic Red Team `atomics/` | `388942ad` | MIT | Read as data only; nothing was executed |

## Construction

1. **Supported rules.** 997 of 1,182 process-creation rules parse into the supported subset and convert with pinned pySigma.
2. **Positives.** The pool holds 137 SigmaHQ regression recordings and 159 OTRF events labeled malicious, 296 positives in all. Replay on the pinned Elasticsearch 8.19.3 matches each rule against the pool. On every rule that declares a count, the replay matches exactly SigmaHQ's declared `match_count` (83 of 83).
3. **Roots.** A root is a rule with at least one verified positive. With 42 verified natural fixes added, 187 roots are eligible.
4. **Split.**
   - Roots are grouped by rule family (largest group: 19 rules) and assigned whole by a seeded hash.
   - Every positive event belongs to exactly one split, with priority test, then development, then train. That dropped 5 shared positives and moved 2 roots to reserve.
   - The preview has test 14 roots, development 12, train 39 and reserve 122.
5. **Cases.** Each root gets a healthy control plus up to three verified faults.
   - The fault types are mapping drift, missing telemetry and a one-edit logic fault, all synthetic.
   - Natural cases come from SigmaHQ maintenance commits, where the fix catches a recorded attack that the earlier version missed.
   - A fault is kept only if it costs at least one detection.

| Kind | Provenance | Cases |
| --- | --- | --- |
| healthy control | synthetic | 61 |
| logic | synthetic | 61 |
| mapping drift | synthetic | 47 |
| missing telemetry | synthetic | 47 |
| natural fix | natural | 13 |

By split, the synthetic cases are train 124, development 40 and test 52, and the natural cases are train 7, development 4 and test 2. 168 cases have a single verified positive and therefore no validation suite; their repairs are reported as provisional.

## Labels

**Event labels** are `malicious`, `benign` or `unknown`.

- SigmaHQ regression events are malicious by construction.
- The 175 OTRF candidates were labeled **with AI assistance**. Two independent AI reviewers agreed on 94.3% of events (κ = 0.53), and a third AI reviewer adjudicated the 10 disagreements, all to `unknown`. The result is 159 malicious, 3 benign and 13 unknown.
- Every such label carries `ai-` reviewer provenance.

**Background negatives** are labeled benign *relative to the rule*. They are events the healthy reference does not match: the "must not fire" oracle of plan section 10. Without them, a repair that weakened a rule would go unnoticed.

## Integrity guarantees

- Every source file is SHA-256 manifested and re-verified before use.
- Splits are assigned by root, and no positive event appears in two splits.
- B1's memory and M1's training data come from train only. Development is used for monitoring, and test is read only with `--locked`.
- Prompts and SFT examples hold no event values.
- Engine or conversion errors are failures, never "no match".
- Case folders hold raw event values and stay private on the cluster. Only aggregate reports, which hold ids, counts and hashes, are published.

## Known limitations and biases

- **Small and skewed.** 65 roots are in the evaluated splits, most with one positive, so the intervals are wide and the results exploratory.
- **The synthetic faults partly mirror B0's search space.** Logic faults are one-edit mutations, so the deterministic baseline is favored on them. Natural faults are the unbiased probe, but there are only 13.
- **AI-assisted labels.** The owner waived the human check of 10 adjudicated events and a 10% sample. A sensitivity run that drops every AI-assisted label reaches the same conclusions (see Results). Some console-host children of attacker shells are `unknown` by design.
- **Process creation only:** Windows Sysmon EID 1, in an ECS-style layout. Other log sources and schemas are not covered.
- **False-positive fixes are not represented.** A natural fix that only removes false positives cannot be verified without reviewed benign events.

## Results

The full tables are in [`qc/README.md`](qc/README.md), under "Final results on the frozen split".

**Best possible validated success.** Cases with one recorded attack have no validation suite, so the best possible validated success is below 1:
- development: 0.591;
- test: 0.648;
- sensitivity run: 0.476.

**Systems:**
- **B0 (deterministic) and B1 (retrieval)** reach 1.000 of the provable development cases and 0.971 of the provable test cases.
- **B2 (an unmodified 7B model)** is the only system measurably worse: −0.074 against B0 on test (95% CI −0.135 to −0.018). It also weakens rules.
- **M1 (LoRA fine-tune)** ties B0 and B1 on test with all three seeds and never weakens a rule.

**Sensitivity run.** Without AI-assisted labels every system reaches the 0.476 ceiling, and the ordering on outcome match and weakening is unchanged.

The test split was evaluated once, on 2026-10-18 (Slurm jobs 11177293 to 11177301 and 11190540 to 11190542).
