# Detection repair: measured accuracy

This page collects every accuracy number that is committed for `kestrix detect`, with the file each one comes from. It adds no new measurement. The shipped system is **B0**, the deterministic generator; B1 (retrieval), B2 (an unmodified 7B model) and M1 (a LoRA fine-tune) are research systems that were compared against it and do not ship ([model card](../model-card.md)).

**What the benchmark is.** A small, partly synthetic set of faults injected into public SigmaHQ process-creation rules, replayed on the pinned Elasticsearch against recorded Windows Sysmon events (SigmaHQ regression data and OTRF captures). It is exploratory. It is not a measurement on your telemetry. Its labels are AI-assisted; the owner waived the human check, and a run without those labels reaches the same ceiling ([dataset card](../data/dataset-card.md)).

## Locked test, run once on 2026-10-18

54 cases from 14 rule roots. Source: [`data/qc/comparison-locked-test.md`](../data/qc/comparison-locked-test.md) and `.json`; weakened-rule counts from the [model card](../model-card.md).

| System | Validated success | Of provable cases | Outcome match | Abstained | Wrong change | Weakened rules |
| --- | --- | --- | --- | --- | --- | --- |
| B0, deterministic (shipped) | 0.630 | 0.971 | 0.982 | 0.018 | 0.000 | 0 |
| B1, retrieval | 0.630 | 0.971 | 0.982 | 0.018 | 0.000 | 0 |
| B2, unmodified model | 0.556 | 0.857 | 0.741 | 0.204 | 0.000 | 3 |
| M1, LoRA fine-tune, seeds 1 / 2 / 3 | 0.630 each | 0.971 each | 0.944 / 0.963 / 0.944 | 0.056 / 0.037 / 0.056 | 0.000 | 0 |

- **Best possible validated success is 0.648** (35 of 54 cases). A case whose rule has only one recorded attack event has nothing left to validate a repair on, so its repair is provisional by design and does not count as validated success. B0 reached 0.971 of the 35 provable cases.
- **Outcome match** counts a case as right when the outcome is the expected one, provisional repairs included.
- **B1 ties B0 on the locked test** (difference 0.000, no case won or lost). M1 ties B0 with all three seeds. **B2 is the only system measurably worse**: -0.074 against B0, 95% confidence interval -0.135 to -0.018, 0 cases won and 4 lost.
- **Success by fault kind on the locked test** (B0 and B1 alike): healthy rule left unchanged 1.00; missing telemetry reported 1.00; logic faults 0.31; mapping faults 0.31; natural faults 0.00. Logic and mapping are low because most of those repairs are provisional, not because they were wrong (wrong change is 0.000).
- **Tied does not mean better.** Nothing beat the deterministic baseline, so none of the learned systems ships.

## Development split (44 cases, 12 roots)

Source: [`data/qc/comparison-frozen-development.md`](../data/qc/comparison-frozen-development.md). Best possible validated success is 0.591 (26 of 44).

| System | Validated success | Outcome match | Abstained | Weakened rules |
| --- | --- | --- | --- | --- |
| B0 | 0.591 | 0.932 | 0.000 | 3 |
| B1 | 0.591 | 0.932 | 0.068 | 0 |
| B2 | 0.523 | 0.659 | 0.273 | 3 |
| M1, seeds 1 / 2 / 3 | 0.568 / 0.568 / 0.545 | 0.886 / 0.864 / 0.864 | 0.114 / 0.136 / 0.136 | 0 |

B0 reached its score on development by weakening 3 rules (the repaired rule also matched benign events). B1 matches B0's validated success with none, which is why B1 is the recommended research baseline. On the locked test B0 weakened none.

The sensitivity run without AI-assisted labels (42 cases, 13 roots; [`data/qc/comparison-sensitivity-development.md`](../data/qc/comparison-sensitivity-development.md)) has a best possible success of 0.476, and every system reaches it.

## Natural faults

Natural faults are maintainer fixes mined from SigmaHQ history. They are the unbiased probe, because the synthetic faults partly mirror B0's own search space. There are few of them (13 cases across the splits; 4 on development). Validated success on them is 0.00 for every system on both the development split and the locked test, so **no claim is made for repairs of real-world rule drift**. Source: [`data/qc/README.md`](../data/qc/README.md), "Corrected results".

## Rule coverage and replay fidelity

Sources: [`data/qc/README.md`](../data/qc/README.md) (jobs 11086173 and 11105959), `replay-positives.json`.

- **997 of 1,182 SigmaHQ process-creation rules (84%) are in the supported subset**, and every one converts with the pinned pySigma backend. The other 185 (16%) are rejected with a reason code (`windash` 78, `re` 41, null matching 23, wildcards 21, value-count limits 17, `base64offset` 4, more than 16 alternative maps 1). That is the share of public Sigma rules `kestrix detect` answers `unsupported` for; the rate on your own rules is not measured.
- **Replay fidelity: 83 of 83 rules match exactly the number of events SigmaHQ declares.** Only single-rule regression folders have an unambiguous declared count, so 83 is the testable set. 997 rules replayed with 0 engine errors.
- 101 supported rules have SigmaHQ positive events, and 176 have at least one positive once unreviewed OTRF candidates are counted.

## Not published

These are not in any committed report, so no number is given for them:

- per-case outcomes of the locked test (only the aggregate comparison is committed), and the number of cases per fault kind on it;
- results on real production rules or telemetry, other log sources or schemas (the benchmark is Windows Sysmon process creation only);
- how often an analyst accepts a proposed repair, or review time saved;
- false-positive-only fixes (they need reviewed benign events to verify);
- the human check of the AI-assisted labels (waived by the owner).

The locked test is spent. A new comparison needs new held-out data.
