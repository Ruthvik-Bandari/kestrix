Paired on 54 cases from 14 roots (test split); baseline b0. Exploratory: a small benchmark of synthetic faults on public telemetry; intervals resample roots.

Best possible validated success: 0.648 (35 of 54 cases can be proven; a repair on a case with only one recorded attack has nothing left to validate it on, so it is provisional by design).

| System | Validated success | Of provable cases | Outcome match (incl. provisional) | Wrong change | Abstained | Δ success vs baseline (95% CI) | Won / lost |
| --- | --- | --- | --- | --- | --- | --- | --- |
| b0 | 0.630 | 0.971 | 0.982 | 0.000 | 0.018 | — | — |
| b1 | 0.630 | 0.971 | 0.982 | 0.000 | 0.018 | +0.000 (+0.000 to +0.000) | 0 / 0 |
| b2 | 0.556 | 0.857 | 0.741 | 0.000 | 0.204 | -0.074 (-0.135 to -0.018) | 0 / 4 |
| m1-seed1 | 0.630 | 0.971 | 0.944 | 0.000 | 0.056 | +0.000 (+0.000 to +0.000) | 0 / 0 |
| m1-seed2 | 0.630 | 0.971 | 0.963 | 0.000 | 0.037 | +0.000 (+0.000 to +0.000) | 0 / 0 |
| m1-seed3 | 0.630 | 0.971 | 0.944 | 0.000 | 0.056 | +0.000 (+0.000 to +0.000) | 0 / 0 |
