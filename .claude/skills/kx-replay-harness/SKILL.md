---
name: kx-replay-harness
description: Build or change replay execution that loads labeled fixtures into a run-specific index on the pinned Elasticsearch image and compares observed match IDs to expectations. Use when implementing validation execution, golden fixtures, acceptance policy or replay reports. Do not use to write a Python matcher, to generate attack activity, or to run locked test evaluation.
---

# Replay harness and validation policy

Plan refs: sections 6 (isolated engine), 9 (negative controls), 10 (all), 13, 16.

## Expected inputs

- A compiled query and its rule, pipeline and query hashes from kx-sigma-adapter.
- A DatasetVersion with stable event IDs and labels.
- The pinned Elasticsearch image digest and fixed index mappings.

## Steps

1. Create a run-specific disposable index with fixed mappings. The loader identity may write only to that index; the query identity is read-only.
2. Bulk-load events, refresh, and verify indexed count equals the manifest count. A mismatch is a failed run.
3. Execute the exact compiled query with pagination that retrieves every match. Truncation, timeouts and partial shards are recorded as errors, never as zero matches.
4. Compare observed IDs to labels: TP, FP, FN, TN for labeled events; unlabeled matches counted separately.
5. Apply the acceptance policy: all mandatory positives match, mandatory negatives behave, no loss of previously detected attack scenarios, no hidden errors, noise repairs reduce independently labeled benign matches.
6. Run negative controls: always-true, always-false, unknown-field substitution, benign overfitting. Each must fail policy.
7. Freeze candidate, mapping and suite hashes before validation. Record engine image digest in the run manifest.
8. Golden tests for missing fields, case sensitivity, arrays, keyword vs analyzed text, escaping, Unicode, timestamps and Boolean logic.

## Output evidence

- ValidationRun manifest (git SHA, hashes, engine digest, seed, timings, failure status), match ID lists, confusion counts, query text.
- Integration test output from a real container run, or an explicit note that it was not run.

## Failure conditions (stop and report)

- Elasticsearch is unavailable: report unavailable, do not substitute another matcher.
- The engine version differs from the pinned digest without a new compatibility run.
- Any request to read locked test fixtures during development.
