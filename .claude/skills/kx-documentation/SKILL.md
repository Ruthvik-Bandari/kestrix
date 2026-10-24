---
name: kx-documentation
description: Update docs to match implemented and verified behavior - support matrix, ADRs, API docs, provenance notes, model and dataset cards, docs/handoff.md and attribution. Use at the end of a slice or when behavior changed. Do not use to document planned or unverified features as if they exist, or to edit CLAUDE.md into a long history log.
---

# Documentation of implemented behavior

Plan refs: sections 3 (attribution), 7 (provenance), 17 (definition of done), 22 (handoff), 24 (claim discipline).

## Expected inputs

- The completed slice's diff, commands actually run and their results.
- Existing docs in `docs/` (architecture, api, support matrix, ADRs) and `docs/handoff.md`.

## Steps

1. Describe only behavior verified by tests or commands in this session. Label anything else as planned or unverified.
2. Update the support matrix: each Sigma operator and log source as supported, rejected or pending engine verification, with the pinned backend, target and engine digest.
3. Update API docs or OpenAPI references when routes or schema versions changed.
4. Record provenance for any new data: source, revision, license, labels, split.
5. Model and dataset cards state exact revisions, licenses, intended use, limitations, and that small-sample results are exploratory.
6. Keep upstream attribution intact; mark inherited versus new components.
7. Update `docs/handoff.md`: git SHA, completed slice, commands actually run, failed or skipped checks, artifact IDs, next action.
8. Keep `CLAUDE.md` short; history belongs in git and the handoff.

## Output evidence

- List of doc files changed and the evidence each claim is based on.

## Failure conditions (stop and report)

- A requested statement is not supported by evidence (e.g. "zero false positives" from a small sample).
- Documentation would include credentials, raw telemetry or locked test content.
