---
name: kx-sigma-adapter
description: Implement or change Sigma parsing, the supported single-event subset, capability rejection, processing pipelines and pinned pySigma conversion to the Elasticsearch target. Use when rule semantics, operators, modifiers, field mappings or the compatibility matrix change. Do not use for replay execution itself (kx-replay-harness) or for repair generation (kx-repair-baselines).
---

# Sigma subset and pinned conversion

Plan refs: sections 5 (version one semantics), 9 (diagnosis sequence, repair classes), 10 (engine fidelity), 16, 26 (version compatibility).

## Expected inputs

- Sigma YAML rule(s), synthetic only, under 100 KB each.
- The environment processing pipeline and reviewed field mappings.
- Pinned versions of pySigma, the Elasticsearch backend and target (Lucene by default; ES|QL only after golden fixtures prove it).

## Steps

1. Load YAML with a safe loader only. Reject custom tags, anchors/aliases bombs, duplicate keys and files over the size ceiling.
2. Build a rule AST. Verify required structure, `logsource` (process_creation, windows) and allowed operators.
3. Supported subset (ADR 0002): named selections as a field map or a list of field maps, exact values, lists, `contains`, `startswith`, `endswith`, optional `|all`, and `and` / `or` / `not` with `1 of` / `all of` quantifiers expanded at parse time. Reject with explicit reason codes: aggregation, correlation, `near`, `re`/regex, `base64offset`, `cidr`, `windash`, wildcards in values, keyword selections, and unsupported logsources. Every new construct needs an engine test before it is accepted.
4. Compute and preserve SHA-256 for the rule, the pipeline and the compiled query.
5. Resolve the pipeline, then convert with the pinned backend. Record backend and target version in the output.
6. Define and test null, missing field, case and array handling; each behavior must later be confirmed by real-engine replay, not assumed.
7. Update the support matrix in `docs/` with every operator: supported, rejected, or pending verification.
8. Tests: hostile YAML, unsupported modifier, unknown field, Unicode and escaping, renamed field fixed by pipeline (mapping drift demo).

## Output evidence

- Parser and conversion test output, the hashes, compiled query text, support matrix diff.
- A statement that conversion success has not been treated as detection correctness.

## Failure conditions (stop and report)

- A request to "support everything" or to emulate Elasticsearch matching in Python.
- Backend or target versions cannot be pinned.
- An operator is marked supported without a golden replay fixture.
