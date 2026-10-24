---
name: kx-repair-baselines
description: Add or change repair candidate generation and baselines B0 (maintained mappings and deterministic diagnostics), B1 (retrieval of reviewed training repairs) and B2 (unmodified open model with structured output), including the candidate envelope, AST edit bounds and abstention. Use when adding a repair method or the local model adapter. Do not use for fine-tuning or final evaluation.
---

# Repair candidates and comparable baselines

Plan refs: sections 9 (repair classes, structured output, negative controls), 12, 13 (comparison design), 14 (inference contract), 16.

## Expected inputs

- A diagnosis with failure family hypotheses and replay findings.
- The reviewed mapping set and training-partition repair examples (for B1/B2 retrieval).
- Candidate budget (max 4) and evidence budget, identical across methods.

## Steps

1. Implement the envelope: proposal_id, original_sha256, patch_kind, patch, reason_codes, evidence_event_ids, assumptions, model_revision, prompt_sha256, abstained, abstention_reason. Validate with Pydantic.
2. Allowed patches: named selection values, selection conditions, approved mapping transformation. Reject arbitrary code, unknown fields, new external resources, disabled selections, deleting the condition, or more than 3 AST node edits.
3. Prefer a pipeline mapping patch for renamed fields; keep portable rule logic unchanged.
4. Missing telemetry and unsupported semantics produce abstention with a telemetry recommendation, never a rule edit.
5. B1 retrieves only from the training partition. B2 receives bounded, sanitized context; the model adapter has no shell, database credentials or network tools.
6. Every candidate is applied to an immutable copy, re-parsed, compiled and replayed via kx-replay-harness. Explanatory text is not evidence.
7. Rank passing candidates by preserved attack scenarios, benign match reduction, then smaller edit. No passing candidate means abstain.
8. Store model scores as ranking scores, not confidence.

## Output evidence

- Candidate envelopes, rejection reasons, replay results per candidate, and per-baseline outcome counts including abstentions.

## Failure conditions (stop and report)

- A method needs development or locked test outcomes in its context.
- Budgets differ between baselines.
- A prompt includes raw restricted telemetry or credentials.
