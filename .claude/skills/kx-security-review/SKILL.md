---
name: kx-security-review
description: Review a changed surface (parser, upload path, route, connector, worker, model adapter, export) against the section 16 threat table and report evidence-backed risks with concrete fixes. Use after a slice changes an input boundary, auth check, credential flow or artifact path. Do not use as a general code style review or to run offensive tests against external systems.
---

# Security review of a changed surface

Plan refs: sections 15, 16 (threat table, Claude boundary, runtime control), 7 (artifact integrity), 17.

## Expected inputs

- The diff or list of changed paths and the issue or slice name.
- Test output gathered by the main session (the reviewer reads evidence; it does not invent it).

## Steps

1. Map each changed path to section 16 threats: prompt injection in rules/logs, hostile or oversized input, credential disclosure, unauthorized case access, unreviewed rule weakening, supply chain, benchmark leakage, evidence alteration.
2. Parsers: safe YAML loader, size and nesting bounds, path traversal in any filename, no pickle or eval.
3. Routes: role and project checks on every new endpoint; cross-user and role denial tests present.
4. Model path: model receives sanitized bounded context and has no execution tools; an adversarial fixture with instructions in `CommandLine` cannot trigger an action.
5. Rule weakening: always-false and disabled-selection candidates are rejected by policy.
6. Secrets: grep the diff and generated evidence for tokens, keys, passwords; confirm credential references only.
7. Artifacts: hashes verified on load; approval invalidated on change; audit is append-only.
8. Network: services bind to loopback; connectors allowlist hosts and block metadata addresses.
9. Optionally hand findings and evidence to the `appsec-reviewer` agent.

## Output evidence

- Findings table: threat, location file:line, evidence, severity, fix, verifying test. Separate confirmed issues from unverified concerns.

## Failure conditions (stop and report)

- Review would require real credentials, raw telemetry or locked data.
- Evidence for a claim is missing: mark it unverified rather than asserting it.
