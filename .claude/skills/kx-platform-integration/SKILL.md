---
name: kx-platform-integration
description: Wire an Kestrix module function into the CLI, the FastAPI routes in src/kestrix/server and the React dashboard in frontend/ - commands, exit codes, routes, report rendering and evidence export. Use when exposing new analysis results to users. Do not use for changing rule semantics, replay internals or ML training.
---

# CLI, API and dashboard integration

Plan refs: sections 4 (FR05-FR10), 5 (analyst workflow), 6, 7, 8 (routes, job behavior), 17. Platform decision: `docs/adr/0001-platform-direction.md`.

## Expected inputs

- The contracts from kx-schema-contract and the module functions in `src/kestrix/<module>/`.
- The target CLI command, API route(s) and affected dashboard pages under `frontend/src/features/`.

## Steps

1. Keep one core: `src/kestrix/<module>/cli.py` and `api.py` call the same function and add no business logic.
2. The CLI emits a text summary by default and the full report with `--json`. Exit codes match domain outcomes (detect: 0, 2, 3, 10, 11) and are documented.
3. Each route validates its body with a Pydantic model, raises `Rejected(Reason, detail)` for invalid input, and maps non-400 reasons in `server/app.py` `_STATUS`. Large bodies need a `LARGE_BODY_ROUTES` entry and a streaming or field limit.
4. Artifacts: write temp, SHA-256, atomic rename (`core/evidence.py`). Evidence holds content and hashes, never secrets.
5. Long-running work stays synchronous in this release. Durable jobs, the outbox, leases, analyst accounts and approval records are deferred until a shared deployment exists (ADR 0001); do not add them inside a slice.
6. Every new route keeps the `_LocalOnly` protections and gets tests for Host refusal, cross-site refusal and body caps where relevant (`tests/server/`).
7. The dashboard shows original rule, diff, replay counts, abstention reason and evidence download. Unsupported, insufficient-evidence and engine-error states are explicit. Outbound actions say what leaves the machine.
8. Model failure or a missing AI key must not block static diagnosis, original replay or evidence inspection.
9. For UI work, follow `.claude/rules/ui.md`; for routes, `.claude/rules/backend.md`. Update `docs/api.md` and the module page.

## Output evidence

- Route list with their tests, CLI JSON sample from synthetic fixtures, exit-code tests, and command output for `uv run pytest`, `uv run mypy`, `uv run ruff check src tests scripts` and `npm --prefix frontend run build`.

## Failure conditions (stop and report)

- Logic would be duplicated between the CLI, the API or the dashboard.
- A route would weaken the loopback, cross-site or body-size protections, or return a secret.
- Model failure would block static diagnosis, original replay or evidence inspection.
