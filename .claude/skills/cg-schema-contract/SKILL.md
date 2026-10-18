---
name: cg-schema-contract
description: Define or change versioned contracts and records - the detect report and candidate envelope, replay results, fixture and mapping formats, Pydantic API models, the OpenAPI schema and the dashboard types in frontend/src/lib/types.ts. Use when changing an API route, report field or envelope. Do not use for UI-only styling or for telemetry field mappings (use cg-telemetry-ingest or cg-sigma-adapter).
---

# Versioned schema and contract changes

Plan refs: sections 7, 8, 16. Platform decision: `docs/adr/0001-platform-direction.md`.

## Expected inputs

- The record or route being changed and the ticket ID.
- Current Pydantic models and dataclasses in `src/kestrix/`, the OpenAPI schema (`GET /api/openapi.json`, or `create_app().openapi()`), and `frontend/src/lib/types.ts`.

## Steps

1. State the invariant for each touched record from the section 7 table (for example, a candidate binds `original_sha256`; a selected artifact is frozen before validation).
2. Bump an explicit `schema_version` on any changed envelope or report (`detect/workflow.py` `SCHEMA_VERSION`, `detect/candidate.py`, mapping `schema_version`). Keep existing fields backward compatible within a minor version, or record the break in `CHANGELOG.md`.
3. Keep score and label fields distinct: replay counts, heuristic scores and model text are never merged or relabeled as confidence.
4. There is no database in this release. Persisted state is content-addressed evidence JSON and the `secrets.json` config; a format change there needs a compatibility note.
5. Mirror the contract on both sides: Pydantic model (and its OpenAPI output) and the TypeScript type in `frontend/src/lib/types.ts`. Add a test that round-trips a fixture through the Python model, and keep `npm --prefix frontend run typecheck` passing.
6. Domain outcomes are explicit fields (`outcome`, `reason`); errors use `{reason, detail}`.
7. Status codes: 400, 403, 404, 413, 421, 422, 502, 503 as mapped in `server/app.py`. No stack traces in responses.
8. Never add a field that carries credentials or raw event payloads into evidence.

## Output evidence

- Diff of contract files, schema version changes, contract test names and their command output.
- A compatibility note for existing CLI JSON, API clients and the dashboard, plus the `docs/api.md` or module page update.

## Failure conditions (stop and report)

- A change would alter the meaning of an existing field or reason code without a version bump.
- A field would carry credentials or raw event payloads into evidence.
- Python and TypeScript contracts cannot be kept in sync within the slice.
