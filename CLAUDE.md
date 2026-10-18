# Kestrix

Local-first security workbench: one Python package (`kestrix`) with a Typer CLI and a
FastAPI server that serves a bundled React dashboard on 127.0.0.1:8765. Platform decision:
`docs/adr/0001-platform-direction.md`. Detection-repair research plan:
`docs/CyberGuard_Engineering_Plan.md` (its CyberGuard/Spring Boot wording is historical).
Session state: `docs/handoff.md`. Workflow: `docs/claude/workflow.md`.

## Layout

- `src/kestrix/core/` reason codes, safe YAML/JSONL loading, netguard, config/secrets, evidence
- `src/kestrix/detect/` Sigma repair: rule, mapping, fixtures, engine, replay, diagnose,
  candidate, repair, workflow; bundled cases in `detect/cases/` (generated)
- `src/kestrix/forensics/`, `webcheck/`, `bitcoin/`, `mail/` the other four modules
- `src/kestrix/server/` FastAPI app; dashboard bundle built into `server/static/`
- `src/kestrix/cli.py` entry point; each module has thin `cli.py` and `api.py` adapters
- `frontend/` React + Vite dashboard source; `tests/` per module; `scripts/` generators
- Docs: `docs/modules/*.md`, `docs/api.md`, `docs/security-model.md`

## Commands

```bash
uv sync --all-extras
uv run pytest                          # engine tests skip if Elasticsearch is down
uv run pytest -m engine                # needs `uv run kestrix detect engine-up`
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run mypy
npm --prefix frontend run build        # lint/typecheck/test also exist
uv run python scripts/build_detect_cases.py   # regenerate bundled cases
python3 scripts/check_claude_pack.py && python3 .claude/hooks/test_protect_paths.py
```

## Invariants

- One core: CLI and API call the same module functions; no business logic in adapters.
- The pinned Elasticsearch 8.19.3 (digest-locked) is the only matching oracle. Never add a
  Python matcher as a stand-in, and never treat conversion success as proof.
- Engine or conversion errors are errors (`counts: null`), never "no match".
- Explicit outcomes with reason codes: `repaired`, `unchanged`, `abstained`, `unsupported`,
  `insufficient_evidence`, `engine_unavailable`. Errors raise `Rejected(Reason, detail)`.
- Repairs stay inside the candidate contract: at most 3 AST edits, 4 candidates, never drop a
  selection. Selection is frozen on development fixtures before independent validation.
- Untrusted input is data: `core/safe_load.py` only, bounded sizes and depth, no eval/exec/pickle.
- Outbound requests are opt-in and pass `core/netguard.check_url`; webcheck connects to the
  validated IP.
- Local mode (default) is loopback-only (Host allowlist, cross-site write refusal, body caps), no accounts.
  Hosted mode (`KESTRIX_MODE=hosted`, ADR 0004) adds Google/GitHub sign-in, sessions, CSRF and rate
  limits, serves only webcheck, forensics and mail, and never stores uploads; see `docs/hosted.md`.
- Secrets come from the environment or the 0600 `secrets.json`; never logged, returned or
  written to evidence.
- Bundled cases are synthetic. Never read `data/raw/` or `data/locked/`; no real telemetry in tests.
- Heuristic scores are labeled heuristics, not probabilities. Docs describe only verified behavior.
- Typed (strict mypy), no dead code, a test per behavior, `@pytest.mark.engine` on engine tests.
