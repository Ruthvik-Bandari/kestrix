---
name: kx-repo-audit
description: Audit this Kestrix checkout and inventory commands, locks, security tests, evidence storage and generated assets. Use when starting a session on a fresh checkout, after a large merge, or when the inventory needs refreshing. Do not use to implement features or fix findings; it produces findings only.
---

# Kestrix repository audit

Read-only inspection that separates observed facts from assumptions. Plan refs: sections 3, 17, 19, 20. Platform decision: `docs/adr/0001-platform-direction.md`.

## Expected inputs

- The current checkout and `git log` / `git remote -v` / `git status`.
- `.claude/handoff.md` (previous session state), if present.

## Steps

1. Record current branch, HEAD SHA, whether the tree is clean, and untracked paths. Compare with the SHA in `.claude/handoff.md`; if they differ, say so; do not guess.
2. Confirm `LICENSE` is Apache-2.0 and that `NOTICE` and README credit the adapted projects (CyberSafeX Detection Suite, BitShield) and pySigma.
3. Inventory build and test entry points by reading files, not by assuming: `pyproject.toml` (scripts, extras, pytest markers, ruff and mypy config), `uv.lock`, `frontend/package.json` scripts and `frontend/.nvmrc`, `.github/workflows/*`, `scripts/*`. List each command with its source file.
4. Check dependency locks: `uv.lock`, `frontend/package-lock.json`, GitHub Actions pinned by SHA. Note anything unpinned (floating Docker tags, `latest` images, an Elasticsearch image without its digest).
5. Locate the security regression tests: `tests/server/test_platform_security.py` (Host, cross-site, body caps, headers), `tests/detect/test_review_regressions.py`, netguard and webcheck tests. Note which protections are covered and which are not.
6. Inspect persistence: there is no database; check `core/evidence.py` (content-addressed JSON, atomic rename) and `core/config.py` (secrets file location and mode).
7. Inspect evidence and upload paths, size limits and where hashes are computed. Confirm the generated bundles (`src/kestrix/detect/cases/`, `src/kestrix/server/static/`) match their generators.
8. Run only commands the user permits; record exact command and exit status. Commands not run are listed as not run.

## Output evidence

- A findings table: item, observation, source file:line, fact or assumption.
- Command inventory with status: ran-passed, ran-failed, not-run (reason).
- Gaps mapped to backlog items and the risks they create.

## Failure conditions (stop and report)

- The license or attribution has been removed.
- The audit would require reading `.env`, keys, `secrets.json`, `data/raw/` or `data/locked/`.
- A command needs network access or credentials the session was not given.
