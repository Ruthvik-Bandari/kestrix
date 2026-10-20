# Changelog

All notable changes to `kestrix-scan`. Rule ids and the JSON report (`schema_version`) are a stable
interface: renaming a rule or a report key is a breaking change and is recorded here.

## Unreleased

## 0.1.0

First release as its own package (ADR 0006). The scanner, its rules and the Claude Code plugin come from
`kestrix.code` and `kestrix.integrations` in Kestrix 0.1.0; their behaviour and output are unchanged.

- **Scanner:** Python AST rules (`py.*`) and secret rules (`secret.*`), inline suppressions with a required
  reason, baselines, `--diff`, and text, JSON (`schema_version` 1) and SARIF 2.1.0 output. Exit codes
  0, 1 and 2.
- **No runtime dependencies** on Python 3.11 and newer; `tomli` on 3.10. Python 3.10 to 3.13.
- **Command:** `kestrix-scan [scan] PATH ...` and `python -m kestrix_scan`, with `rules`, `version`, `init`
  and the Claude plugin and skill installers.
- **Configuration:** `[tool.kestrix]` in `pyproject.toml` or `.kestrix.toml`: `fail-on`, `exclude`,
  `rules.enable`, `rules.disable` and `baseline`. Flags override it; unknown keys warn; unknown rule ids
  exit 2 with a suggestion.
- **`kestrix-scan init`:** `[tool.kestrix]`, a pre-commit entry, a GitHub workflow that uploads SARIF with
  SHA-pinned actions, and the Claude Code plugin; idempotent.
- **pre-commit hook** `kestrix-scan` (`.pre-commit-hooks.yaml` at the repository root).
- **pytest plugin:** `pytest --kestrix [--kestrix-fail-on=LEVEL]`, off unless asked.
- **Python API:** `kestrix_scan.scan`, `Finding`, `ScanReport`, `rules()`, `load_config`, typed (`py.typed`).
- **Claude Code plugin:** hooks run `kestrix-scan`, falling back to `kestrix code scan`, and fail open.
