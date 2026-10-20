# Changelog

All notable changes to `kestrix-scan`. Rule ids and the JSON report (`schema_version`) are a stable
interface: renaming a rule or a report key is a breaking change and is recorded here.

## Unreleased

### Added

- **Offline dependency scanning.** `kestrix-scan db update [--ecosystem PyPI npm]` downloads the OSV exports
  over HTTPS (2 GiB cap, atomic writes, ETag reuse) and builds a local SQLite index with each download's
  SHA-256 and time; it is the only command that uses the network. `kestrix-scan db status` shows its age and
  counts. Scans then check `requirements*.txt` (exact pins), `uv.lock`, `poetry.lock`, `pdm.lock`,
  `Pipfile.lock`, `package-lock.json` v2/v3, `yarn.lock` v1 and Berry, and `pnpm-lock.yaml` with PEP 440 and
  SemVer range matching.
- **New rules** `dep.vulnerable` (CVSS-based severity, OSV CWE, "upgrade to" fix) and `dep.malicious`
  (critical; OpenSSF `MAL-` reports), appended to the registry, so earlier SARIF `ruleIndex` values are
  unchanged. Notes `dep.db_stale` (missing or 7-day-old index, once per scan), `dep.not_checked` and
  `dep.unsupported`.
- **Configuration:** `ignore-advisories = {"GHSA-..." = "reason"}` and `claude.install-guard = false`.
  Requirements lines accept `# kestrix: ignore[<advisory id>] reason`.
- **Claude Code install guard:** a `PreToolUse` hook on `Bash` that denies installing a known malicious
  package and warns about a known-vulnerable pinned version (`pip`, `uv`, `npm`, `pnpm`, `yarn`). It fails
  open and is turned off with `KESTRIX_INSTALL_GUARD=0`.
- `kestrix-scan init --ci github` runs `kestrix-scan db update` before the scan.

### Changed

- Lockfiles up to 64 MiB are scanned (other files keep the 1 MiB limit); a lockfile over 1 MiB gets only the
  dependency check.

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
