# ADR 0006: Two packages, a zero-dependency `kestrix-scan` and the full `kestrix` workbench

- Status: accepted
- Date: 2026-10-19
- Decision owner: Ruthvik Bandari

## Context

The code scanner and its Claude Code plugin (ADR 0005) are the part of Kestrix most likely to be adopted widely.
A plain `pip install kestrix` currently pulls in the dashboard server, the Sigma engine, HTTP clients, Pydantic
and Typer, and needs Python 3.12 or newer. That is heavy for someone who only wants a security check in their
project or in Claude Code. The owner chose two packages and support for Python 3.10 and newer.

## Decision

### `kestrix-scan`: lightweight and the entry point for most users

- **Import package:** `kestrix_scan`.
- **Commands:** `kestrix-scan` for the CLI, and `python -m kestrix_scan`.
- **Zero runtime dependencies** on Python 3.11 and newer. Only `tomli` is added on 3.10, for reading
  `pyproject.toml`. It uses the standard library throughout: `ast`, `argparse`, `dataclasses` and `json`.
  Pydantic and Typer are not used.
- **Python 3.10–3.13,** with all four tested in CI.
- **Contents:**
  - the rule engine (Python AST rules and secrets);
  - the file walker, baselines, suppressions, `--diff`, and text, JSON and SARIF output;
  - the `--hook` mode;
  - the Claude Code plugin, skills and commands, with `kestrix-scan install-claude-plugin`;
  - `kestrix-scan init`, which writes `[tool.kestrix]` config, a `.pre-commit-hooks` entry and a GitHub Actions
    workflow that uploads SARIF, and optionally installs the plugin;
  - a pytest plugin (`pytest --kestrix`) that is off unless requested;
  - a typed Python API: `kestrix_scan.scan(...) -> ScanReport`;
  - later: OSV dependency scanning, taint analysis and JS/TS rules.
- **Configuration:** `[tool.kestrix]` in `pyproject.toml`, or `.kestrix.toml`. It sets `fail-on`, `exclude`,
  `rules.enable` / `rules.disable` and `baseline`. Command-line flags override it.
- **Output stability:** the JSON report keeps a `schema_version`, and rule ids are stable. Renaming a rule is a
  breaking change and is recorded in the CHANGELOG.

### `kestrix`: the full workbench

- **Depends on** `kestrix-scan` with an exact version range.
- **Contains:** the dashboard and the modules for email, website, forensics, detection repair and Bitcoin, plus
  hosted mode.
- **The scanner command:** `kestrix code scan ...` delegates to `kestrix_scan`. `kestrix.code` is kept only as a
  thin re-export for compatibility.
- **Python 3.10–3.13.** Python 3.11+ features (`StrEnum`, `datetime.UTC`, `tomllib`) are replaced or
  backported.

### Repository layout

- A uv workspace: the root `kestrix` package, plus `packages/kestrix-scan/`.
- The repo-root Claude plugin marketplace points at the plugin inside `kestrix-scan`.
- **Releases:**
  - published to PyPI through GitHub OIDC trusted publishing, with build provenance attestations;
  - both packages are versioned together while the version is below 1.0.

## Consequences

- **Smaller install:** one fast, dependency-free install covers the scanner, CI, pre-commit, pytest and Claude
  Code uses.
- **Where the scanner lives:** its code moves out of `src/kestrix/code/`. Tests move with it. The `kestrix code`
  command and `kestrix.code` imports keep working.
- **The plugin's hooks:** they call `kestrix-scan`. If that is missing they fall back to `kestrix code scan`, and
  they fail open either way.
