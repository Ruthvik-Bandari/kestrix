# Changelog

All notable changes to `kestrix-scan`. Rule ids and the JSON report (`schema_version`) are a stable
interface: renaming a rule or a report key is a breaking change and is recorded here.

## Unreleased

- **Taint analysis (Python):** an intraprocedural forward data flow from Flask, Django and FastAPI request
  data, LLM client output (Anthropic, OpenAI, LiteLLM, Ollama, Google GenAI, LangChain), `input()`/`sys.argv`
  and environment variables, with per-sink sanitizers (`shlex.quote`, `basename`/`secure_filename`,
  `html.escape`, numeric conversion, resolve-and-contain guards). `py.exec.*`, `py.subprocess.shell_true`,
  `py.os.system` and `py.sql.string_built` keep their pattern behaviour and gain the source's confidence and a
  trace when tainted data reaches them. `py.path.traversal` is now taint-based: it reports at the file operation
  (`open`, `send_file`, `FileResponse`, `Path.read_text` ...) instead of at `os.path.join`, follows FastAPI
  parameters and LLM output, and accepts a resolve-and-contain guard only on the guarded name.
- **New rules:** `py.ssrf.request` (CWE-918), `py.redirect.open` (CWE-601), `py.xss.markup` (CWE-79, CWE-1336 for
  template source), `py.llm.output_to_sink` (CWE-94/78/89/22 by sink; replaces the pattern finding on that
  line), `py.ml.unsafe_model_load` (CWE-502; `torch.load`, `joblib.load`, pickled model files, Keras
  `safe_mode=False`, `trust_remote_code=True`), and `config.claude.hook_remote_exec`,
  `config.claude.permissions_bypass`, `config.mcp.unpinned_launcher`, `config.mcp.secret_inline` and
  `config.claude.env_leak` for `.claude/settings*.json`, plugin `hooks/hooks.json` and `.mcp.json`. 38 rules.
- **Report:** findings may carry `trace` (a list of `{line, note}`); the key is present only on taint findings,
  so `schema_version` stays 1 and existing reports are unchanged. SARIF results carry it as `codeFlows`; the
  text report prints a `trace:` line and the hook context a compact `[trace: L4→L7]`. A finding's `cwe` and
  `confidence` can now differ from the rule default.
- **Behaviour changes:** `pickle.load` of a model file reports `py.ml.unsafe_model_load` instead of
  `py.deserialize.pickle`; a secret in a configuration file reports the `config.*` rule instead of `secret.*`.
  New rules sit after `py.path.traversal` in the registry, so SARIF `ruleIndex` values of the `secret.*`
  rules moved.

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
