# Code security scanning

The code module looks for common security mistakes in source code before they ship: shell and SQL injection, unsafe deserialization, disabled TLS checks, weak hashes and randomness, and hard-coded secrets. Run it on a checkout, in CI, or from a Claude Code hook on every file the assistant writes. Each finding names a rule, a CWE, why it matters and how to fix it. It is available from the CLI and as a Python function; there is no API route or dashboard page yet.

It is pattern analysis, not a proof. Rules miss things, and a finding can be wrong in context. Kestrix has not measured detection or false-positive rates for this module, so none are claimed; "no findings" means no rule fired, not that the code is secure. The design is recorded in [ADR 0005](../adr/0005-code-security.md); this page describes slice C1: the Python rules, the secret rules, the CLI, the output formats, exit codes, suppression and baselines. Source files are under [`src/kestrix/code/`](../../src/kestrix/code/).

## Privacy and safety

The scanner reads files as bytes and decodes them as UTF-8 (invalid bytes replaced). Python source is parsed with the standard-library `ast` module; nothing is imported, executed or sent off the machine. Secret values never leave the scanner: findings, JSON, SARIF, text output, baselines and hook output hold only the secret's kind, its location and its first four characters (for example `github_token:ghp_…`). Secrets found anywhere on a reported line are also redacted from the snippets of other findings.

## Commands

| Command | Options | Exit codes |
| --- | --- | --- |
| `kestrix code scan [PATH ...]` | `--format text\|json\|sarif`, `--output FILE`, `--fail-on low\|medium\|high\|critical\|none` (default `high`), `--baseline FILE`, `--write-baseline FILE`, `--diff BASE`, `--hook` | 0 no findings at or above `--fail-on`; 1 findings at or above it; 2 usage or input error |

`PATH` defaults to `.`. Errors print `Rejected (<reason>): <detail>` to stderr and exit 2: a missing path, an unreadable or malformed baseline, `--diff` outside a git work tree or with an unknown ref.

```text
$ kestrix code scan app.py
app.py
  4:5  HIGH  py.subprocess.shell_true  CWE-78
      subprocess.run runs a built command through the shell (shell=True).
      fix: Pass the command as a list of arguments without shell=True, for example subprocess.run(['git', 'log', ref], check=True). Use shlex.quote only when a shell is unavoidable.

1 finding(s): 0 critical, 1 high, 0 medium, 0 low in 1 file(s); 0 suppressed, 0 in baseline, 0 skipped; fail-on high.
```

Text output groups findings by file. Severities are colored only when stdout is a terminal. The last line is the notice that rules can miss things.

**Options.**

- `--format json` prints the full report (below). `--format sarif` prints SARIF 2.1.0 for GitHub code scanning.
- `--output FILE` writes the report to `FILE` instead of stdout; the exit code is the same.
- `--fail-on` sets the lowest severity that makes the command exit 1. `none` always exits 0 after a successful scan.
- `--baseline FILE` leaves out findings whose fingerprint is in `FILE`, a JSON list of fingerprints. `--write-baseline FILE` scans, writes the fingerprints of every current finding to `FILE` (sorted, mode 0644, written to a temporary file and renamed), prints how many it wrote and exits 0. It ignores `--baseline`, so the new file covers everything found today.
- `--diff BASE` keeps only findings on lines added or changed since the git ref `BASE`, comparing the working tree (staged or not) with `git diff --unified=0`. Untracked files that are not ignored count as wholly new. Refs that start with `-` are refused.
- `--hook` is the Claude Code mode described [below](#claude-code-hook). It ignores the other options.

## What is scanned

- **Directories** are walked without following symbolic links. These directories are always skipped: `.git`, `.hg`, `.svn`, `node_modules`, `bower_components`, `.venv`, `venv`, `dist`, `build`, `__pycache__`, `.mypy_cache`, `.ruff_cache`, `.pytest_cache`, `.tox`, `site-packages`, `vendor`, `third_party`.
- **`.gitignore`** is honored. Inside a git work tree Kestrix asks git (`git ls-files --cached --others --exclude-standard`), so nested ignore files and global excludes apply. Elsewhere it reads the root `.gitignore` with a small parser that supports comments, `!` negation, trailing `/` for directories, anchored patterns, `*`, `?`, `[...]` and `**`.
- **A file named on the command line** is scanned even if it is ignored, so a hook can check a file such as `.env`.
- **Limits:** files over 1 MiB are skipped as `too_large`; files with a NUL byte in their first 8 KiB as `binary`; at most 20,000 files per scan, after which `truncated` is true. A symbolic link whose target is outside the scan root is skipped as `symlink_outside_root`; a link inside the root is scanned once, under its target's path.
- **Python rules** run on `.py` and `.pyw` files. A file that does not parse is listed as `syntax_error` (or `too_complex` for pathological nesting); the secret rules still run on it.
- **Secret rules** run on every text file.

Finding paths are relative to the scan root: the current directory when every path is inside it, otherwise the paths' common parent.

## Rules

Every rule was written for Kestrix from public CWE guidance; none is copied from another scanner. Each has positive and negative tests in [`tests/code/`](../../tests/code/). The table is generated from the registry in [`rules.py`](../../src/kestrix/code/rules.py) by `scripts/build_code_rules_doc.py`, and a test fails if it drifts.

<!-- rules:start (generated by scripts/build_code_rules_doc.py) -->
| Rule id | Applies to | CWE | Severity | Confidence | What it finds |
| --- | --- | --- | --- | --- | --- |
| `py.exec.eval` | Python | CWE-95 | high | medium | eval() of a value that is not a literal |
| `py.exec.exec` | Python | CWE-95 | high | medium | exec() of a value that is not a literal |
| `py.exec.compile` | Python | CWE-95 | medium | medium | compile() of a value that is not a literal |
| `py.subprocess.shell_true` | Python | CWE-78 | high | high | Command run through a shell |
| `py.os.system` | Python | CWE-78 | high | high | os.system or os.popen with a built command |
| `py.deserialize.pickle` | Python | CWE-502 | high | medium | Unsafe deserialization (pickle, dill, shelve, marshal) |
| `py.deserialize.yaml_unsafe` | Python | CWE-502 | high | high | YAML loaded with a loader that can build objects |
| `py.sql.string_built` | Python | CWE-89 | high | medium | SQL statement built from strings |
| `py.tls.verify_disabled` | Python | CWE-295 | high | high | TLS certificate or hostname verification disabled |
| `py.crypto.weak_hash` | Python | CWE-328 | medium | medium | MD5 or SHA-1 hash |
| `py.crypto.insecure_random` | Python | CWE-330 | medium | medium | random module used for a secret value |
| `py.tempfile.mktemp` | Python | CWE-377 | medium | high | tempfile.mktemp returns a name, not a file |
| `py.flask.debug` | Python | CWE-489 | medium | medium | Debug mode enabled |
| `py.jwt.no_verify` | Python | CWE-347 | high | high | JWT decoded without verifying the signature |
| `py.xml.unsafe_parser` | Python | CWE-776 | low | low | Standard-library XML parser on data that is not a literal |
| `py.assert.security` | Python | CWE-617 | low | medium | assert used for an access check |
| `py.path.traversal` | Python | CWE-22 | medium | medium | File path built from request data |
| `secret.aws_access_key_id` | any text file | CWE-798 | high | high | AWS access key id |
| `secret.aws_secret_access_key` | any text file | CWE-798 | critical | medium | AWS secret access key |
| `secret.github_token` | any text file | CWE-798 | critical | high | GitHub token |
| `secret.slack_token` | any text file | CWE-798 | critical | high | Slack token |
| `secret.stripe_live_key` | any text file | CWE-798 | critical | high | Stripe live secret or restricted key |
| `secret.google_api_key` | any text file | CWE-798 | high | high | Google API key |
| `secret.private_key` | any text file | CWE-798 | critical | high | Private key block |
| `secret.jwt` | any text file | CWE-798 | high | medium | JSON Web Token |
| `secret.anthropic_api_key` | any text file | CWE-798 | critical | high | Anthropic API key |
| `secret.openai_api_key` | any text file | CWE-798 | critical | medium | OpenAI-style API key |
| `secret.generic` | any text file | CWE-798 | high | medium | Hard-coded credential |
<!-- rules:end -->

**How the Python rules decide.** Calls are resolved through imports and aliases (`import subprocess as sp`, `from os import system`). A name counts as a literal when every assignment to it in its function, or in the module, is a literal; a fixed command or query is not reported. When an argument cannot be classified, the rule stays quiet: the rules prefer missing a case to flagging safe code.

- `py.subprocess.shell_true` drops to **low** when the command is a literal. `subprocess.getoutput`, `subprocess.getstatusoutput` and `asyncio.create_subprocess_shell` always use a shell and are reported with a built command.
- `py.crypto.weak_hash` drops to **low** with `usedforsecurity=False`, which marks a checksum.
- `py.deserialize.yaml_unsafe` accepts `SafeLoader`, `CSafeLoader` and classes defined in the same file that derive from them; a loader it cannot resolve is not reported.
- `py.sql.string_built` reports `execute`, `executemany`, `executescript`, `.raw()` and SQLAlchemy `text()` when the first argument is an f-string, `%`-formatted, `+`-concatenated or `.format()`-ed string (directly or through a variable) whose literal text contains SQL such as `SELECT ... FROM`, `WHERE ... =` or `INSERT INTO`.
- `py.crypto.insecure_random` reports `random.*` calls in a value assigned to a name, attribute or key whose words include token, secret, password, key, nonce, salt, otp or csrf (not sort or cache keys), and in the return value of a function named that way. `random.SystemRandom` is fine.
- `py.flask.debug` reports `app.run(debug=True)`, `app.debug = True` and `app.config["DEBUG"] = True` in files that import Flask, and a module-level `DEBUG = True` in `settings*.py` or a `settings/` package.
- `py.assert.security` ignores test files (`tests/`, `test_*.py`, `*_test.py`, `conftest.py`).
- `py.path.traversal` follows Flask `request.args`, `form`, `files` and similar, and Django `request.GET`, `POST`, `FILES` and `COOKIES`, into `open`, `os.path.join` and `flask.send_file`. `secure_filename` and `os.path.basename` clear the value, and a function that resolves the path and checks containment (`is_relative_to`, `commonpath`, or `realpath`/`abspath`/`resolve` with `startswith`) is not reported. FastAPI parameters are not tracked.
- One finding per rule per line.

**How the secret rules decide.** Provider rules match the documented shape of each credential and need at least 3.0 bits of entropy per character, which drops runs such as `ghp_xxxx…`. Values that contain placeholder words (example, changeme, test, your, xxxx, a `${...}` or `<...>`) are ignored, which also drops the AWS documentation key. A private key needs its base64 body, not just the `BEGIN` line. `secret.generic` needs a credential-like name (password, secret, api_key, token, client_secret and similar, but not names ending in `_url`, `_path`, `_env`, `_hash`, `_id` and similar) assigned a quoted value, or an unquoted `NAME=value` line as in `.env` files, and the value must be at least 16 characters, have at least 3.5 bits of entropy per character, mix character classes and not look like a URL, path, dotted name or environment-variable name. A provider match wins over a generic match of the same value. Severities: critical for live provider credentials and private keys; high for AWS access key ids, Google API keys, JWTs and generic credentials.

## Suppression

Add `# kestrix: ignore[rule-id] reason` on the finding's line or the line above. Several ids may be given, separated by commas. `// kestrix: ignore[...] reason` works the same way, for files with `//` comments.

```python
subprocess.run(BUILD_COMMAND, shell=True)  # kestrix: ignore[py.subprocess.shell_true] fixed command from this file
```

The reason is required. A suppression without one suppresses nothing and adds a note with id `kestrix.suppression.missing_reason` to the report (the text output prints it as `note:`). Notes never change the exit code. The report counts suppressed findings in `suppressed`.

## Baselines and fingerprints

A fingerprint is the SHA-256 of the rule id, the path and the snippet with all whitespace removed. It leaves out the line number, so a finding keeps its fingerprint when code above it moves or its indentation changes. Two findings of the same rule on identical lines of one file share a fingerprint. For secrets the snippet is the redacted form, so replacing one secret with another of the same kind and prefix on the same line keeps the fingerprint.

To adopt the scanner on existing code: `kestrix code scan --write-baseline .kestrix-baseline.json`, commit the file, then run `kestrix code scan --baseline .kestrix-baseline.json` in CI. The report's `baseline_filtered` says how many findings the baseline left out.

## Report

`--format json` prints a `ScanReport` ([`models.py`](../../src/kestrix/code/models.py)):

| Field | Meaning |
| --- | --- |
| `schema_version`, `generated_by`, `notice` | `1`, `"Kestrix by Ruthvik Bandari"`, and the pattern-analysis notice |
| `root` | absolute scan root; finding paths are relative to it |
| `diff_base`, `fail_on` | the `--diff` ref (or null) and the failure threshold |
| `files_scanned` | files read and checked |
| `files_skipped` | `{path, reason}` with reason `binary`, `too_large`, `unreadable`, `syntax_error`, `too_complex` or `symlink_outside_root` |
| `truncated` | true when the 20,000-file limit stopped the scan |
| `findings` | most severe first, then by path, line and column |
| `counts` | findings per severity |
| `suppressed`, `baseline_filtered` | findings left out by suppressions with a reason and by the baseline |
| `notes` | scanner notes, such as suppressions without a reason |
| `duration_ms` | wall-clock time of the scan |

Each finding has `rule_id`, `cwe`, `severity` (`low`, `medium`, `high`, `critical`), `confidence` (`low`, `medium`, `high`), `path`, `line`, `column`, `end_line`, `message`, `why`, `fix`, `snippet` (at most 200 characters; redacted for secrets) and `fingerprint`.

## SARIF

`--format sarif` writes SARIF 2.1.0 ([`sarif.py`](../../src/kestrix/code/sarif.py)). The driver is named `Kestrix` with `informationUri` `https://github.com/Ruthvik-Bandari/kestrix`, and lists every rule with a short description (the title), a full description (why it matters), help (the fix), tags `security` and the CWE, a `precision` from the confidence and a `security-severity` of 9.5, 8.0, 5.5 or 3.0 for critical, high, medium and low. GitHub documents `security-severity` as a number written in a string, and Kestrix follows that. Each result carries its level (`error` for critical and high, `warning` for medium, `note` for low), the location relative to the `SRCROOT` base, the redacted snippet and the fingerprint as `partialFingerprints["kestrixFingerprint/v1"]`.

## Claude Code hook

`kestrix code scan --hook` is meant for a Claude Code `PostToolUse` hook on `Write`, `Edit` and `MultiEdit`. It reads the hook JSON from stdin, takes the file from `tool_input.file_path` (or the `file_path` of each entry in `tool_input.edits`), resolves a relative path against the payload's `cwd`, and scans that file. When it finds anything at medium severity or above, it prints:

```json
{"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "Kestrix found 1 security issue(s) ... Fix: ..."}}
```

The context lists up to 20 findings with their location, severity, rule, CWE, message and fix, and explains how to suppress a false positive. Without such findings it prints nothing. It always exits 0: malformed input, a missing file or a scanner error produces no output and a one-line note on stderr, so the hook never blocks the editor. A test checks that a 2,000-line file is handled in under 1.5 s. The plugin that installs this hook is slice C2.

## Python API

```python
from kestrix.code import exit_code, scan

report = scan(["src"], fail_on="high")
for finding in report.findings:
    print(finding.path, finding.line, finding.rule_id, finding.fix)
raise SystemExit(exit_code(report))
```

`scan(paths, *, root=None, fail_on="high", baseline=None, diff_base=None) -> ScanReport` raises `Rejected` for the input errors listed under [Commands](#commands). `exit_code(report, fail_on=None)` returns 0 or 1 using the report's threshold unless one is given.

## Limits

- Only Python has code rules in this slice. JavaScript and TypeScript rules are slice C3.
- Data flow is local: names are followed through assignments in the same function or module, a few hops deep, and not across functions or files.
- The secret rules are high-precision on purpose and miss credentials with no recognizable shape or name.
- Column numbers come from the parser's offsets and can be off on lines with non-ASCII characters before the finding.
