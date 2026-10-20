# Code scanner scorecard: OWASP BenchmarkPython and the Kestrix cases

This page compares `kestrix-scan` with Bandit and with the regex layer of Anthropic's `security-guidance` plugin on two
test suites:

- [OWASP BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) v0.1, a public suite of 1,230 labelled
  Python test cases;
- the Kestrix cases in [`bench/cases`](../../bench/cases), 87 labelled cases written for this project.

Semgrep CE was also run. Its numbers are not published here; see [Semgrep](#semgrep) for why.

The machine-readable results are [benchmarkpython.json](benchmarkpython.json) and [owned.json](owned.json). The
harness is [`bench/run.py`](../../bench/run.py).

**Run:** 2026-10-20, Apple M4 Pro (12 cores), macOS 27.0.1, Python 3.12.13, Kestrix commit `3b74fd0`
(`kestrix-scan` 0.1.0, the scanner unchanged since `35d2e28`). The rules were not tuned on either suite.

## Read this first

- **BenchmarkPython v0.1 is early and synthetic.** Its authors call it "a preliminary initial release". Each case is
  a small Flask handler built from templates, and several categories reuse one sink with small variations.
- **These numbers measure category coverage on synthetic code.** They are not real-world detection or
  false-positive rates.
- **A category with no rule scores 0.** When a tool has no rule for a category, every vulnerable case is a miss
  (TPR 0) and the category still counts in the overall average. Kestrix has no rule for 4 of BenchmarkPython's 14
  categories.
- **The Kestrix cases are not neutral.** They were written by the Kestrix project, with knowledge of the Kestrix
  rules, and the configuration category exists only in Kestrix. Treat that table as a regression set, not as a
  comparison. Most of its categories have 1 to 4 cases, so a single case moves a score by 25 to 100 points.

## Results: BenchmarkPython v0.1

| Tool | Version | TPR % | FPR % | Score (TPR-FPR) | Precision % | Strict-CWE score | Runtime s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| kestrix | `0.1.0` | 43.3 | 27.5 | 15.8 | 59.0 | 15.8 | 1.2 |
| bandit | `1.9.4` | 48.4 | 30.9 | 17.5 | 71.9 | 9.3 | 1.6 |
| security-guidance | `2.0.14` | 21.7 | 20.1 | 1.6 | 43.9 | n/a | 0.4 |

**Bandit scores higher than Kestrix overall** (17.5 against 15.8). The difference comes mostly from weak randomness,
where Bandit finds 77 of 99 cases and Kestrix finds none.

| Category | Cases (vuln/safe) | kestrix | bandit | security-guidance |
| --- | --- | ---: | ---: | ---: |
| Command injection (`cmdi`) | 13/7 | -46.2 (7/6/7/0) | 0.0 (13/0/7/0) | -46.2 (7/6/7/0) |
| Code injection (`codeinj`) | 20/33 | 0.0 (20/0/33/0) | 0.0 (20/0/33/0) | 1.5 (10/10/16/17) |
| Insecure deserialization (`deserialization`) | 18/36 | 66.7 (18/0/12/24) | 66.7 (18/0/12/24) | 66.7 (18/0/12/24) |
| Weak hash (`hash`) | 71/80 | 100.0 (71/0/0/80) | 100.0 (71/0/0/80) | 0.0 (0/71/0/80) |
| LDAP injection (`ldapi`) | 16/13 | 0.0 (0/16/0/13) | 0.0 (0/16/0/13) | 0.0 (0/16/0/13) |
| Path traversal (`pathtraver`) | 65/103 | -1.8 (14/51/24/79) | 0.0 (0/65/0/103) | 0.0 (0/65/0/103) |
| Open redirect (`redirect`) | 13/21 | 2.2 (4/9/6/15) | 0.0 (0/13/0/21) | 0.0 (0/13/0/21) |
| Insecure cookie (`securecookie`) | 24/15 | 0.0 (0/24/0/15) | 0.0 (0/24/0/15) | 0.0 (0/24/0/15) |
| SQL injection (`sqli`) | 5/11 | 100.0 (5/0/0/11) | 0.0 (5/0/11/0) | 0.0 (0/5/0/11) |
| Trust boundary violation (`trustbound`) | 18/19 | 0.0 (0/18/0/19) | 0.0 (0/18/0/19) | 0.0 (0/18/0/19) |
| Weak randomness (`weakrand`) | 99/227 | 0.0 (0/99/0/227) | 77.8 (77/22/0/227) | 0.0 (0/99/0/227) |
| XPath injection (`xpathi`) | 51/135 | 0.0 (0/51/0/135) | 0.0 (0/51/0/135) | 0.0 (0/51/0/135) |
| Cross-site scripting (`xss`) | 31/58 | 0.0 (0/31/0/58) | 0.0 (0/31/0/58) | 0.0 (0/31/0/58) |
| XML external entities (`xxe`) | 8/20 | 0.0 (8/0/20/0) | 0.0 (8/0/20/0) | 0.0 (8/0/20/0) |

Each cell is the score in percentage points, then (TP/FN/FP/TN).

### What the BenchmarkPython numbers show for Kestrix

**Where Kestrix does well:**

- **SQL injection, 100.** It finds all 5 vulnerable cases and flags none of the 11 safe ones. Bandit flags all 16.
- **Weak hash, 100.** It ties with Bandit.

**Where Kestrix scores 0 because it has no rule:** LDAP injection, XPath injection, insecure cookies and trust
boundary violations.

**Where Kestrix has a rule that never fires here:**

- **Weak randomness.** `py.crypto.insecure_random` reports `random` only when the value is used for something named
  like a secret. BenchmarkPython puts `random` values in remember-me cookies and session entries.
- **Cross-site scripting.** `py.xss.markup` covers `Markup(...)` and template source built from request data. The
  benchmark's XSS cases return an HTML string from the view, which no rule covers.

**Where Kestrix's rule fires on every case, safe or not (score 0 or below):**

- **Code injection.** Every case passes a non-literal to `eval` or `exec`. Most safe cases (22 of 33) first check
  that the value is a plain string literal; the others replace it with a constant. The rule fires on the call, not on
  tainted data.
- **XML external entities.** `py.xml.unsafe_parser` (CWE-776) reports any standard-library parser on non-literal data.
  The safe cases rely on parser defaults that do not resolve external entities.
- **Command injection (-46.2).** All 7 safe cases are flagged. `py.subprocess.shell_true` fires on `shell=True` with
  any built command, and at least 5 of these cases first replace the request value with a constant (through a dict,
  a `configparser` entry or a branch whose condition is constant). 6 of 13 vulnerable cases are missed: they run
  `["sh", "-c", command]` as an argument list, without `shell=True`.

**Path traversal and open redirect (about 0).** Kestrix finds 14 of 65 and 4 of 13. Most misses are taint that
stops early:

- `codecs.open` is not a file sink;
- `urllib.parse.unquote_plus` and a base64 round trip drop the taint;
- some sources come through a helper module, which intraprocedural analysis cannot follow.

24 safe path cases are flagged. In 19 of them the request value is replaced by a constant in the same ways as above;
6 of those 19 also resolve the path and check it with `str(...).startswith(...)`.

## Results: Kestrix cases

| Tool | Version | TPR % | FPR % | Score (TPR-FPR) | Precision % | Strict-CWE score | Runtime s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| kestrix | `0.1.0` | 85.8 | 13.7 | 72.1 | 86.7 | 60.3 | 0.1 |
| bandit | `1.9.4` | 63.2 | 11.8 | 51.5 | 72.7 | 20.6 | 0.1 |
| security-guidance | `2.0.14` | 26.0 | 7.8 | 18.1 | 80.0 | n/a | 0.0 |

| Category | Cases (vuln/safe) | kestrix | bandit | security-guidance |
| --- | --- | ---: | ---: | ---: |
| Risky Claude Code / MCP configuration (`agentconfig`) | 10/6 | 100.0 (10/0/0/6) | 0.0 (0/10/0/6) | 0.0 (0/10/0/6) |
| Command injection (`cmdi`) | 4/6 | 41.7 (3/1/2/4) | 0.0 (4/0/6/0) | 41.7 (3/1/2/4) |
| Code injection (`codeinj`) | 3/3 | 100.0 (3/0/0/3) | 100.0 (3/0/0/3) | 66.7 (2/1/0/3) |
| Debug mode enabled (`debug`) | 1/1 | 100.0 (1/0/0/1) | 100.0 (1/0/0/1) | 0.0 (0/1/0/1) |
| Insecure deserialization (`deserialization`) | 4/4 | 100.0 (4/0/0/4) | 75.0 (3/1/0/4) | 100.0 (4/0/0/4) |
| Weak hash (`hash`) | 2/2 | 50.0 (2/0/1/1) | 100.0 (2/0/0/2) | 0.0 (0/2/0/2) |
| JWT signature not verified (`jwt`) | 1/1 | 100.0 (1/0/0/1) | 0.0 (0/1/0/1) | 0.0 (0/1/0/1) |
| Path traversal (`pathtraver`) | 4/3 | 50.0 (2/2/0/3) | 0.0 (0/4/0/3) | 0.0 (0/4/0/3) |
| Open redirect (`redirect`) | 1/1 | 0.0 (1/0/1/0) | 0.0 (0/1/0/1) | 0.0 (0/1/0/1) |
| Hard-coded credential (`secrets`) | 2/1 | 100.0 (2/0/0/1) | 100.0 (2/0/0/1) | 0.0 (0/2/0/1) |
| SQL injection (`sqli`) | 3/4 | 16.7 (2/1/2/2) | 16.7 (2/1/2/2) | 0.0 (0/3/0/4) |
| Server-side request forgery (`ssrf`) | 2/1 | 50.0 (1/1/0/1) | 0.0 (0/2/0/1) | 0.0 (0/2/0/1) |
| Insecure temporary file (`tempfile`) | 1/1 | 100.0 (1/0/0/1) | 100.0 (1/0/0/1) | 0.0 (0/1/0/1) |
| TLS verification disabled (`tls`) | 2/1 | 100.0 (2/0/0/1) | 100.0 (2/0/0/1) | 100.0 (2/0/0/1) |
| Weak randomness (`weakrand`) | 2/2 | 50.0 (1/1/0/2) | 50.0 (2/0/1/1) | 0.0 (0/2/0/2) |
| Cross-site scripting (`xss`) | 3/3 | 66.7 (2/1/0/3) | 33.3 (1/2/0/3) | 0.0 (0/3/0/3) |
| XML external entities (`xxe`) | 1/1 | 100.0 (1/0/0/1) | 100.0 (1/0/0/1) | 0.0 (1/0/1/0) |

Without the configuration category, which only Kestrix scans, Kestrix still scores highest on these cases. But the
set was written knowing the rules, so that result is weak evidence.

**Where Kestrix loses or ties on its own cases:**

- **Weak hash.** It reports MD5 with `usedforsecurity=False` (at low severity, as a checksum use). Bandit does not.
- **SQL injection.** It flags an `ORDER BY` built from an allowlisted constant and an `int()`-cast id. It misses SQL
  written by an Anthropic client and run with `conn.execute` (`llm_text_to_sql_vuln`).
- **Open redirect.** It flags a redirect that a `urlsplit` check has already made local.
- **Command injection.** It flags `shell=True` after `shlex.quote`, and after a constant overwrite. It misses
  `["sh", "-c", ...]`.
- **It also misses:**
  - path traversal through a helper function;
  - LLM output parsed with `json.loads` before it reaches `open`;
  - an `httpx.AsyncClient` call in FastAPI (SSRF);
  - a reflected XSS f-string returned from a view;
  - a `random` remember-me cookie.

## Method

### Suites

**BenchmarkPython** is fetched by a shallow `git fetch` of commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`
(`main` on 2026-05-19, v0.1) into the git-ignored `bench/.cache/`. Its `expectedresults-0.1.csv` gives each test
case's category, CWE and whether it is a real vulnerability. Every tool scans `testcode/`, the 1,230
`BenchmarkTestNNNNN.py` files; the helper modules are not scanned.

**The Kestrix cases** are in [`bench/cases`](../../bench/cases), labelled in
[`bench/cases/expected.csv`](../../bench/cases/expected.csv) in the same format. They have two parts:

- **71 Python files.** These are vulnerable/safe pairs per rule family, written in the style of AI-generated Flask,
  FastAPI and agent code. They include taint and sanitizer cases (`shlex.quote`, `secure_filename`, resolve-and-contain
  guards, `int()` casts, allowlists, constant overwrites, a helper function) and LLM-output cases: Anthropic and
  OpenAI replies reaching `eval`, a shell, SQL or a file path.
- **16 Claude Code and MCP configuration cases.** These are `.claude/settings.json`, plugin `hooks/hooks.json` and
  `.mcp.json` files. Every URL in them uses the reserved `.invalid` domain.

### Tools

| Tool | Version | How it runs |
| --- | --- | --- |
| kestrix-scan | 0.1.0 at the commit above | `python -m kestrix_scan scan . --no-config --fail-on none --format json` from the project environment |
| Bandit | 1.9.4 | `bandit -r . -f json --exit-zero`: every test, every severity and confidence |
| security-guidance regex layer | plugin 2.0.14, [`claude-plugins-official@a0b04d9`](https://github.com/anthropics/claude-plugins-official/tree/a0b04d9ddccaabe1976645f68b0eda50f74e7022/plugins/security-guidance) | `hooks/patterns.py`, checked against a pinned SHA-256, applied by [`bench/sg_regex.py`](../../bench/sg_regex.py) to each file's full content, as the plugin's hook checks a `Write` |
| Semgrep CE | 1.178.0 | `semgrep scan --config p-python.yml --metrics=off` on a saved copy of the `p/python` ruleset (not published) |

Bandit and Semgrep are installed into their own virtual environment in `bench/.cache/tools`, never into the project.
Every tool scans with its default settings, and every finding counts, whatever its severity or confidence. Only the
security-guidance plugin's pattern warnings are measured; its LLM reviews are out of scope.

### Scoring

The scoring follows [OWASP BenchmarkUtils](https://github.com/OWASP-Benchmark/BenchmarkUtils); no code was taken
from it.

A finding belongs to the test case whose name is its file's name. For the configuration cases, the case name is the
directory name. A case is *flagged* when at least one of its findings matches the case's category. Then, for each
category:

- **TP:** a vulnerable case that is flagged. **FN:** a vulnerable case that is not.
- **FP:** a safe case that is flagged. **TN:** a safe case that is not.
- **TPR** = TP / (TP + FN), and **FPR** = FP / (FP + TN). Each is 0 when its denominator is 0.
- **Score** = TPR − FPR, the Youden index.

The overall TPR and FPR are unweighted means over the categories, and the overall score is their difference, as in
BenchmarkUtils. Overall precision is pooled: TP / (TP + FP) over all cases.

Two matching modes are reported:

- **Category (primary).** A finding matches through the mapping tables below.
- **Strict CWE.** This is BenchmarkUtils' own rule: a CWE the tool reports must equal the case's CWE. It penalizes
  tools that report a near-synonym, for example Kestrix's CWE-95 for `eval`, CWE-776 for XML parsers, and Bandit's
  CWE-20 for XML and CWE-78 for `exec`. The security-guidance layer reports no CWE, so it has no strict score.

### Mapping tables

These tables are in [`bench/mapping.py`](../../bench/mapping.py); `uv run python -m bench.run --print-mapping`
prints them.

- **Kestrix:** mapped by rule id.
- **Bandit:** mapped by the CWE that Bandit reports, except for the listed test ids. For those, Bandit's CWE is
  generic (CWE-20) or names another weakness (CWE-78 on `exec`, CWE-94 on Flask debug).
- **Semgrep:** mapped by the CWEs in each rule's metadata.
- **security-guidance:** mapped by rule name.

BenchmarkPython has no weak-encryption category, so CWE-327 counts as a weak hash. Bandit's import-only checks keep
their CWE, as BenchmarkUtils would score them: B403 (pickle, CWE-502), B404 (subprocess, CWE-78) and the XML import
checks. This is why Bandit flags every command-injection case.

| CWE | Category |
| --- | --- |
| CWE-22, 23, 36, 73 | `pathtraver` |
| CWE-77, 78 | `cmdi` |
| CWE-79, 80, 1336 | `xss` |
| CWE-89 | `sqli` |
| CWE-90 | `ldapi` |
| CWE-94, 95 | `codeinj` |
| CWE-215, 489 | `debug` |
| CWE-259, 321, 798 | `secrets` |
| CWE-295 | `tls` |
| CWE-327, 328 | `hash` |
| CWE-330, 338 | `weakrand` |
| CWE-347 | `jwt` |
| CWE-377 | `tempfile` |
| CWE-501 | `trustbound` |
| CWE-502 | `deserialization` |
| CWE-601 | `redirect` |
| CWE-611, 776 | `xxe` |
| CWE-614 | `securecookie` |
| CWE-643 | `xpathi` |
| CWE-918 | `ssrf` |

| Kestrix rule | Category |
| --- | --- |
| `py.exec.eval`, `py.exec.exec`, `py.exec.compile` | `codeinj` |
| `py.subprocess.shell_true`, `py.os.system` | `cmdi` |
| `py.deserialize.pickle`, `py.deserialize.yaml_unsafe`, `py.ml.unsafe_model_load` | `deserialization` |
| `py.sql.string_built` | `sqli` |
| `py.tls.verify_disabled` | `tls` |
| `py.crypto.weak_hash` | `hash` |
| `py.crypto.insecure_random` | `weakrand` |
| `py.tempfile.mktemp` | `tempfile` |
| `py.flask.debug` | `debug` |
| `py.jwt.no_verify` | `jwt` |
| `py.xml.unsafe_parser` | `xxe` |
| `py.path.traversal` | `pathtraver` |
| `py.ssrf.request` | `ssrf` |
| `py.redirect.open` | `redirect` |
| `py.xss.markup` | `xss` |
| `py.llm.output_to_sink` | by the finding's CWE (94, 78, 89 or 22) |
| `config.*` | `agentconfig` |
| `secret.*` | `secrets` |
| `py.assert.security`, `dep.*` | none |

| Bandit test id | Category |
| --- | --- |
| B102 (`exec_used`), B307 (`eval`) | `codeinj` |
| B201 (`flask_debug_true`) | `debug` |
| B304, B305 (ciphers and modes) | none |
| B310 (`urllib_urlopen`) | `ssrf` |
| B313–B320, B405–B411 (XML parsers and imports) | `xxe` |
| B502, B503, B504 (TLS protocol versions) | `tls` |
| B506 (`yaml_load`) | `deserialization` |
| B615 (`huggingface_unsafe_download`) | none |
| B701, B702 (Jinja2 autoescape off, Mako) | `xss` |
| any other | by the CWE Bandit reports |

| security-guidance rule | Category |
| --- | --- |
| `eval_injection` | `codeinj` |
| `os_system_injection`, `python_subprocess_shell` | `cmdi` |
| `pickle_deserialization`, `pickle_variants_load`, `pickle_wrapper_load`, `marshal_loads`, `shelve_open`, `torch_unsafe_load`, `unsafe_yaml_load`, `yaml_unsafe_load_variants` | `deserialization` |
| `tls_verification_disabled` | `tls` |
| `xml_unsafe_parse` | `xxe` |
| any other (JavaScript, workflow and cipher rules) | none |

### Deviations from BenchmarkUtils

- The primary score maps rules to categories through the tables above. BenchmarkUtils compares CWEs exactly; the
  strict-CWE column shows that score.
- BenchmarkUtils reads each tool's own report format (for example SARIF). The harness reads each tool's JSON report.
- Only `testcode/` is scanned.

## Semgrep

Semgrep CE 1.178.0 was run with the `p/python` ruleset on both suites, but its numbers are kept out of this page and
out of the committed JSON:

- **The engine is fine to run.** It is LGPL-2.1 ([licensing](https://docs.semgrep.dev/licensing)), and the
  [terms of service](https://semgrep.dev/terms) (updated 2026-08-20) exclude the open-source engine from "Software".
- **The rules are the problem.** `p/python` comes from the Semgrep Registry, and its rules are under the
  [Semgrep Rules License v1.0](https://semgrep.dev/legal/rules-license): use "only for your own internal business
  purposes", with no distribution and no use "as a service". Publishing a competing scanner's comparison built on
  those rules may fall outside internal business use.
- **The terms also restrict benchmarking.** Section 2.3(i) forbids benchmarking "the Service" for competitive
  purposes without written consent. The Service includes "Rules", and the terms do not say whether Registry rules
  run by the open-source CLI are covered.

Because this is unclear, the Semgrep results stay in the local cache for internal review. The harness can run
Semgrep (`--tools semgrep`), but `--publish` leaves it out. To publish Semgrep numbers, get written confirmation from
Semgrep, or use a ruleset whose license allows it.

## Licensing of this benchmark

- **BenchmarkPython (GPL-3.0) is never committed.** The harness downloads it into the git-ignored `bench/.cache/`.
- **The committed results hold only data.** They contain test-case names, categories, CWEs, booleans, counts,
  rates, versions and timings, and no code from the benchmark.
- **Raw tool reports stay local.** They quote benchmark code, so they stay in `bench/.cache/` and are not uploaded
  by CI.
- **The security-guidance patterns are downloaded at run time.** They are Apache-2.0 and are not copied into this
  repository.
- **The Kestrix cases are Apache-2.0,** written from scratch for this project.

## Reproduce

```bash
uv sync --all-extras
uv run python -m bench.run --suite all --tools kestrix,bandit,security-guidance --publish docs/benchmarks
```

The first run needs network access, `git` and `uv`. It fetches BenchmarkPython and builds the tool environment
(Python 3.12). Later runs reuse `bench/.cache/`. Results go to `bench/.cache/results/` (`<suite>.json` and a
Markdown table). `--publish DIR` also writes the publishable JSON to `DIR`.

The [`bench.yml`](../../.github/workflows/bench.yml) workflow runs the harness weekly and on demand, and uploads the
scored results as an artifact. It is not a pull-request check. The scoring code is unit-tested in
[`tests/codebench/test_scoring.py`](../../tests/codebench/test_scoring.py) against a small synthetic
expected-results file.

Each run records the date, the machine, the Kestrix commit (and whether the scanner had uncommitted changes), the
tool versions and the runtimes. Runtimes are wall-clock times for the whole scan, including tool start-up, measured
on the machine above.
