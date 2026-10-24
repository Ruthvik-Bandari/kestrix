# Code scanner scorecard: OWASP BenchmarkPython and the Kestrix cases

This page compares `kestrix-scan` with Bandit and with the regex layer of Anthropic's `security-guidance` plugin on
three test suites:

- [OWASP BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) v0.1, a public suite of 1,230 labelled
  Python test cases;
- the Kestrix cases in [`research/scanbench/cases`](../../research/scanbench/cases), 87 labelled cases written for this project;
- the held-out Kestrix cases in [`research/scanbench/cases/heldout`](../../research/scanbench/cases/heldout), 44 vulnerable/safe pairs (88 cases)
  written before the latest rule changes were measured.

Semgrep CE was also run. Its numbers are not published here; see [Semgrep](#semgrep) for why.

The machine-readable results are [benchmarkpython.json](benchmarkpython.json), [owned.json](owned.json) and
[heldout.json](heldout.json). Each one carries the earlier Kestrix results for its suite (`history`) and the
disclosure below (`disclosure`), from [`research/scanbench/history.json`](../../research/scanbench/history.json). The harness is
[`src/kestrixscanbench/run.py`](../../src/kestrixscanbench/run.py).

**Run:** 2026-10-20, Apple M4 Pro (12 cores), macOS 27.0.1, Python 3.12.13, Kestrix commit `0de3fb4` (`kestrix-scan`
0.1.0, scanner committed).

## Disclosure: this round of rule changes was informed by the benchmark

The first run on this page (scanner `35d2e28`) was blind: the rules had not been tuned on either suite. The rule
changes since then were made **in response to that run's BenchmarkPython gap analysis** (kept below, under
[Gap analysis at 35d2e28](#gap-analysis-at-35d2e28-before)). So the "after" BenchmarkPython numbers are no longer a
blind measurement of the scanner.

What was done to limit that:

- **No BenchmarkPython test-case source was read to write rules.** The changes use only the category-level gap list
  on this page and the CWE entries and library documentation cited by each rule. Every change is a general rule,
  justified by language or library semantics, with unit tests written from scratch
  ([`test_code_rule_gaps.py`](../../packages/kestrix-scan/tests/test_code_rule_gaps.py)).
- One benchmark case was used for debugging, without reading its source: `BenchmarkTest00431` (command injection)
  stopped being reported after the constant tracking was added. Probing the engine with synthetic code found the
  cause, a soundness bug: a branch that ends in `break` or `continue` was dropped from the join. This also lost taint
  in the scanner before this round. It is fixed, and that case is reported again.
- **A held-out set** of 44 new pairs was written before the rule changes were measured, and run once with the
  unchanged scanner. The held-out set is not independent either. The same author wrote the cases and the rules in
  the same work session, knowing which gaps were being closed. Two held-out false positives were fixed after the
  first post-change run, which scored 96.2:
  - a fixed `shell=True` command is no longer reported;
  - `",".join("?" for _ in ids)` now counts as literal.

  Read the held-out result as a regression check of the new rules on code written in a different style, not as an
  unbiased estimate.

## Read this first

- **BenchmarkPython v0.1 is early and synthetic.** Its authors call it "a preliminary initial release". Each case is
  a small Flask handler built from templates, and several categories reuse one sink with small variations.
- **These numbers measure category coverage on synthetic code.** They are not real-world detection or
  false-positive rates.
- **A category with no rule, or a rule that never fires, scores 0.** When a tool finds nothing in a category, every
  vulnerable case is a miss (TPR 0), and the category still counts in the overall average.
- **The Kestrix cases are not neutral.** The Kestrix project wrote both owned sets, with knowledge of the Kestrix
  rules, and the configuration category exists only in Kestrix. Treat those tables as regression sets, not as a
  comparison. Most of their categories have 1 to 6 cases, so a single case moves a score by 17 to 100 points.

## History

Kestrix results only. Bandit and security-guidance did not change between the runs (same versions, same scores).

| Run | Scanner | Blind on BenchmarkPython | BenchmarkPython score (TPR / FPR / precision) | Strict-CWE | Owned score | Held-out score |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| before | `35d2e28` (held-out: `0a42c4b`, same Python rules) | yes | 15.8 (43.3 / 27.5 / 59.0) | 15.8 | 72.1 | 16.7 |
| after | `0de3fb4` | **no**: informed by the gap analysis | 39.5 (65.0 / 25.6 / 66.3) | 39.0 | 86.8 | 100.0 |

On BenchmarkPython, Kestrix's runtime went from 1.2 s to 1.3 s (1.3 to 1.6 s across this round's runs), and its
findings from 306 to 426.

## Results: BenchmarkPython v0.1

| Tool | Version | TPR % | FPR % | Score (TPR-FPR) | Precision % | Strict-CWE score | Runtime s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| kestrix | `0.1.0` | 65.0 | 25.6 | 39.5 | 66.3 | 39.0 | 1.3 |
| bandit | `1.9.4` | 48.4 | 30.9 | 17.5 | 71.9 | 9.3 | 1.6 |
| security-guidance | `2.0.14` | 21.7 | 20.1 | 1.6 | 43.9 | n/a | 0.4 |

| Category | Cases (vuln/safe) | kestrix before (`35d2e28`) | kestrix after | bandit | security-guidance |
| --- | --- | ---: | ---: | ---: | ---: |
| Command injection (`cmdi`) | 13/7 | -46.2 (7/6/7/0) | -31.9 (7/6/6/1) | 0.0 (13/0/7/0) | -46.2 (7/6/7/0) |
| Code injection (`codeinj`) | 20/33 | 0.0 (20/0/33/0) | 6.1 (20/0/31/2) | 0.0 (20/0/33/0) | 1.5 (10/10/16/17) |
| Insecure deserialization (`deserialization`) | 18/36 | 66.7 (18/0/12/24) | 72.2 (18/0/10/26) | 66.7 (18/0/12/24) | 66.7 (18/0/12/24) |
| Weak hash (`hash`) | 71/80 | 100.0 (71/0/0/80) | 100.0 (71/0/0/80) | 100.0 (71/0/0/80) | 0.0 (0/71/0/80) |
| LDAP injection (`ldapi`) | 16/13 | 0.0 (0/16/0/13) | 44.2 (12/4/4/9) | 0.0 (0/16/0/13) | 0.0 (0/16/0/13) |
| Path traversal (`pathtraver`) | 65/103 | -1.8 (14/51/24/79) | 25.4 (31/34/23/80) | 0.0 (0/65/0/103) | 0.0 (0/65/0/103) |
| Open redirect (`redirect`) | 13/21 | 2.2 (4/9/6/15) | 48.4 (10/3/6/15) | 0.0 (0/13/0/21) | 0.0 (0/13/0/21) |
| Insecure cookie (`securecookie`) | 24/15 | 0.0 (0/24/0/15) | 100.0 (24/0/0/15) | 0.0 (0/24/0/15) | 0.0 (0/24/0/15) |
| SQL injection (`sqli`) | 5/11 | 100.0 (5/0/0/11) | 100.0 (5/0/0/11) | 0.0 (5/0/11/0) | 0.0 (0/5/0/11) |
| Trust boundary violation (`trustbound`) | 18/19 | 0.0 (0/18/0/19) | 12.0 (5/13/3/16) | 0.0 (0/18/0/19) | 0.0 (0/18/0/19) |
| Weak randomness (`weakrand`) | 99/227 | 0.0 (0/99/0/227) | 0.0 (0/99/0/227) | 77.8 (77/22/0/227) | 0.0 (0/99/0/227) |
| XPath injection (`xpathi`) | 51/135 | 0.0 (0/51/0/135) | 10.9 (15/36/25/110) | 0.0 (0/51/0/135) | 0.0 (0/51/0/135) |
| Cross-site scripting (`xss`) | 31/58 | 0.0 (0/31/0/58) | 0.0 (0/31/0/58) | 0.0 (0/31/0/58) | 0.0 (0/31/0/58) |
| XML external entities (`xxe`) | 8/20 | 0.0 (8/0/20/0) | 65.0 (8/0/7/13) | 0.0 (8/0/20/0) | 0.0 (8/0/20/0) |

Each cell is the score in percentage points, then (TP/FN/FP/TN).

### What the BenchmarkPython numbers show for Kestrix

**No category scores lower than before, and no vulnerable case found before is missed now.** The overall score rose
from 15.8 to 39.5, and Kestrix now scores above
Bandit (17.5). That comparison is not like for like: Bandit is measured blind, and Kestrix's rules were changed after
seeing this suite's gap list.

**Where the score went up:**

- **Insecure cookies, 0 to 100.** The new `py.cookie.insecure` rule.
- **XML external entities, 0 to 65.** `py.xml.unsafe_parser` now follows the Python documentation and no longer
  reports standard-library parsers with their defaults, so 13 of 20 safe cases are no longer flagged. All 8
  vulnerable cases are still found.
- **Open redirect, 2.2 to 48.4** and **path traversal, -1.8 to 25.4.** These come from the new propagators
  (`unquote_plus`, base64, `json.loads`), `codecs.open` as a sink, and the guards. Path traversal finds 31 of 65
  vulnerable cases (14 before).
- **LDAP injection, 0 to 44.2**, **trust boundary, 0 to 12.0** and **XPath injection, 0 to 10.9.** These are new
  rules.
- **Command injection, -46.2 to -31.9.** All 7 vulnerable cases found before are still found. 6 of 7 safe cases are
  still flagged.
- **Code injection, 0 to 6.1** and **deserialization, 66.7 to 72.2.** A few safe cases are now provably constant.

**What did not improve:**

- **Weak randomness stays at 0.** The rule now follows `random` values into cookies, session entries, response
  headers and secret-named variables, and it finds every such case in both owned sets. It finds none of the 99
  BenchmarkPython cases. Finding out why would mean reading the cases, which this round did not do. Bandit, which
  reports every `random` call, finds 77.
- **Cross-site scripting stays at 0** for the same reason. `py.xss.reflected` finds every reflected-XSS case in both
  owned sets, and none here.
- **Command injection is still negative.** Most safe cases still look dynamic to the rules.

**New false positives.** The new rules add flagged safe cases:

| Category | New FPs | Safe cases flagged after |
| --- | ---: | ---: |
| XPath injection | 25 | 25 of 135 |
| LDAP injection | 4 | 4 of 13 |
| Trust boundary | 3 | 3 of 19 |
| Path traversal | 8 (and 9 no longer flagged) | 23 of 103 |
| Open redirect | 1 (and 1 no longer flagged) | 6 of 21 |

These safe cases presumably neutralize the value in a way the rules do not recognize. This was not investigated
case by case. Overall precision still rose, from 59.0% to 66.3%.

## Results: Kestrix cases

| Tool | Version | TPR % | FPR % | Score (TPR-FPR) | Precision % | Strict-CWE score | Runtime s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| kestrix | `0.1.0` | 87.8 | 1.0 | 86.8 | 97.7 | 80.9 | 0.1 |
| bandit | `1.9.4` | 63.2 | 11.8 | 51.5 | 72.7 | 20.6 | 0.1 |
| security-guidance | `2.0.14` | 26.0 | 7.8 | 18.1 | 80.0 | n/a | 0.0 |

| Category | Cases (vuln/safe) | kestrix before (`35d2e28`) | kestrix after | bandit | security-guidance |
| --- | --- | ---: | ---: | ---: | ---: |
| Risky Claude Code / MCP configuration (`agentconfig`) | 10/6 | 100.0 (10/0/0/6) | 100.0 (10/0/0/6) | 0.0 (0/10/0/6) | 0.0 (0/10/0/6) |
| Command injection (`cmdi`) | 4/6 | 41.7 (3/1/2/4) | 83.3 (4/0/1/5) | 0.0 (4/0/6/0) | 41.7 (3/1/2/4) |
| Code injection (`codeinj`) | 3/3 | 100.0 (3/0/0/3) | 100.0 (3/0/0/3) | 100.0 (3/0/0/3) | 66.7 (2/1/0/3) |
| Debug mode enabled (`debug`) | 1/1 | 100.0 (1/0/0/1) | 100.0 (1/0/0/1) | 100.0 (1/0/0/1) | 0.0 (0/1/0/1) |
| Insecure deserialization (`deserialization`) | 4/4 | 100.0 (4/0/0/4) | 100.0 (4/0/0/4) | 75.0 (3/1/0/4) | 100.0 (4/0/0/4) |
| Weak hash (`hash`) | 2/2 | 50.0 (2/0/1/1) | 100.0 (2/0/0/2) | 100.0 (2/0/0/2) | 0.0 (0/2/0/2) |
| JWT signature not verified (`jwt`) | 1/1 | 100.0 (1/0/0/1) | 100.0 (1/0/0/1) | 0.0 (0/1/0/1) | 0.0 (0/1/0/1) |
| Path traversal (`pathtraver`) | 4/3 | 50.0 (2/2/0/3) | 75.0 (3/1/0/3) | 0.0 (0/4/0/3) | 0.0 (0/4/0/3) |
| Open redirect (`redirect`) | 1/1 | 0.0 (1/0/1/0) | 100.0 (1/0/0/1) | 0.0 (0/1/0/1) | 0.0 (0/1/0/1) |
| Hard-coded credential (`secrets`) | 2/1 | 100.0 (2/0/0/1) | 100.0 (2/0/0/1) | 100.0 (2/0/0/1) | 0.0 (0/2/0/1) |
| SQL injection (`sqli`) | 3/4 | 16.7 (2/1/2/2) | 66.7 (2/1/0/4) | 16.7 (2/1/2/2) | 0.0 (0/3/0/4) |
| Server-side request forgery (`ssrf`) | 2/1 | 50.0 (1/1/0/1) | 50.0 (1/1/0/1) | 0.0 (0/2/0/1) | 0.0 (0/2/0/1) |
| Insecure temporary file (`tempfile`) | 1/1 | 100.0 (1/0/0/1) | 100.0 (1/0/0/1) | 100.0 (1/0/0/1) | 0.0 (0/1/0/1) |
| TLS verification disabled (`tls`) | 2/1 | 100.0 (2/0/0/1) | 100.0 (2/0/0/1) | 100.0 (2/0/0/1) | 100.0 (2/0/0/1) |
| Weak randomness (`weakrand`) | 2/2 | 50.0 (1/1/0/2) | 100.0 (2/0/0/2) | 50.0 (2/0/1/1) | 0.0 (0/2/0/2) |
| Cross-site scripting (`xss`) | 3/3 | 66.7 (2/1/0/3) | 100.0 (3/0/0/3) | 33.3 (1/2/0/3) | 0.0 (0/3/0/3) |
| XML external entities (`xxe`) | 1/1 | 100.0 (1/0/0/1) | **0.0 (0/1/0/1)** | 100.0 (1/0/0/1) | 0.0 (1/0/1/0) |

**One category got worse: XML external entities, 100 to 0.** The vulnerable case `xxe_etree_upload_vuln` parses an
upload with `xml.etree.ElementTree.fromstring`. Per the Python documentation's XML vulnerabilities table, ElementTree
does not expand external entities, and Expat 2.4.1 and newer resists entity-expansion attacks. So
`py.xml.unsafe_parser` no longer reports it. This change was deliberate. The case's label was left as written rather
than relabelled to match the new rule.

**What remains:**

- **SQL injection:** `llm_text_to_sql_vuln`, SQL written by an Anthropic client and run with `conn.execute`, is still
  missed.
- **Path traversal:** a path built in a helper function is still missed; the analysis is intraprocedural.
- **SSRF:** an `httpx.AsyncClient` call in FastAPI is still missed.
- **Command injection:** one safe case is flagged: `shell=True` after `shlex.quote`. It is now reported at low
  confidence, and the category scoring counts any finding.

## Results: held-out Kestrix cases

44 pairs in 14 categories (2 to 6 pairs each), in Flask, Django and FastAPI style, plus an LLM-output case. See the
[disclosure](#disclosure-this-round-of-rule-changes-was-informed-by-the-benchmark) for what this set can and cannot
show.

| Tool | Version | TPR % | FPR % | Score (TPR-FPR) | Precision % | Strict-CWE score | Runtime s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| kestrix before (`0a42c4b`) | `0.1.0` | 42.1 | 25.5 | 16.7 | 60.7 | 16.7 | 0.1 |
| kestrix after | `0.1.0` | 100.0 | 0.0 | 100.0 | 100.0 | 90.5 | 0.1 |
| bandit | `1.9.4` | 46.2 | 20.0 | 26.2 | 65.5 | 13.1 | 0.1 |
| security-guidance | `2.0.14` | 15.7 | 8.6 | 7.1 | 60.0 | n/a | 0.0 |

| Category | Cases (vuln/safe) | kestrix before | kestrix after | bandit | security-guidance |
| --- | --- | ---: | ---: | ---: | ---: |
| Command injection (`cmdi`) | 5/5 | 0.0 (2/3/2/3) | 100.0 (5/0/0/5) | 0.0 (4/1/4/1) | 0.0 (1/4/1/4) |
| Code injection (`codeinj`) | 3/3 | 33.3 (3/0/2/1) | 100.0 (3/0/0/3) | 33.3 (3/0/2/1) | 33.3 (2/1/1/2) |
| Insecure deserialization (`deserialization`) | 2/2 | 100.0 (2/0/0/2) | 100.0 (2/0/0/2) | 100.0 (2/0/0/2) | 100.0 (2/0/0/2) |
| Weak hash (`hash`) | 2/2 | 50.0 (2/0/1/1) | 100.0 (2/0/0/2) | 100.0 (2/0/0/2) | 0.0 (0/2/0/2) |
| LDAP injection (`ldapi`) | 3/3 | 0.0 (0/3/0/3) | 100.0 (3/0/0/3) | 0.0 (0/3/0/3) | 0.0 (0/3/0/3) |
| Path traversal (`pathtraver`) | 6/6 | 16.7 (1/5/0/6) | 100.0 (6/0/0/6) | 0.0 (0/6/0/6) | 0.0 (0/6/0/6) |
| Open redirect (`redirect`) | 3/3 | 33.3 (3/0/2/1) | 100.0 (3/0/0/3) | 0.0 (0/3/0/3) | 0.0 (0/3/0/3) |
| Insecure cookie (`securecookie`) | 3/3 | 0.0 (0/3/0/3) | 100.0 (3/0/0/3) | 0.0 (0/3/0/3) | 0.0 (0/3/0/3) |
| SQL injection (`sqli`) | 3/3 | 33.3 (3/0/2/1) | 100.0 (3/0/0/3) | 33.3 (3/0/2/1) | 0.0 (0/3/0/3) |
| Trust boundary violation (`trustbound`) | 2/2 | 0.0 (0/2/0/2) | 100.0 (2/0/0/2) | 0.0 (0/2/0/2) | 0.0 (0/2/0/2) |
| Weak randomness (`weakrand`) | 3/3 | 0.0 (0/3/0/3) | 100.0 (3/0/0/3) | 100.0 (3/0/0/3) | 0.0 (0/3/0/3) |
| XPath injection (`xpathi`) | 3/3 | 0.0 (0/3/0/3) | 100.0 (3/0/0/3) | 0.0 (0/3/0/3) | 0.0 (0/3/0/3) |
| Cross-site scripting (`xss`) | 3/3 | 0.0 (0/3/0/3) | 100.0 (3/0/0/3) | 0.0 (0/3/0/3) | 0.0 (0/3/0/3) |
| XML external entities (`xxe`) | 3/3 | -33.3 (1/2/2/1) | 100.0 (3/0/0/3) | 0.0 (2/1/2/1) | -33.3 (1/2/2/1) |

The perfect score on cases the same author wrote, while closing these exact gaps, is weak evidence. The gap between
it and BenchmarkPython (39.5, with weak randomness and XSS still at 0) is the more useful signal: the new rules match
the shapes their author expected, and not yet the shapes another author wrote.

## Gap analysis at 35d2e28 (before)

This is the analysis of the blind run that informed the rule changes. It is kept as written then, for the record.

**Where Kestrix did well:**

- **SQL injection, 100.** It found all 5 vulnerable cases and flagged none of the 11 safe ones. Bandit flagged all
  16.
- **Weak hash, 100.** It tied with Bandit.

**Where Kestrix scored 0 because it had no rule:** LDAP injection, XPath injection, insecure cookies and trust
boundary violations.

**Where Kestrix had a rule that never fired:**

- **Weak randomness.** `py.crypto.insecure_random` reported `random` only when the value was used for something
  named like a secret. BenchmarkPython puts `random` values in remember-me cookies and session entries.
- **Cross-site scripting.** `py.xss.markup` covered `Markup(...)` and template source built from request data. The
  benchmark's XSS cases return an HTML string from the view, which no rule covered.

**Where Kestrix's rule fired on every case, safe or not (score 0 or below):**

- **Code injection.** Every case passes a non-literal to `eval` or `exec`. Most safe cases (22 of 33) first check
  that the value is a plain string literal; the others replace it with a constant. The rule fired on the call, not
  on tainted data.
- **XML external entities.** `py.xml.unsafe_parser` (then CWE-776) reported any standard-library parser on
  non-literal data. The safe cases rely on parser defaults that do not resolve external entities.
- **Command injection (-46.2).** All 7 safe cases were flagged. `py.subprocess.shell_true` fired on `shell=True` with
  any built command, and at least 5 of these cases first replace the request value with a constant (through a dict,
  a `configparser` entry or a branch whose condition is constant). 6 of 13 vulnerable cases were missed: they run
  `["sh", "-c", command]` as an argument list, without `shell=True`.

**Path traversal and open redirect (about 0).** Kestrix found 14 of 65 and 4 of 13. Most misses were taint that
stopped early:

- `codecs.open` was not a file sink;
- `urllib.parse.unquote_plus` and a base64 round trip dropped the taint;
- some sources come through a helper module, which intraprocedural analysis cannot follow.

24 safe path cases were flagged. In 19 of them the request value is replaced by a constant in the same ways as
above; 6 of those 19 also resolve the path and check it with `str(...).startswith(...)`.

**Owned cases:** MD5 with `usedforsecurity=False` was reported at low severity; an `ORDER BY` from an allowlisted
constant, an `int()`-cast id, a `urlsplit`-checked redirect, `shell=True` after `shlex.quote` and a constant overwrite
were flagged; `["sh", "-c", ...]`, a reflected XSS f-string and a `random` remember-me cookie were missed.

### What this round changed, and what it left out

Each item in the gap list became a general rule change; see `docs/modules/code.md` and the commit history for the
details. Items that were **not** addressed:

- the `configparser` constant (a value written with `set` and read back with `get`);
- the eval/exec safe cases that "check that the value is a plain string literal": the check's form is not known
  without reading the cases;
- sources that come through a helper module (interprocedural analysis).

## Method

### Suites

**BenchmarkPython** is fetched by a shallow `git fetch` of commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`
(`main` on 2026-05-19, v0.1) into the git-ignored `research/scanbench/.cache/`. Its `expectedresults-0.1.csv` gives each test
case's category, CWE and whether it is a real vulnerability. Every tool scans `testcode/`, the 1,230
`BenchmarkTestNNNNN.py` files; the helper modules are not scanned.

**The Kestrix cases** are in [`research/scanbench/cases`](../../research/scanbench/cases), labelled in
[`research/scanbench/cases/expected.csv`](../../research/scanbench/cases/expected.csv) in the same format. They have two parts:

- **71 Python files.** These are vulnerable/safe pairs per rule family, written in the style of AI-generated Flask,
  FastAPI and agent code. They include taint and sanitizer cases (`shlex.quote`, `secure_filename`, resolve-and-contain
  guards, `int()` casts, allowlists, constant overwrites, a helper function) and LLM-output cases: Anthropic and
  OpenAI replies reaching `eval`, a shell, SQL or a file path.
- **16 Claude Code and MCP configuration cases.** These are `.claude/settings.json`, plugin `hooks/hooks.json` and
  `.mcp.json` files. Every URL in them uses the reserved `.invalid` domain.

**The held-out Kestrix cases** are in [`research/scanbench/cases/heldout`](../../research/scanbench/cases/heldout), labelled in their own
`expected.csv`. They are 44 vulnerable/safe pairs, written from scratch from the category-level gap list and the
CWE and library documentation before the rule changes were measured (commit `ce7e3d3`), and measured once with the
unchanged scanner. They are scanned as their own suite; the owned suite counts only findings in its own cases, so the
held-out files in its directory do not affect it.

### Tools

| Tool | Version | How it runs |
| --- | --- | --- |
| kestrix-scan | 0.1.0 at the commit above | `python -m kestrix_scan scan . --no-config --fail-on none --format json` from the project environment |
| Bandit | 1.9.4 | `bandit -r . -f json --exit-zero`: every test, every severity and confidence |
| security-guidance regex layer | plugin 2.0.14, [`claude-plugins-official@a0b04d9`](https://github.com/anthropics/claude-plugins-official/tree/a0b04d9ddccaabe1976645f68b0eda50f74e7022/plugins/security-guidance) | `hooks/patterns.py`, checked against a pinned SHA-256, applied by [`src/kestrixscanbench/sg_regex.py`](../../src/kestrixscanbench/sg_regex.py) to each file's full content, as the plugin's hook checks a `Write` |
| Semgrep CE | 1.178.0 | `semgrep scan --config p-python.yml --metrics=off` on a saved copy of the `p/python` ruleset (not published) |

Bandit and Semgrep are installed into their own virtual environment in `research/scanbench/.cache/tools`, never into the project.
Every tool scans with its default settings, and every finding counts, whatever its severity or confidence. Only the
security-guidance plugin's pattern warnings are measured; its LLM reviews are out of scope.

### Scoring

The scoring follows [OWASP BenchmarkUtils](https://github.com/OWASP-Benchmark/BenchmarkUtils); no code was taken
from it.

A finding belongs to the test case whose name is its file's name. For the configuration cases, the case name is the
directory name. Findings in files that belong to no case of the suite are ignored. A case is *flagged* when at least one of its findings matches the case's category. Then, for each
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
  tools that report a near-synonym, for example Kestrix's CWE-95 for `eval` and CWE-1004 for a cookie missing only
  HttpOnly, and Bandit's CWE-20 for XML and CWE-78 for `exec`. The security-guidance layer reports no CWE, so it has no strict score.

### Mapping tables

These tables are in [`src/kestrixscanbench/mapping.py`](../../src/kestrixscanbench/mapping.py); `uv run python -m kestrixscanbench.run --print-mapping`
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
| CWE-614, 1004 | `securecookie` |
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
| `py.xss.markup`, `py.xss.reflected` | `xss` |
| `py.ldap.injection` | `ldapi` |
| `py.xpath.injection` | `xpathi` |
| `py.cookie.insecure` | `securecookie` |
| `py.trust_boundary.session` | `trustbound` |
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

- **BenchmarkPython (GPL-3.0) is never committed.** The harness downloads it into the git-ignored `research/scanbench/.cache/`.
- **The committed results hold only data.** They contain test-case names, categories, CWEs, booleans, counts,
  rates, versions and timings, and no code from the benchmark.
- **Raw tool reports stay local.** They quote benchmark code, so they stay in `research/scanbench/.cache/` and are not uploaded
  by CI.
- **The security-guidance patterns are downloaded at run time.** They are Apache-2.0 and are not copied into this
  repository.
- **The Kestrix cases, held-out cases included, are Apache-2.0,** written from scratch for this project.

## Reproduce

```bash
uv sync --all-extras
uv run python -m kestrixscanbench.run --suite all --tools kestrix,bandit,security-guidance --publish docs/benchmarks
```

`--suite all` runs BenchmarkPython, the owned cases and the held-out cases; `--suite heldout` runs only the held-out
cases. The first run needs network access, `git` and `uv`. It fetches BenchmarkPython and builds the tool environment
(Python 3.12). Later runs reuse `research/scanbench/.cache/`. Results go to `research/scanbench/.cache/results/` (`<suite>.json` and a
Markdown table). `--publish DIR` also writes the publishable JSON to `DIR`, with the suite's `history` and the
`disclosure` from `research/scanbench/history.json`. Add a run to the history by hand when its results replace the published
ones.

The [`bench.yml`](../../.github/workflows/bench.yml) workflow runs the harness weekly and on demand, and uploads the
scored results as an artifact. It is not a pull-request check. The scoring code is unit-tested in
[`tests/kestrixscanbench/test_scoring.py`](../../tests/kestrixscanbench/test_scoring.py) against a small synthetic
expected-results file.

Each run records the date, the machine, the Kestrix commit (and whether the scanner had uncommitted changes), the
tool versions and the runtimes. Runtimes are wall-clock times for the whole scan, including tool start-up, measured
on the machine above.
