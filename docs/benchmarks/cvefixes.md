# Kestrix code scanner on CVE-fix commits (CVEfixes and GitHub Advisory Database)

This page measures `kestrix-scan` on the vulnerable and the fixed version of files from real CVE fix commits, compares it with Bandit and with ESLint's security plugin, and records one round of rule changes judged on the development half only. **The round-1 locked test was run once (see the end of the page) and is spent; round 2 adds a second held-out set that has not been run.** The numbers up to "Locked test" are development numbers. Code: `src/kestrixcodebench/`, `hpc/codebench_*`; aggregates: [`docs/data/codebench/`](../data/codebench/).

The ground truth is approximate. Read [What is not claimed](#what-is-not-claimed) before quoting any rate.

## Method

**Data.** Nothing new was downloaded: the benchmark reuses what `kestrixvul` acquired on the cluster ([data card](../data/vul/README.md)).

- **CVEfixes v1.0.8** (CC BY 4.0), from the private working database: every Python, JavaScript and TypeScript file a CVE fix commit modified, with the whole file before and after.
- **GitHub Advisory Database fix commits** (CC BY 4.0), mined from the public repositories by `kestrixvul`: commits that neither CVEfixes nor MoreFixes hold, before and after text of each changed file. The files the miner sampled from the parent snapshot of every mined commit (up to 3 per commit, which the commit did not change) are the **unchanged files**.
- MoreFixes (also CC BY 4.0) is not used in this benchmark.

**Filters.** The path and content rules of `kestrixvul.paths`: no test, vendored, bundled, minified or generated files; no file over 400,000 characters or 20,000 lines; before-files shorter than 5 lines are skipped; added and deleted files have no pair; pairs whose two versions differ only in whitespace are dropped. Two commits with the same before and after text are one pair (their CVEs and repositories merge). Dropped changed files: 1228 other-language, 1441 test, 483 minified, 230 bundled, 529 duplicate pairs, plus smaller groups (see `split-manifest.json`).

**A pair** is one changed file of a CVE fix: its before-file and after-file, the lines the fix changed (a `difflib` line diff; a pure insertion counts as the two lines around it), the CVE's CWEs and their *family*.

**Families.** The CWE families of `bench/mapping.py` (command injection, code injection, SQL injection, path traversal, XSS, SSRF and so on) plus prototype pollution, ReDoS, CSRF, timing and CORS (`src/kestrixcodebench/families.py`). A pair is *in scope* when a CWE of its CVE maps to a family; the other pairs (CWE-20, memory safety, access control, information exposure, CWEs without an id) are used only where a rate says so. Kestrix and Bandit findings map as in `bench/mapping.py`; ESLint's rules map by the weakness each documents.

**Split.** Groups are connected components of repositories, CVE and advisory ids and before-file contents (a fork or backport that copied a file joins the original). A seeded hash (`kestrixcodebench-v1`) sends 30% of the groups to the locked test and 70% to dev, before any scanner ran. `kestrixvul`'s split was not reused: it is temporal, built on function records of a filtered subset, with the post-2024 window reserved for the function model. Projects, CVEs and files never straddle dev and test (checked in code and tested). Test files are written on the cluster; no job reads them until `locked-test`, which claims `reports/LOCKED_EVAL.json` before touching them and refuses a second run.

| Split | Projects | CVEs | File pairs (Python / JavaScript / TypeScript) | Pairs in scope | Unchanged files | KLOC before / after / unchanged |
| --- | --- | --- | --- | --- | --- | --- |
| dev | 1588 | 4311 | 13107 (5723 / 2331 / 5053) | 6634 | 13206 | 7142 / 7262 / 2839 |
| test | 619 | 1679 | 4367 (1714 / 1430 / 1223) | 2172 | 5261 | 2753 / 2800 / 1052 |

Raw changed files read: 7973 (CVEfixes) and 13639 (advisories). Dev pairs by source: CVEfixes 3188, advisories 9919. The largest repository holds 12% of dev pairs and the ten largest 32%, and one advisory-fix commit in one project contributes 743 of the 1,055 SQL-injection pairs, so the point estimates lean on a few projects. That is why every interval resamples whole repositories and why a fix-weighted rate is reported.

**Metrics** (`src/kestrixcodebench/metrics.py`).

- **Detection:** a finding on the before-file whose family is one of the pair's families and whose lines come within 3 lines of a changed line. Over in-scope pairs.
- **Fix-aware detection:** a detection whose rule no longer fires near the same place in the after-file (the place is followed through the diff).
- **Fix-weighted detection:** detection with each fix commit counted once (a file weighs 1 / the commit's file count).
- **False alarms per KLOC:** alerts on after-files, and on unchanged files. An *alert* is a finding that maps to a family; lint-level findings (Bandit's `assert` and `try/except/pass`, import checks) are counted separately in the last column.
- **Precision:** true-detection findings over those plus alerts on after-files and unchanged files. A proxy that depends on the one-before to one-after file mix; not a real-world precision.
- **Intervals:** 95% percentile bootstrap, 1,000 resamples of whole repositories, the same resamples for every tool; differences have their own paired interval.

**Tools.** Bandit 1.9.4 (Apache-2.0, `bandit -r . -f json --exit-zero`, the `bench/` pin); ESLint 9.39.5 with `eslint-plugin-security` 4.2.0 (Apache-2.0; every rule at the plugin's recommended setting, parsed with typescript-eslint), also reported without `detect-object-injection`, the rule projects usually switch off; kestrix-scan 0.1.0 with `--no-config`. Bandit and ESLint were installed through the transfer node into a private prefix under `/scratch` and run offline; ESLint on the cluster's Node 22 module. **Semgrep was not run:** its registry rules are not licensed for this use and no OSS-licensed local ruleset was available. Each tool scanned only the languages it supports.

Jobs (account `aai6610.202610`, partition `short`): build 11297489; baseline scans kestrix 11297949, bandit 11297951, eslint 11297954 and dev metrics 11297955 (an earlier run, 11297619, 11297621, 11297665 and 11297783, was discarded after fixing how ESLint messages and lint-level findings were counted); round 1 below, final 11298874, 11298875, 11298876; speed 11298898.

## Dev baseline: kestrix-scan 0.1.0 before round 1

Percent, 95% repository-bootstrap interval in brackets. Pairs column: pairs (in scope).

| Tool | Subset | Pairs (in scope) | Detection % | Fix-aware % | Fix-weighted detection % | False alarms/KLOC after | False alarms/KLOC unchanged | Precision % | All findings/KLOC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| bandit | python | 5723 (3005) | 6.2 [3.5, 10.0] | 4.1 [2.2, 6.9] | 12.1 [9.6, 15.2] | 1.12 [0.86, 1.46] | 1.19 [0.83, 1.67] | 6.0 [3.6, 9.6] | 3.32 [2.46, 4.69] |
| eslint | javascript | 2331 (1402) | 12.9 [9.9, 16.3] | 2.4 [1.6, 3.4] | 17.6 [13.7, 21.6] | 21.05 [18.55, 23.80] | 21.60 [19.09, 24.18] | 1.4 [1.0, 1.9] | 21.37 [19.24, 23.68] |
| eslint | js_ts | 7384 (3629) | 9.4 [7.7, 11.7] | 2.0 [1.4, 2.6] | 15.0 [12.6, 17.7] | 12.07 [9.27, 15.70] | 13.34 [10.57, 16.93] | 1.7 [1.3, 2.1] | 12.44 [9.61, 15.93] |
| eslint | typescript | 5053 (2227) | 7.2 [5.4, 9.4] | 1.8 [0.9, 2.6] | 11.9 [9.3, 14.7] | 7.02 [5.70, 9.48] | 6.90 [6.06, 8.54] | 2.1 [1.4, 3.1] | 7.01 [5.87, 9.17] |
| eslint-no-object-injection | javascript | 2331 (1402) | 5.1 [3.9, 6.6] | 1.7 [1.0, 2.5] | 7.5 [5.5, 9.7] | 2.15 [1.42, 3.15] | 1.96 [1.57, 2.43] | 3.2 [2.0, 4.8] | 2.27 [1.66, 3.11] |
| eslint-no-object-injection | js_ts | 7384 (3629) | 4.3 [3.2, 5.4] | 1.4 [0.9, 1.8] | 7.5 [5.8, 9.0] | 1.85 [1.46, 2.33] | 1.82 [1.45, 2.11] | 3.1 [2.4, 4.1] | 1.92 [1.56, 2.34] |
| eslint-no-object-injection | typescript | 5053 (2227) | 3.8 [2.1, 5.2] | 1.2 [0.5, 1.7] | 7.6 [4.9, 9.6] | 1.68 [1.21, 2.14] | 1.71 [1.08, 2.03] | 3.1 [2.1, 4.7] | 1.70 [1.25, 2.09] |
| kestrix | all | 13107 (6634) | 5.6 [4.0, 7.9] | 4.1 [2.8, 6.1] | 8.5 [6.9, 10.4] | 0.46 [0.31, 0.69] | 0.30 [0.22, 0.41] | 14.3 [10.1, 20.2] | 0.42 [0.30, 0.60] |
| kestrix | javascript | 2331 (1402) | 9.4 [6.3, 13.8] | 6.4 [3.5, 10.8] | 9.9 [7.7, 12.3] | 1.63 [0.86, 2.58] | 0.74 [0.51, 1.03] | 8.9 [5.5, 15.2] | 1.39 [0.79, 2.13] |
| kestrix | js_ts | 7384 (3629) | 6.8 [4.7, 9.9] | 5.2 [3.3, 8.0] | 8.2 [6.4, 10.5] | 0.69 [0.36, 1.22] | 0.36 [0.23, 0.59] | 15.6 [9.7, 24.9] | 0.61 [0.33, 1.06] |
| kestrix | python | 5723 (3005) | 4.2 [2.4, 7.3] | 2.9 [1.5, 5.3] | 8.9 [5.9, 12.6] | 0.26 [0.21, 0.34] | 0.27 [0.18, 0.39] | 11.9 [7.8, 16.6] | 0.27 [0.21, 0.33] |
| kestrix | typescript | 5053 (2227) | 5.2 [2.7, 9.3] | 4.4 [2.1, 8.3] | 6.2 [4.2, 9.4] | 0.16 [0.08, 0.33] | 0.07 [0.04, 0.14] | 42.1 [25.0, 58.5] | 0.14 [0.07, 0.28] |

Detection by family, pairs with at least 40 pairs in the family:

Python:

| Family | Pairs | kestrix det % | bandit det % |
| --- | --- | --- | --- |
| cmdi | 159 | 9.4 [4.7, 19.1] | 15.7 [8.8, 29.7] |
| codeinj | 448 | 5.8 [3.0, 13.5] | 5.8 [3.0, 13.5] |
| csrf | 116 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| deserialization | 137 | 29.2 [17.4, 46.8] | 31.4 [17.6, 50.7] |
| jwt | 63 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| pathtraver | 417 | 1.0 [0.2, 2.2] | 3.1 [1.0, 5.8] |
| redirect | 225 | 8.4 [0.6, 37.0] | 0.0 [0.0, 0.0] |
| redos | 102 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| sqli | 864 | 1.5 [0.3, 30.0] | 2.0 [0.5, 37.8] |
| ssrf | 344 | 0.6 [0.0, 1.8] | 0.6 [0.0, 1.8] |
| xss | 326 | 0.6 [0.0, 2.2] | 12.3 [3.1, 22.4] |
| xxe | 40 | 2.5 [0.0, 11.1] | 27.5 [6.2, 59.1] |

JavaScript and TypeScript:

| Family | Pairs | kestrix det % | eslint det % | eslint-no-object-injection det % |
| --- | --- | --- | --- | --- |
| cmdi | 449 | 18.9 [7.7, 39.3] | 6.0 [2.9, 13.4] | 6.0 [2.9, 13.4] |
| codeinj | 298 | 2.3 [0.6, 5.4] | 1.0 [0.0, 2.9] | 1.0 [0.0, 2.9] |
| csrf | 111 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| pathtraver | 463 | 1.1 [0.1, 3.0] | 16.4 [11.2, 20.3] | 16.4 [11.2, 20.3] |
| protopollution | 508 | 0.4 [0.0, 1.4] | 36.8 [26.1, 53.3] | 0.0 [0.0, 0.0] |
| redirect | 90 | 2.2 [0.0, 8.0] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| redos | 155 | 0.0 [0.0, 0.0] | 32.3 [23.0, 43.5] | 32.3 [23.0, 43.5] |
| sqli | 191 | 5.2 [0.6, 16.3] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| ssrf | 641 | 0.3 [0.0, 0.9] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| xss | 1058 | 12.4 [8.3, 18.0] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |

**Overlap on in-scope pairs.** Python, Kestrix and Bandit: both 95, only Kestrix 32, only Bandit 90, neither 2788; union 7.2 [4.2, 11.7]%, intersection 3.2 [1.8, 5.4]%. JavaScript and TypeScript, Kestrix and ESLint: both 27, only Kestrix 220, only ESLint 314, neither 3068; union 15.5 [12.5, 19.4]%, intersection 0.7 [0.4, 1.2]%. The tools mostly find different pairs. Kestrix minus Bandit on Python detection is -1.9 points (paired interval -4.4 to -0.3); against ESLint on JavaScript and TypeScript it is -2.6 (-5.4 to +0.8), so neither gap is established for ESLint.

**What the table says.** Every tool finds only a few percent of the vulnerable files by this measure. Kestrix has the fewest alerts on fixed and unchanged files (0.46 and 0.31 per KLOC, against 1.1 for Bandit and 21 for ESLint's full rule set) and the highest precision proxy on Python (12.5% against 6.0%) and on JavaScript and TypeScript (15.6% against 1.7%). ESLint's higher detection comes with `detect-object-injection`, which fires 19 times per KLOC in JavaScript; without it ESLint's JavaScript and TypeScript detection is 4.3 [3.2, 5.4]%, below Kestrix. Kestrix's detections are mostly command injection, XSS sinks and SQL built from strings in JavaScript, and pickle, YAML, `eval` and redirects in Python.

## Error analysis (dev, aggregate only)

Missed pairs mostly have no finding of any family near the change (the count of misses with some other finding near is small, in `error_analysis.missed_by_family`). Reading a few dozen misses on the cluster (no code is quoted here or committed) showed three kinds. The fix adds a check or a validation function and the vulnerable code is an ordinary file operation with no recognizable source, which a pattern scanner without whole-program data flow cannot flag. The commit is a large refactor or a version bump and the labelled file is incidental. Or the weakness is a design flaw (authorization, CSRF, SSRF filters) with no pattern at all. Real gaps with a precise shape were few.

- **kestrix, python.** Most missed (missed/pairs): sqli 851/864, codeinj 422/448, pathtraver 413/417, ssrf 342/344, xss 324/326, redirect 206/225. Most alerts on fixed and unchanged files (true hits in brackets): `py.crypto.weak_hash` 311 (0 true), `py.sql.string_built` 228 (29 true), `py.subprocess.shell_true` 115 (12 true), `py.deserialize.pickle` 104 (24 true), `py.tls.verify_disabled` 104 (1 true).
- **kestrix, javascript.** Most missed (missed/pairs): xss 500/599, protopollution 190/191, ssrf 180/181, pathtraver 108/110, redos 90/90, cmdi 70/88. Most alerts on fixed and unchanged files (true hits in brackets): `js.dom.xss_sink` 1982 (172 true), `js.exec.eval` 186 (4 true), `js.child_process.shell` 73 (31 true), `js.sql.string_built` 24 (15 true), `js.crypto.weak_hash` 22 (0 true).
- **kestrix, typescript.** Most missed (missed/pairs): ssrf 459/460, xss 427/459, pathtraver 350/353, protopollution 316/317, cmdi 294/361, codeinj 231/234. Most alerts on fixed and unchanged files (true hits in brackets): `js.dom.xss_sink` 131 (42 true), `js.sql.string_built` 87 (17 true), `js.child_process.shell` 39 (209 true), `js.crypto.weak_hash` 36 (1 true), `js.exec.eval` 21 (4 true).
- **bandit, python.** Most missed (missed/pairs): sqli 847/864, codeinj 422/448, pathtraver 404/417, ssrf 342/344, xss 286/326, redirect 225/225. Most alerts on fixed and unchanged files (true hits in brackets): `B105` 1075 (4 true), `B603` 686 (16 true), `B311` 508 (13 true), `B308` 489 (72 true), `B404` 485 (9 true).
- **eslint, javascript.** Most missed (missed/pairs): xss 599/599, ssrf 181/181, pathtraver 94/110, protopollution 82/191, cmdi 67/88, codeinj 61/64. Most alerts on fixed and unchanged files (true hits in brackets): `security/detect-object-injection` 32492 (414 true), `security/detect-non-literal-fs-filename` 2182 (40 true), `security/detect-unsafe-regex` 687 (28 true), `security/detect-non-literal-regexp` 495 (15 true), `security/detect-possible-timing-attacks` 91 (0 true).

Bandit's lint-level findings are 10,079 `assert` uses (`B101`), 1,143 `try/except/pass` (`B110`) and 456 requests without a timeout (`B113`) on all scanned Python files; they are not alerts here. Families with no Kestrix rule at all: CSRF, ReDoS, timing, and the broad access-control CWEs.

## Round 1: rule changes judged on dev

**Keep rule, stated before the splits below were run and applied the same way to every change.** Keep a change when the paired detection rate (in-scope pairs, the language where the rule applies) goes up, and the paired change in alerts per KLOC on fixed and unchanged files is within noise: its 95% interval includes zero, or the rise is under 2% of the baseline alert rate. Each change was measured alone: a copy of the scanner with every other round-1 change switched off, scanned over all dev files, against the same baseline (`base`), with paired repository resamples. The first four were chosen after the dev error analysis, so the final numbers are tuned on dev and are **not** a blind measurement; the locked test is.

Change in percentage points of detection and fix-aware detection, and in alerts per KLOC (after-files plus unchanged files pooled; baseline 0.42 overall, 0.26 Python, 0.61 JavaScript and TypeScript). Pairs and alerts are counts of added pairs and added alerts.

| Change | Subset | Detection, points | Fix-aware, points | Alerts per KLOC | Decision |
| --- | --- | --- | --- | --- | --- |
| 1. `py.xss.mark_safe`: `mark_safe`/`Markup` of a built value | python | +1.06 [+0.15, +2.74] (+32 pairs) | +0.87 [+0.11, +2.23] | +0.081 [+0.012, +0.197] (+456 alerts, +31%) | revert |
| 2. `py.archive.extract`: tar `extract`/`extractall` without a filter | python | +0.30 [+0.07, +0.77] (+9 pairs) | +0.23 [+0.02, +0.65] | +0.002 [+0.000, +0.003] (+9 alerts, +1%) | keep |
| 3. `js.dom.xss_sink`: jQuery insertion methods and `$()` given built markup | js_ts | +0.50 [+0.25, +0.86] (+18 pairs) | +0.22 [+0.08, +0.41] | +0.124 [+0.045, +0.262] (+556 alerts, +20%) | revert |
| 4a. `py.regex.redos`/`js.regex.redos`: ReDoS shapes, Python | python | +0.13 [+0.00, +0.37] (+4 pairs) | +0.03 [+0.00, +0.12] | +0.016 [+0.008, +0.028] (+91 alerts, +6%) | revert |
| 4b. same, JavaScript and TypeScript | js_ts | +0.17 [+0.05, +0.34] (+6 pairs) | +0.08 [+0.00, +0.20] | +0.048 [+0.026, +0.088] (+215 alerts, +8%) | revert |
| 5. `py.deserialize.pickle`: `recv_pyobj`, `numpy.load(allow_pickle=True)`, `pandas.read_pickle`, `jsonpickle.decode` | python | +0.13 [+0.00, +0.40] (+4 pairs) | +0.13 [+0.00, +0.40] | +0.001 [+0.000, +0.002] (+4 alerts, +0%) | keep |

The reverted changes raised alerts 6% to 31% for 4 to 32 added detected pairs (about 10 to 36 added alerts per added detection, against 11 for the scanner as it was). Diagnostic splits of the reverted changes, measured afterwards and **not** used to choose them (splitting after the fact would chase noise):

| Split | Subset | Detection, points | Fix-aware, points | Alerts per KLOC |
| --- | --- | --- | --- | --- |
| 1a. mark_safe, built strings only | python | +0.40 [+0.03, +1.22] (+12 pairs) | +0.30 [+0.00, +1.02] | +0.029 [+0.004, +0.071] (+160 alerts, +11%) |
| 1b. mark_safe, names and calls only | python | +0.90 [+0.14, +2.26] (+27 pairs) | +0.73 [+0.11, +1.85] | +0.052 [+0.007, +0.127] (+292 alerts, +20%) |
| 3a. jQuery methods only | js_ts | +0.25 [+0.09, +0.49] (+9 pairs) | +0.08 [+0.00, +0.20] | +0.080 [+0.023, +0.184] (+358 alerts, +13%) |
| 3b. `$()` constructor only | js_ts | +0.25 [+0.10, +0.45] (+9 pairs) | +0.14 [+0.03, +0.29] | +0.044 [+0.018, +0.085] (+198 alerts, +7%) |
| 4c. ReDoS, nested repeats only (both languages) | all | +0.14 [+0.04, +0.26] (+9 pairs) | +0.08 [+0.02, +0.15] | +0.019 [+0.009, +0.034] (+190 alerts, +4%) |

The combined run of changes 1 to 4 (`r1-all2`) added 1.0 point of detection (paired interval +0.5 to +1.8) and 0.13 alerts per KLOC (+0.07 to +0.22): about what the parts add up to, and the reason the three rejected ones are not in the final scanner. The jQuery alerts are mostly real string-built HTML that sits in files the fix did not touch, which is exactly what this benchmark counts as noise.

### Final dev numbers (round 1 kept)

Kestrix after round 1 (changes 2 and 5); the baselines are the same runs as above.

| Tool | Subset | Pairs (in scope) | Detection % | Fix-aware % | Fix-weighted detection % | False alarms/KLOC after | False alarms/KLOC unchanged | Precision % | All findings/KLOC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| bandit | python | 5723 (3005) | 6.2 [3.5, 10.0] | 4.1 [2.2, 6.9] | 12.1 [9.6, 15.2] | 1.12 [0.86, 1.46] | 1.19 [0.83, 1.67] | 6.0 [3.6, 9.6] | 3.32 [2.46, 4.69] |
| eslint | javascript | 2331 (1402) | 12.9 [9.9, 16.3] | 2.4 [1.6, 3.4] | 17.6 [13.7, 21.6] | 21.05 [18.55, 23.80] | 21.60 [19.09, 24.18] | 1.4 [1.0, 1.9] | 21.37 [19.24, 23.68] |
| eslint | js_ts | 7384 (3629) | 9.4 [7.7, 11.7] | 2.0 [1.4, 2.6] | 15.0 [12.6, 17.7] | 12.07 [9.27, 15.70] | 13.34 [10.57, 16.93] | 1.7 [1.3, 2.1] | 12.44 [9.61, 15.93] |
| eslint | typescript | 5053 (2227) | 7.2 [5.4, 9.4] | 1.8 [0.9, 2.6] | 11.9 [9.3, 14.7] | 7.02 [5.70, 9.48] | 6.90 [6.06, 8.54] | 2.1 [1.4, 3.1] | 7.01 [5.87, 9.17] |
| kestrix | all | 13107 (6634) | 5.8 [4.1, 8.2] | 4.3 [2.9, 6.3] | 8.8 [7.1, 10.8] | 0.46 [0.31, 0.70] | 0.31 [0.22, 0.41] | 14.5 [10.4, 20.4] | 0.42 [0.30, 0.60] |
| kestrix | javascript | 2331 (1402) | 9.4 [6.3, 13.8] | 6.4 [3.5, 10.8] | 9.9 [7.7, 12.3] | 1.63 [0.86, 2.58] | 0.74 [0.51, 1.03] | 8.9 [5.5, 15.2] | 1.39 [0.79, 2.13] |
| kestrix | js_ts | 7384 (3629) | 6.8 [4.7, 9.9] | 5.2 [3.3, 8.0] | 8.2 [6.4, 10.5] | 0.69 [0.36, 1.22] | 0.36 [0.23, 0.59] | 15.6 [9.7, 24.9] | 0.61 [0.33, 1.06] |
| kestrix | python | 5723 (3005) | 4.7 [2.7, 8.0] | 3.3 [1.8, 5.9] | 9.7 [6.7, 13.6] | 0.26 [0.21, 0.34] | 0.27 [0.18, 0.39] | 12.5 [8.5, 17.4] | 0.27 [0.22, 0.33] |
| kestrix | typescript | 5053 (2227) | 5.2 [2.7, 9.3] | 4.4 [2.1, 8.3] | 6.2 [4.2, 9.4] | 0.16 [0.08, 0.33] | 0.07 [0.04, 0.14] | 42.1 [25.0, 58.5] | 0.14 [0.07, 0.28] |

Change against the baseline run, paired: Python detection +0.43 points (+0.11 to +0.98), overall +0.20 (+0.05 to +0.40); alerts per KLOC overall +0.0013 (+13 alerts). JavaScript and TypeScript did not change. Round 1 is a small gain: 13 more detected Python pairs out of 3,005 in scope.

### Speed

One core, every dev file (39,420 files: before, after and unchanged), all eight shards in turn, two repetitions each, scanner from the baseline tree and from the final tree, same node: baseline 40.6 and 43.0 files per second, final 42.8 and 42.8 (process start-up per shard included). No measurable slowdown. The scanner still has no runtime dependencies. Earlier, parallel scan jobs gave 35.8 files per second on shared nodes.

## Reproducing and the locked test

```bash
bash hpc/codebench_sync.sh                       # code to ~/kestrix-codebench (never ~/kestrix), records CODEBENCH_SHA
ssh explorer 'cd ~/kestrix-codebench && sbatch hpc/codebench_build.sbatch'
ssh explorer 'cd ~/kestrix-codebench && sbatch --export=ALL,TOOL=kestrix,RUN=base hpc/codebench_scan.sbatch'   # also bandit, eslint
ssh explorer 'cd ~/kestrix-codebench && bash hpc/codebench_round.sh LABEL'      # scan + dev metrics + paired compare
```

The locked test scans the test half with all three tools and writes `reports/codebench-locked-<name>.json`. It claims the lock first and runs once per scanner version; freeze the code before running it:

```bash
ssh explorer 'cd ~/kestrix-codebench && sbatch hpc/codebench_locked.sbatch --name codebench-v1 --tool-run kestrix=r1-final --tool-run bandit=base --tool-run eslint=base'
```

## What is not claimed

- **Not a detection rate for real-world code.** A pair is a changed file of a fix commit. Many such files hold no instance of the CVE's weakness (a validation function added elsewhere, a refactor, a version bump), and a vulnerability can sit in a file the fix did not change. A "miss" is often not a miss.
- **CWE labels are the CVE's, not the file's,** and only CWEs that map to a family are scored. Half the pairs are out of scope.
- **False alarms are approximate.** Alerts on after-files and unchanged files can be real weaknesses; a fixed file can keep other ones. Unchanged files come only from mined commits, three per commit at most. Test files are excluded everywhere.
- **Precision is a proxy** that depends on the file mix; it is not a precision on real code.
- **Duplicates:** exact before-and-after duplicates are merged and repositories sharing a before-file are grouped, but near-duplicates (backports with edits) remain.
- **Python 2 and unparsable files** count as no finding for Kestrix and Bandit (145 before-files, 2.5% of Python pairs; ESLint could not parse 27 JavaScript or TypeScript before-files).
- **Tool defaults only:** no tuning of Bandit or ESLint. A project that configures them would see fewer alerts.
- **Dev numbers after round 1 are tuned numbers.** The changes were chosen from dev error analysis. Only the locked test is blind, and it has not been run.
- **Semgrep is missing** (see Tools).
- The earlier [BenchmarkPython scorecard](benchmarkpython.md) measures synthetic cases; the two benchmarks answer different questions and their numbers are not comparable.

## Attribution and licenses

CVEfixes: Bhandari, G., Naseer, A. and Moonen, L. (2021), *CVEfixes: automated collection of vulnerabilities and their fixes from open-source software*, PROMISE '21 (data CC BY 4.0). GitHub Advisory Database (CC BY 4.0), <https://github.com/github/advisory-database>. The mined files keep their projects' licenses and are not redistributed; only counts, rates and rule ids are published. Tool licenses and the Semgrep decision are in [`dataset-licenses.md`](../research/dataset-licenses.md).

## Locked test (2026-10-22)

Run once (job 11300842, code `51669cf+9230f191`, claim `LOCKED_EVAL.json`) on the test half: 619 projects, 1,679
CVEs, 4,367 file pairs (2,172 in scope). Report: [`codebench-locked-codebench-v1.json`](../data/codebench/codebench-locked-codebench-v1.json).
95% repository-bootstrap intervals.

| Tool | Language | Detection | Fix-aware | False alarms per KLOC (fixed files) |
| --- | --- | --- | --- | --- |
| kestrix-scan | Python | 4.4% [2.4, 6.6] | 3.2% [1.5, 5.2] | **0.29** [0.17, 0.44] |
| Bandit 1.9.4 | Python | 6.2% [4.3, 8.3] | 3.9% [2.2, 6.0] | 1.42 [0.99, 1.92] |
| kestrix-scan | JS/TS | 5.6% [3.9, 7.7] | **3.6%** [2.1, 5.4] | **0.91** [0.52, 1.45] |
| eslint-plugin-security 4.2.0 | JS/TS | 10.4% [7.6, 13.4] | 1.6% [0.8, 2.5] | 15.62 [13.25, 18.26] |
| eslint-plugin-security without `detect-object-injection` | JS/TS | 5.6% [3.2, 7.9] | 1.2% [0.6, 2.0] | 1.45 [1.04, 2.05] |

What the locked test shows, without spin:

- **Kestrix detects less than Bandit on Python** (−1.8 points, paired interval −3.6 to −0.3) at about a fifth of
  Bandit's false-alarm rate, and **less than full ESLint security on JS/TS** (−4.9 points, −8.4 to −1.3), whose lead
  comes with 17x the false alarms. Against ESLint without its noisiest rule, detection is equal and Kestrix raises
  fewer false alarms and is more often right that the fix removed the problem (fix-aware 3.6% vs 1.2%).
- **The tools find different bugs.** Kestrix with Bandit detects 7.1% of Python pairs; Kestrix with ESLint 15.1% of
  JS/TS pairs. Running them together beats either alone.
- **Absolute detection is low for every tool**, partly because the ground truth is coarse (a changed file of a fix
  commit, often without the weakness) and partly because many CVEs are design flaws (authorization, CSRF, logic) that
  pattern rules do not see. These numbers are not a claim that a scan finds most vulnerabilities.
- The locked test is now spent; later rule rounds need new held-out data.


## Round 2: a second held-out set (`test2`) and new rule changes

The round-1 locked test is spent, so round 2 uses it as **tuning data** together with round-1 dev (17,474 file pairs, 8,806 in scope; reports label it `tuning`) and builds a new held-out set that no rule was tuned on. **The test2 evaluation has not been run.** Everything below is a tuning number.

### test2 build

`kestrixcodebench.heldout`, Slurm jobs and the transfer node: a fresh clone of the GitHub Advisory Database (CC BY 4.0, commit `e8186846e9dc`, 2026-10-22), reviewed PyPI and npm advisories with a GitHub fix commit (`/commit/<sha>` or `/pull/<n>/commits/<sha>`), minus everything round 1 touched: GHSA ids, CVE aliases and fix commits of the benchmark's pairs and unchanged files, of `kestrixvul`'s mined targets (every role) and of CVEfixes; at most 3 changed source files per commit (a seeded sample), the round-1 path, content and size filters, 3 unchanged files per commit from the parent. Overlap by id and by fix commit is zero (checked in code, and again against file contents: 132 file pairs that copied a round-1 file were dropped).

| Setting | Advisories | Fix commits | Repositories |
| --- | --- | --- | --- |
| strict (no MoreFixes-only commit, only repositories round 1 never scanned) | 5 | 5 | 5 |
| plus repositories round 1 scanned | 111 | 111 | 23 |
| plus MoreFixes-only commits | 270 | 272 | 237 |
| **both (what test2 uses)** | **1,330** | **1,412** | **576** |

Only 5 advisories are new by the strictest reading because the pinned checkout of 2026-10-19 already gave round 1 nearly every advisory with a fix commit. MoreFixes is not used by this benchmark, so a commit that only MoreFixes holds is new to it (1,243 of the final commits are such); repositories that round 1 scanned are allowed because that is the only way to reach 1,000 in-scope pairs. Each pair carries a `repo_seen` flag and the locked evaluation scores the 401 pairs (239 in scope, 223 repositories) of never-scanned repositories separately.

| Item | Value |
| --- | --- |
| Advisories / fix commits fetched | 1,330 / 1,410 (2 commits unavailable) |
| Projects / CVEs | 522 / 1,173 |
| File pairs | 1,969 (Python 989, JavaScript 540, TypeScript 440) |
| Pairs in scope | 1,024 (Python 482, JavaScript 312, TypeScript 230) |
| Unchanged files | 3,292 (Python 1,417, JavaScript 1,058, TypeScript 817) |
| KLOC before / after / unchanged | 1,455 / 1,478 / 675 |
| Overlap with the round-1 data: GHSA ids, CVE ids, fix commits, file contents | 0, 0, 0, 0 |
| Repositories also in the tuning data | 332 of 522 (1,568 of 1,969 pairs) |

Aggregate manifest: [`test2-manifest.json`](../data/codebench/test2-manifest.json) (SHA-256 of `pairs.jsonl` `028af3a2...`). The private manifest with advisory ids, repositories, commits and the SHA-256 of every file stays on the cluster (`reports/test2-files.json`), with the files, under `/scratch/$USER/kestrix/codebench2/` (0700/0600; `/scratch` is purged 2026-11-03). Advisory data: CC BY 4.0, attribution to the GitHub Advisory Database; the fetched source files keep their project licenses and are not redistributed. Jobs: select 11303297 (strict), 11303732 (tiers), 11303906 (final); fetch on `explorer-xfer` (1,410 commits); build 11305898 and 11305973.

### Tuning measurements

Keep rule as in round 1, applied to the tuning data: keep a change when paired detection goes up and the paired change in alerts per KLOC on fixed and unchanged files is within noise or under 2% of the baseline alert rate; keep a *narrowing* of a rule only if detection does not fall. Each change was measured alone (a copy of the round-1 scanner with only that change) over every tuning file, with the same repository resamples, against `r2-t0` (round 1 on the tuning data). Baseline alert rate: 0.284 per KLOC Python, 0.69 JavaScript and TypeScript (about 2,100 and 6,700 alerts). A change was written from the dev error analysis and a read of missed pairs, so the final numbers are tuned.

| Change | Subset | Detection, points | Fix-aware, points | Alerts per KLOC | Decision |
| --- | --- | --- | --- | --- | --- |
| p1c. Python: Flask route parameters, `view_args`, `get_data()`, `stream` | python | +0.08 [+0.00, +0.22] (+3 pairs) | +0.05 | +0.0020 [+0.0007, +0.0041] (+15 alerts, +0.7%) | keep |
| p2c. Python: request objects of Django REST, Starlette, aiohttp, Pyramid, Sanic, Tornado, Bottle, Falcon | python | +0.05 [+0.00, +0.20] (+2 pairs) | +0.03 | +0.0022 [+0.0007, +0.0041] (+16 alerts, +0.8%) | keep |
| p3. `py.path.traversal`: 22 more file sinks (`os.*`, `shutil.*`, `zipfile`, pathlib) | python | +0.03 [+0.00, +0.11] (+1 pairs) | +0.00 | +0.0161 [+0.0074, +0.0287] (+120 alerts, +5.7%) | revert |
| p3b. `py.path.traversal`: only the sinks that change or delete files | python | +0.00 [+0.00, +0.00] (+0 pairs) | +0.00 | +0.0039 [+0.0014, +0.0071] (+29 alerts, +1.4%) | revert |
| p4. `py.ssrf.request`: session and client methods, `urlretrieve`, `HTTPConnection` | python | +0.05 [+0.00, +0.15] (+2 pairs) | +0.00 | +0.0026 [+0.0001, +0.0068] (+19 alerts, +0.9%) | keep |
| p5. `py.xss.markup`: `from_string`, Mako, Django, Tornado template source | python | +0.00 [+0.00, +0.00] (+0 pairs) | +0.00 | +0.0000 [+0.0000, +0.0000] (+0 alerts, +0.0%) | revert |
| p6. new rule `py.subprocess.tainted_args` (request data in an argument list) | python | +0.00 [+0.00, +0.00] (+0 pairs) | +0.00 | +0.0000 [+0.0000, +0.0000] (+0 alerts, +0.0%) | revert |
| p8. new rule `py.xss.autoescape_off` (Jinja2 `Environment` without autoescape) | python | +0.24 [+0.09, +0.50] (+9 pairs) | +0.16 | +0.0095 [+0.0040, +0.0171] (+71 alerts, +3.4%) | revert |
| p8b. same, only in files that name an HTML template | python | +0.19 [+0.06, +0.40] (+7 pairs) | +0.13 | +0.0060 [+0.0015, +0.0122] (+45 alerts, +2.1%) | revert |
| p9. `py.xss.markup`: `Markup`/`mark_safe` of Markdown renderer output without a sanitizer | python | +0.05 [+0.00, +0.20] (+2 pairs) | +0.03 | +0.0009 [+0.0001, +0.0020] (+7 alerts, +0.3%) | keep |
| p10. Django URL parameters (`def view(request, slug)`) as sources | python | +0.00 [+0.00, +0.00] (+0 pairs) | +0.00 | +0.0050 [+0.0008, +0.0110] (+37 alerts, +1.8%) | revert |
| p11. `py.archive.extract`: `shutil.unpack_archive` without `filter=` | python | +0.03 [+0.00, +0.10] (+1 pairs) | +0.03 | +0.0003 [+0.0000, +0.0007] (+2 alerts, +0.1%) | keep |
| j1. JS sources: `req.url`, `originalUrl`, `path`, `payload`, Koa `ctx.url` | js_ts | +0.08 [+0.02, +0.18] (+4 pairs) | +0.06 | +0.0038 [+0.0020, +0.0062] (+25 alerts, +0.6%) | keep |
| j2. `js.path.traversal`: `readdir`, `stat`, `exists`, `rename`, `copyFile`, `mkdir`, `rmdir`, fs-extra | js_ts | +0.04 [+0.00, +0.10] (+2 pairs) | +0.04 | +0.0055 [+0.0017, +0.0112] (+36 alerts, +0.8%) | keep |
| j3. `js.ssrf.request`: `request`, `needle`, `ky`, `phin`, `bent`, `undici` verbs | js_ts | +0.00 [+0.00, +0.00] (+0 pairs) | +0.00 | +0.0006 [+0.0000, +0.0015] (+4 alerts, +0.1%) | revert |
| j4. `js.redirect.open`: `res.location`, `Location` header, `writeHead`, `h.redirect` | js_ts | +0.02 [+0.00, +0.07] (+1 pairs) | +0.00 | +0.0003 [+0.0000, +0.0009] (+2 alerts, +0.0%) | keep |
| j5. `js.exec.eval`: `vm.*`, template engines, `require()` of request data | js_ts | +0.00 [+0.00, +0.00] (+0 pairs) | +0.00 | +0.0000 [+0.0000, +0.0000] (+0 alerts, +0.0%) | revert |
| j6a. `js.child_process.shell`: `spawn('sh', ['-c', script])`, `shelljs.exec`, `execa.command` | js_ts | +0.04 [+0.00, +0.13] (+2 pairs) | +0.04 | +0.0012 [+0.0004, +0.0025] (+8 alerts, +0.2%) | keep |
| j6b. `js.child_process.shell`: request data as program or argument of `spawn`/`execFile` | js_ts | +0.00 [+0.00, +0.00] (+0 pairs) | +0.00 | +0.0005 [+0.0000, +0.0014] (+3 alerts, +0.1%) | revert |
| j9. `js.dom.xss_sink`: `res.send` of markup built from request data | js_ts | +0.00 [+0.00, +0.00] (+0 pairs) | +0.00 | +0.0006 [+0.0000, +0.0018] (+4 alerts, +0.1%) | revert |
| j10. `js.dom.xss_sink`: `el.href`/`src` assigned from the URL or a request | js_ts | +0.00 [+0.00, +0.00] (+0 pairs) | +0.00 | +0.0009 [+0.0002, +0.0020] (+6 alerts, +0.1%) | revert |
| j7. `js.dom.xss_sink` narrowed: built strings and tainted values only | js_ts | -2.45 [-3.77, -1.48] (-123 pairs) | -1.81 | -0.3614 [-0.5635, -0.2106] (-2354 alerts, -53.5%) | revert (narrowing loses detection) |
| j7b. `js.dom.xss_sink` narrowed: jQuery `.html()` only for built strings and tainted values | js_ts | -0.52 [-0.82, -0.29] (-26 pairs) | -0.22 | -0.2344 [-0.4109, -0.1000] (-1527 alerts, -34.7%) | revert (narrowing loses detection) |

`p1c` and `p2c` are `p1` and `p2` plus making the taint analysis run on files that mention `flask`, `tornado` or `falcon` (it skipped files with no `request` word); the same numbers as without. Near misses: `p8b` adds 9 pairs less 2 for +2.1% alerts, just over the line. Nine changes are kept, all of them wider sources or sinks of existing rules, so the registry still has 60 rules. Hand analysis of missed pairs (aggregates only, no code quoted) again found no precise shapes: path traversal misses are library functions with no recognizable source (`Path(root) / key`), XSS misses are sanitizer swaps and version bumps.

Most of `js.dom.xss_sink`'s noise is jQuery `.html(x)` of names, members and calls (about 3,800 of the alerts against about 90 true hits); every narrower form measured loses detection in proportion, so none was kept.

Final scanner against round 1 on the tuning data (paired, repository bootstrap):

| Subset | Detection, points | Fix-aware, points | Alerts per KLOC |
| --- | --- | --- | --- |
| python | +0.26 [+0.09, +0.56] (+10 pairs) | +0.13 | +0.0087 [+0.0044, +0.0146] (+65, +3.1%) |
| js_ts | +0.26 [+0.11, +0.44] (+13 pairs) | +0.16 | +0.0144 [+0.0089, +0.0224] (+94, +2.1%) |
| all | +0.26 [+0.13, +0.42] (+23 pairs) | +0.15 | +0.0114 [+0.0081, +0.0157] (+159, +2.4%) |

| Run | Subset | Detection % | Fix-aware % | Alerts/KLOC (after) | Alerts/KLOC (unchanged) | Precision % |
| --- | --- | --- | --- | --- | --- | --- |
| round 1 | all (8,806 in scope) | 5.67 [4.31, 7.35] | 4.10 [2.95, 5.56] | 0.51 [0.37, 0.69] | 0.35 [0.27, 0.45] | 12.4 [9.4, 16.2] |
| round 2 | all | 5.93 [4.56, 7.63] | 4.25 [3.11, 5.75] | 0.53 [0.39, 0.70] | 0.35 [0.28, 0.45] | 12.6 [9.6, 16.3] |
| round 1 | python (3,778) | 4.61 [2.99, 7.04] | 3.26 [2.00, 5.22] | 0.27 [0.22, 0.34] | 0.31 [0.22, 0.44] | 11.4 [8.3, 15.2] |
| round 2 | python | 4.87 [3.18, 7.40] | 3.39 [2.09, 5.32] | 0.28 [0.23, 0.35] | 0.32 [0.22, 0.44] | 11.7 [8.6, 15.5] |
| round 1 | js_ts (5,028) | 6.46 [4.55, 8.72] | 4.73 [3.15, 6.70] | 0.76 [0.48, 1.13] | 0.40 [0.28, 0.56] | 12.8 [8.6, 18.8] |
| round 2 | js_ts | 6.72 [4.81, 8.97] | 4.89 [3.29, 6.87] | 0.77 [0.50, 1.15] | 0.41 [0.29, 0.57] | 13.0 [8.8, 19.0] |

Round 2 is a small gain: 23 more detected pairs of 8,806 in scope, for 159 more alerts; the nine changes added 129 alerts alone and 159 together (the wider analysis scope adds a few). Alerts rise 2.4% in total, just over the 2% line the single changes each stayed under. Aggregates: [`codebench-tuning-r2-t0.json`](../data/codebench/codebench-tuning-r2-t0.json), [`codebench-tuning-r2-final.json`](../data/codebench/codebench-tuning-r2-final.json), `codebench-compare-r2-*.json`.

**Speed** (job 11306099, one core, every dev file, 39,420 files, two repetitions each, same node): round 1 36.8 and 38.8 files per second, round 2 38.9 and 38.7. No measurable slowdown (the limit was 10%); the scanner still has no runtime dependencies.

### The one-time test2 evaluation

Not run. It claims `reports/LOCKED_EVAL_TEST2.json` in `/scratch/$USER/kestrix/codebench2/` (exclusive create; a second run is refused), scans test2 with kestrix round 2 (the code tree the job runs from), kestrix round 1 (`kestrix@r1`), Bandit and ESLint security, and writes `reports/codebench-locked-test2-v1.json` with the paired round-2-against-round-1 change and the never-scanned-repository subset:

```bash
ssh explorer 'cd ~/kestrix-codebench2-locked && KESTRIX_CODE=$HOME/kestrix-codebench2-locked KESTRIX_CODEBENCH=/scratch/$USER/kestrix/codebench2 sbatch --export=ALL hpc/codebench2_locked.sbatch --name test2-v1 --kestrix-tree r1=$HOME/kestrix-codebench2-r1'
```

### What round 2 does not claim

- Tuning numbers are not a measurement; the test2 run is. With 23 more detected pairs the gain is within the intervals of most subsets.
- test2 shares 332 of its 522 repositories (1,568 pairs) with the tuning data, though no file, CVE, advisory or commit; the separate never-scanned-repository subset (401 pairs) answers whether that matters. 1,243 commits are ones MoreFixes also holds.
- Fixes touching more than 3 changed source files contribute a seeded sample of 3, so a few "changed files" are not the file with the weakness.
- The path, SSRF and XSS gains are small because the scanner has no whole-program data flow; see the error analysis above.

## Round 2 on the fresh held-out set (test2, 2026-10-22)

Run once (job 11308164, claim `LOCKED_EVAL_TEST2.json`) on test2: 1,024 in-scope pairs from 522 projects, with no
advisory, CVE, fix commit or file content shared with any tuning data (332 repositories do overlap; the 239
in-scope pairs from never-scanned repositories are reported separately in the JSON). Report:
[`codebench-locked-test2-v1.json`](../data/codebench/codebench-locked-test2-v1.json). 95% repository-bootstrap
intervals.

| Tool | Language | Detection | False alarms per KLOC (fixed files) |
| --- | --- | --- | --- |
| kestrix-scan round 2 | Python | 7.7% [4.2, 12.0] | **0.23** [0.16, 0.29] |
| kestrix-scan round 1 | Python | 7.5% [4.0, 11.6] | 0.22 [0.15, 0.29] |
| Bandit 1.9.4 | Python | 10.2% [6.3, 14.2] | 0.99 [0.77, 1.21] |
| kestrix-scan round 2 | JS/TS | 10.3% [7.2, 13.9] | **0.43** [0.24, 0.70] |
| kestrix-scan round 1 | JS/TS | 9.0% [5.8, 12.9] | 0.40 [0.22, 0.66] |
| eslint-plugin-security | JS/TS | 12.4% [8.8, 16.1] | 16.93 [14.09, 19.90] |
| eslint-plugin-security without `detect-object-injection` | JS/TS | 7.0% [4.3, 9.8] | 1.51 [1.08, 2.10] |

What test2 shows:

- **Round 2 helped, a little, on unseen code:** detection 8.3% to 9.1% overall (+0.8 points, paired interval +0.1 to
  +1.6; 85 to 93 pairs), mostly in JavaScript and TypeScript, for 3% more alerts (+0.009 per KLOC, interval +0.004 to
  +0.016).
- **Bandit still detects more Python** (−2.5 points, interval −4.7 to −0.2) at about four times the false alarms.
  On JS/TS full ESLint security's lead (−2.0 points, interval −6.3 to +2.8) is not established, at about forty
  times the false alarms; without its noisiest rule ESLint detects less than Kestrix.
- **Using two tools still catches the most:** Kestrix with Bandit detects 11.8% of Python pairs.
- test2 is now spent.
