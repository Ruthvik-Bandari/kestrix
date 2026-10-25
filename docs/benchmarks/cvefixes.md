# Kestrix code scanner on CVE-fix commits (CVEfixes and GitHub Advisory Database)

This page measures `kestrix-scan` on the vulnerable and the fixed version of files from real CVE fix commits, compares it with Bandit and with ESLint's security plugin, and records one round of rule changes judged on the development half only. **The round-1 locked test was run once (see the end of the page) and is spent; round 2 adds a second held-out set, `test2`, which was also run once and is spent ([results](#round-2-on-the-fresh-held-out-set-test2-2026-10-22)).** The numbers up to "Locked test" are development numbers. Code: `src/kestrixcodebench/`, `research/hpc/codebench/codebench_*`; aggregates: [`research/results/codebench/`](../../research/results/codebench/).

Phase 2 (PHP and SQL) has its own [section](#phase-2-php-and-sql-2026-10-24) with a held-out run next to Psalm. Phase 4 (Go, Java, Kotlin, C# and Ruby) has its own [section](#phase-4-go-java-kotlin-c-and-ruby-2026-10-24) with a held-out run next to gosec and Opengrep.

The ground truth is approximate. Read [What is not claimed](#what-is-not-claimed) before quoting any rate.

## Method

**Data.** Nothing new was downloaded: the benchmark reuses what `kestrixvul` acquired on the cluster ([data card](../../research/results/vul/README.md)).

- **CVEfixes v1.0.8** (CC BY 4.0), from the private working database: every Python, JavaScript and TypeScript file a CVE fix commit modified, with the whole file before and after.
- **GitHub Advisory Database fix commits** (CC BY 4.0), mined from the public repositories by `kestrixvul`: commits that neither CVEfixes nor MoreFixes hold, before and after text of each changed file. The files the miner sampled from the parent snapshot of every mined commit (up to 3 per commit, which the commit did not change) are the **unchanged files**.
- MoreFixes (also CC BY 4.0) is not used in this benchmark.

**Filters.** The path and content rules of `kestrixvul.paths`: no test, vendored, bundled, minified or generated files; no file over 400,000 characters or 20,000 lines; before-files shorter than 5 lines are skipped; added and deleted files have no pair; pairs whose two versions differ only in whitespace are dropped. Two commits with the same before and after text are one pair (their CVEs and repositories merge). Dropped changed files: 1228 other-language, 1441 test, 483 minified, 230 bundled, 529 duplicate pairs, plus smaller groups (see `split-manifest.json`).

**A pair** is one changed file of a CVE fix: its before-file and after-file, the lines the fix changed (a `difflib` line diff; a pure insertion counts as the two lines around it), the CVE's CWEs and their *family*.

**Families.** The CWE families of `src/kestrixscanbench/mapping.py` (command injection, code injection, SQL injection, path traversal, XSS, SSRF and so on) plus prototype pollution, ReDoS, CSRF, timing and CORS (`src/kestrixcodebench/families.py`). A pair is *in scope* when a CWE of its CVE maps to a family; the other pairs (CWE-20, memory safety, access control, information exposure, CWEs without an id) are used only where a rate says so. Kestrix and Bandit findings map as in `src/kestrixscanbench/mapping.py`; ESLint's rules map by the weakness each documents.

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

**Tools.** Bandit 1.9.4 (Apache-2.0, `bandit -r . -f json --exit-zero`, the `kestrixscanbench` pin); ESLint 9.39.5 with `eslint-plugin-security` 4.2.0 (Apache-2.0; every rule at the plugin's recommended setting, parsed with typescript-eslint), also reported without `detect-object-injection`, the rule projects usually switch off; kestrix-scan 0.1.0 with `--no-config`. Bandit and ESLint were installed through the transfer node into a private prefix under `/scratch` and run offline; ESLint on the cluster's Node 22 module. **Semgrep was not run:** its registry rules are not licensed for this use and no OSS-licensed local ruleset was available. Each tool scanned only the languages it supports.

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
bash research/hpc/codebench/codebench_sync.sh                       # code to ~/kestrix-codebench (never ~/kestrix), records CODEBENCH_SHA
ssh explorer 'cd ~/kestrix-codebench && sbatch research/hpc/codebench/codebench_build.sbatch'
ssh explorer 'cd ~/kestrix-codebench && sbatch --export=ALL,TOOL=kestrix,RUN=base research/hpc/codebench/codebench_scan.sbatch'   # also bandit, eslint
ssh explorer 'cd ~/kestrix-codebench && bash research/hpc/codebench/codebench_round.sh LABEL'      # scan + dev metrics + paired compare
```

The locked test scans the test half with all three tools and writes `reports/codebench-locked-<name>.json`. It claims the lock first and runs once per scanner version; freeze the code before running it:

```bash
ssh explorer 'cd ~/kestrix-codebench && sbatch research/hpc/codebench/codebench_locked.sbatch --name codebench-v1 --tool-run kestrix=r1-final --tool-run bandit=base --tool-run eslint=base'
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
CVEs, 4,367 file pairs (2,172 in scope). Report: [`codebench-locked-codebench-v1.json`](../../research/results/codebench/codebench-locked-codebench-v1.json).
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

The round-1 locked test is spent, so round 2 uses it as **tuning data** together with round-1 dev (17,474 file pairs, 8,806 in scope; reports label it `tuning`) and builds a new held-out set that no rule was tuned on. Everything in this section up to the test2 run is a tuning number; the run itself is [reported below](#round-2-on-the-fresh-held-out-set-test2-2026-10-22).

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

Aggregate manifest: [`test2-manifest.json`](../../research/results/codebench/test2-manifest.json) (SHA-256 of `pairs.jsonl` `028af3a2...`). The private manifest with advisory ids, repositories, commits and the SHA-256 of every file stays on the cluster (`reports/test2-files.json`), with the files, under `/scratch/$USER/kestrix/codebench2/` (0700/0600; `/scratch` is purged 2026-11-03). Advisory data: CC BY 4.0, attribution to the GitHub Advisory Database; the fetched source files keep their project licenses and are not redistributed. Jobs: select 11303297 (strict), 11303732 (tiers), 11303906 (final); fetch on `explorer-xfer` (1,410 commits); build 11305898 and 11305973.

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

Round 2 is a small gain: 23 more detected pairs of 8,806 in scope, for 159 more alerts; the nine changes added 129 alerts alone and 159 together (the wider analysis scope adds a few). Alerts rise 2.4% in total, just over the 2% line the single changes each stayed under. Aggregates: [`codebench-tuning-r2-t0.json`](../../research/results/codebench/codebench-tuning-r2-t0.json), [`codebench-tuning-r2-final.json`](../../research/results/codebench/codebench-tuning-r2-final.json), `codebench-compare-r2-*.json`.

**Speed** (job 11306099, one core, every dev file, 39,420 files, two repetitions each, same node): round 1 36.8 and 38.8 files per second, round 2 38.9 and 38.7. No measurable slowdown (the limit was 10%); the scanner still has no runtime dependencies.

### The one-time test2 evaluation

Run once on 2026-10-22 (job 11308164); results in the next section. The job claims `reports/LOCKED_EVAL_TEST2.json` in `/scratch/$USER/kestrix/codebench2/` (exclusive create; a second run is refused), scans test2 with kestrix round 2 (the code tree the job runs from), kestrix round 1 (`kestrix@r1`), Bandit and ESLint security, and writes `reports/codebench-locked-test2-v1.json` with the paired round-2-against-round-1 change and the never-scanned-repository subset:

```bash
ssh explorer 'cd ~/kestrix-codebench2-locked && KESTRIX_CODE=$HOME/kestrix-codebench2-locked KESTRIX_CODEBENCH=/scratch/$USER/kestrix/codebench2 sbatch --export=ALL research/hpc/codebench/codebench2_locked.sbatch --name test2-v1 --kestrix-tree r1=$HOME/kestrix-codebench2-r1'
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
[`codebench-locked-test2-v1.json`](../../research/results/codebench/codebench-locked-test2-v1.json). 95% repository-bootstrap
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


## Phase 1: the web stack (tuning numbers, 2026-10-23)

Phase 1 of the [language roadmap](../research/language-roadmap.md) adds web-file rules (HTML, Vue, Svelte, CSS,
`next.config`), Angular's `bypassSecurityTrust*`, and request sources for Next.js, Fastify, Koa and NestJS. **Every
number below is a tuning number.** All earlier held-out sets are spent (round-1 test, test2), the rules were written
and kept with these files in view, and there is no fresh set yet: `research/hpc/codebench/codebench_heldout_future.sh` builds a `test3`
from advisories published after 2026-10-22 once they exist (see the end of this section). Aggregates:
[`research/results/codebench/`](../../research/results/codebench/README.md).

### Method

- **Code and JavaScript/TypeScript changes** use the round-2 tuning data (round-1 dev plus the spent round-1 test:
  17,474 pairs, 8,806 in scope, 4,396 KLOC of after-files and unchanged JavaScript and TypeScript), the round-2
  keep rule, and one repository bootstrap. The baseline is the scanner of the commit the phase started from (`w-base`,
  which reproduces the round-2 numbers: JS/TS detection 6.72%, 0.689 alerts per KLOC). Each change was measured
  **leave-one-out**: the final scanner against the final scanner with only that change switched off (a copy of the
  tree with one constant or condition edited, `research/hpc/codebench/codebench_web_variants.py`), which is the change's marginal effect in
  the final scanner (round 2 measured each change alone against the baseline; these changes touch separate sources and
  sinks, so the marginal and the stand-alone effect are close, but they are not the same measurement).
- **Web files** are in a benchmark root of their own (`--only-language web`, job 11322685), so the ids and the split of
  the Python/JavaScript/TypeScript benchmark are unchanged. The CVEfixes working database holds only **183**
  `.html`/`.htm`/`.vue`/`.svelte`/`.css` changed files (180 with both versions; the mined advisory commits hold none, and no unchanged web
  file was sampled): after the round-1 filters (tests, vendored, minified, generated, duplicates) **92 pairs from 32 projects remain, 73
  in scope** (39 of them XSS, the rest CSRF, SSRF, command and code injection, path traversal and redirect), 27.9 KLOC
  of after-files. They are all tuning data (the claim file of the spent round-1 test is copied into that root). The
  scanner before Phase 1 reads these files for secrets only, so its detection is 0 by construction.
- **Keep rule:** unchanged from round 2 (paired detection up; alerts per KLOC within noise or under 2% of the baseline
  rate). Where the data cannot show detection the table says so instead of inventing a number.

### JavaScript and TypeScript changes (leave-one-out, tuning data)

Baseline: 0.689 alerts per KLOC (4,490 alerts) and 338 detected pairs in JavaScript and TypeScript. Python did not change.

| Change | Detection, points | Alerts per KLOC | Decision |
| --- | --- | --- | --- |
| `js.angular.bypass_trust` (`bypassSecurityTrust*` of a non-literal) | +0.06 [+0.00, +0.20] (+3 pairs) | +0.0000 (+0 alerts) | keep |
| NestJS `@Query()`/`@Body()`/`@Param()`/`@Headers()` parameters as sources | +0.02 [+0.00, +0.07] (+1 pair) | +0.0002 (+1 alert, 0.0%) | keep |
| `new URL(input, base)`: only `input` carries taint | +0.00 (+0 pairs) | -0.0029 [-0.0092, +0.0000] (-19 alerts, -0.4%) | keep (fewer alerts, same detection) |
| Next.js route-handler `params`/`searchParams`, `context.params`, server-action `FormData` | +0.00 (+0 pairs) | +0.0000 (+0 alerts) | no evidence in the data; **kept because requested, fails the keep rule** |
| Next.js `redirect()`, `permanentRedirect()`, `NextResponse.redirect()`, `Response.redirect()` | +0.00 (+0 pairs) | +0.0009 [+0.0000, +0.0024] (+6 alerts, +0.1%) | no detection, +6 alerts: **kept because requested, fails the keep rule** |
| Koa `ctx.get()`, `ctx.headers`, `ctx.request.headers` | +0.00 (+0 pairs) | +0.0003 (+2 alerts, 0.0%) | **kept because requested, fails the keep rule** |
| `request.json()`, `.formData()`, `.text()`, `.arrayBuffer()`, `.blob()` as sources | +0.00 (+0 pairs) | +0.0002 (+1 alert, 0.0%) | **kept because requested, fails the keep rule** |

All together, the final scanner against the round-2 scanner: JavaScript and TypeScript detection **6.72% to 6.80%**
(+0.08 points [+0.00, +0.23], +4 pairs), alerts per KLOC 0.689 to 0.691 (+0.0015 [+0.0003, +0.0032], +10 alerts,
+0.2%); overall 5.93% to 5.97%. The Fastify sources needed no change (`request.query`, `.params` and `.body` were
sources already; tests cover them). The four changes marked "kept because requested" have no detection in this data
(the tuning files hold almost no Next.js, Koa or NestJS code) and together add 10 alerts; each one is a one-line
revert (`_NEXT_REDIRECTS = {}`, `next_context = False`, the Koa branches, `_BODY_READERS`) if the review prefers to
apply the keep rule strictly.

### Web-file rules (tuning data, 92 pairs, 73 in scope)

Per rule, counted on its own findings (`kestrixcodebench rule-rates`): the in-scope pairs it detects (a finding of the
pair's family within 3 lines of a changed line), and the alerts it raises on the after-files (27.9 KLOC; the web
benchmark has no unchanged files). `html.*` and `css.import.http` findings carry CWEs outside the benchmark's families
(CWE-693, 1022 and 319), so they never count as detections or alerts; their counts are shown as findings.

| Rule | Detected pairs | Alerts on after-files (per KLOC) | Findings near a change / on before-files | Decision |
| --- | --- | --- | --- | --- |
| `vue.xss.v_html` | **13** of 73 | 1 (0.04) | 16 / 17 | keep |
| `svelte.xss.at_html` | 3 | 2 (0.07) | 5 / 5 | keep |
| `web.url.dynamic_scheme` | 3 | 10 (0.36) | 4 / 10 | keep (3.3 alerts per detected pair, below the scanner's usual 11) |
| `html.inline.event_handler` | n/a (lint-level, CWE-693) | 0 alerts; 34 findings (1.2 per KLOC) | 2 / 34 | **no measurable detection; kept because requested**, low severity |
| `html.url.javascript_scheme`, `html.link.target_blank`, `html.form.http_action`, `html.mixed.http_resource`, `html.angular.inner_html`, `css.import.http`, `css.expression.legacy` | 0 findings in these 92 files | 0 | 0 / 0 | **no data**: see the clean-corpus counts below; kept because requested |
| `js.*` rules inside web-file `<script>` blocks | `js.dom.xss_sink` 2; `js.exec.eval` 0 | 38 (1.36) and 83 (2.97) | 13 / 38 and 14 / 84 | see below |

Web-file detection as a whole: **27.4%** [7.4, 50.9] of the 73 in-scope pairs (20 pairs), fix-aware 19.2% [2.6, 41.9], against
0 before Phase 1; alerts 4.80 per KLOC on after-files [0.97, 12.03] (134 alerts) at 17.3% precision proxy. The
intervals are wide (32 projects) and 13 of the 20 detected pairs are `v-html` fixes. **79 of the 83 `js.exec.eval`
alerts and 16 of the 38 `js.dom.xss_sink` alerts come from one repository** (a legacy calendar widget with one script in
each of its `.htm` pages), so the 4.80 per KLOC mostly describes that project; leaving it out the eval rule raises 4 alerts and
the XSS-sink rule 22. Running the existing JavaScript rules over `<script>` blocks therefore costs alerts in
legacy pages with no detection gain here (`js.exec.eval` detects 0 of 73), and fails the keep rule on this data; it
stays because the roadmap asks for it and the alerts concentrate in one project.

### Clean web files (no CVE fix touched them)

The CVE data has no unchanged web files, so the false-alarm rate was measured on web files already on the machine
(`kestrixcodebench web-corpus`): 492 distinct files, 123 KLOC (342 `.css`, 146 `.html`, 4 `.scss`; 606 duplicates, 43 minified `.css` and
57 minified `.html` skipped), from third-party packages and the project's own sites. **0.47 findings per KLOC in all**: `html.link.target_blank` 29 (0.235 per KLOC), `js.dom.xss_sink`
in inline scripts 24 (0.19), `html.inline.event_handler` 3, `html.mixed.http_resource` 1, `js.exec.eval` 1; the other
rules, the CSS rules and every Vue and Svelte rule: 0. These are library and project files, not a labelled clean set,
so a finding may be real; read it as an upper bound for hand-written code, on a corpus that holds no Vue or Svelte file.

### Speed

One core, every dev file of the Python/JavaScript/TypeScript benchmark (39,420 files, no web files), all eight shards in turn, two
repetitions each, scanner of the starting commit against the final scanner, same node (job 11323099): baseline 41.2 and 43.1 files per second,
final 42.7 and 42.0 (means 42.2 and 42.4). No measurable slowdown (the limit was 10%); the scanner still has no runtime dependencies. Web files are
scanned in one pass of the tag scanner plus the JavaScript and CSS passes over their script and style blocks, and the 92-pair
web benchmark (about 28 KLOC) scans in seconds. Pathological inputs (tag, brace and comment floods) are linear and tested.

### What this does not show

- The web-file numbers come from 92 pairs, 13 of them `v-html`; they are an existence proof for `v-html` and
  `{@html}` detection, not a rate. The CSS, mixed-content, form, `target="_blank"` and `javascript:` rules have no
  detection data at all.
- No Next.js, NestJS, Fastify or Koa fixture is in the tuning data in numbers that move any rate; those sources are
  covered by unit tests only.
- `next.images.wildcard_host` and the web rules are not compared with another tool: no licensed open-source scanner covers
  these file types in the same way (ESLint's security plugin reads JavaScript only, and Semgrep is not used, see
  [Tools](#method)).
- Everything is tuning data. The held-out test3 below has not been built.

### test3: a fresh held-out set

`research/hpc/codebench/codebench_heldout_future.sh` runs the test2 pipeline against a fresh clone of the GitHub Advisory Database and keeps
only advisories published after a cutoff (`--published-after`, default 2026-10-22), minus everything the benchmark has
touched, in a root of its own (`/scratch/$USER/kestrix/codebench3`): `clone` (transfer node), `select`, `fetch`
(transfer node), `build`, and `eval`, which only prints the one-time `locked-test2` command. Run it once enough
post-cutoff advisories with fix commits exist (the select report counts them), freeze the scanner first, and report
the result next to Bandit and ESLint as for test2. The set will hold Python, JavaScript and TypeScript pairs only: the
advisory miner fetches those files, which is why the web files above come from CVEfixes.


## Round 3: the Bandit gap (tuning numbers, 2026-10-23)

**Every number below is a tuning number.** Both held-out sets (the round-1 test and test2) are spent, so round 3 uses the
round-2 tuning data (round-1 dev plus the round-1 test: 17,474 file pairs, 8,806 in scope, 3,778 of them Python) for the
gap analysis, the rule choices and the measurements, the round-2 keep rule, and one repository bootstrap. Bandit's
findings on that data are the dev scan (`base`) and the locked-test scan of the same Bandit 1.9.4, merged. Aggregates:
[`research/results/codebench/`](../../research/results/codebench/README.md) (`codebench-gap-r3-gap*.json`, `codebench-compare-r3*.json`).

### Where Bandit detects and Kestrix does not

Python, in-scope pairs, `kestrixcodebench bandit-gap` (a pair counts when the tool has a finding of one of the pair's
families within 3 lines of a changed line). Bandit detects 233 pairs (6.17%), Kestrix 184 (4.87%); both 131, only Bandit
102, only Kestrix 53. The 102 by Bandit test id (a pair can carry several ids), with each test's alerts per KLOC on
fixed and unchanged files:

| Bandit test | Gap pairs (of pairs it detects) | What it reports | Alerts per KLOC | What Kestrix has |
| --- | --- | --- | --- | --- |
| B308, B703, B704 | 32 (34), 30 (32), 4 (4) | `mark_safe` and `Markup` | 0.067, 0.059, 0.042 | `py.xss.mark_safe` was tried in round 1: +31% alerts, reverted |
| B404, B603, B607, B605 | 10 (13), 7 (12), 2 (5), 2 (10) | `subprocess` import, `subprocess` without a shell | 0.095, 0.144, 0.066, 0.027 | import and no-shell checks are lint-level; not a rule here |
| B701 | 10 (10) | Jinja2 `Environment` without autoescape | 0.009 | round 2 `p8` failed the keep rule; narrowed below |
| B314, B405, B319, B409, B411 | 10 (10), 7 (7), 1, 1, 1 | stdlib XML parsers and imports | 0.014, 0.015, 0.001, 0.001, 0.003 | none for the stdlib parsers by design |
| B403 | 8 (25) | `pickle` import | 0.029 | the call rules are in place; the import is lint-level |
| B608 | 6 (20) | SQL built from strings | 0.068 | `py.sql.string_built` (different shapes) |
| B202 | 6 (15) | tar `extractall` | 0.007 | `py.archive.extract` |
| B105, B311, B310 | 3, 2, 2 | hard-coded password, `random`, `urlopen` | 0.212, 0.087, 0.019 | noisy; not a rule here |

By family the gap is XSS 46, command injection 17, XML 12, deserialization 8, path traversal 6, SQL injection 6, secrets
3, SSRF 2, weak randomness 2. Reading a handful of missed pairs on the cluster (no code is quoted or committed): the
`mark_safe` pairs are the shape round 1 measured, the XML pairs parse a response body or request body with
`xml.etree.ElementTree.fromstring`, the Jinja pairs are `Environment(loader=FileSystemLoader(...))` in web code, and the
tar pairs call `extractall` on a parameter or pass `members=` or their own `filter=`. The checks the brief named first
(`yaml.load` without a safe loader, `tempfile.mktemp`, `verify=False`, XML parsers with `resolve_entities`, `assert` for
access, `ssl` unverified contexts) are already rules, and none of their Bandit tests is in the gap.

### Changes, each measured alone

Each new rule has its own rule id, so each was measured as the final scan with the other new rules' findings removed
(`research/hpc/codebench/codebench_derive.py`), against `r3-t0` (the scanner at the commit this round started from, scanned on the tuning
data). The baseline is 0.293 Python alerts per KLOC (about 2,170 alerts). The keep rule is unchanged: detection up, and
the paired change in alerts within noise or under 2% of the baseline.

| Change | Detection, points | Fix-aware, points | Alerts per KLOC | Decision |
| --- | --- | --- | --- | --- |
| c1. `py.archive.extract`: `extract`/`extractall` on a parameter named `tar`, `tf`, `tarball`, `archive` ... | +0.00 [+0.00, +0.00] (+0 pairs) | -0.03 | +0.0001 [+0.0000, +0.0005] (+1 alert, +0.0%) | revert (no detection) |
| c2. stdlib XML `fromstring`/`XML`/`parseString` of a non-literal, any file | +0.21 [+0.03, +0.49] (+8 pairs) | +0.13 | +0.0085 [+0.0049, +0.0137] (+63 alerts, +2.9%) | revert (over the 2% line, interval excludes 0) |
| c3. stdlib XML `parse`/`iterparse` of a non-literal, any file | +0.05 [+0.00, +0.14] (+2 pairs) | +0.00 | +0.0051 [+0.0014, +0.0114] (+38 alerts, +1.7%) | not kept: passes the line, but 19 alerts per added pair against 11 for the scanner as a whole (a judgement call, see below) |
| c2+c3 together | +0.26 [+0.07, +0.57] (+10 pairs) | +0.16 | +0.0134 [+0.0075, +0.0216] (+100 alerts, +4.6%) | revert |
| c4. `py.xml.stdlib_parse`, only when the argument is `.content`, `.text`, `.body`, `.data` or `.read()` | +0.03 [+0.00, +0.10] (+1 pair) | +0.03 | +0.0031 [+0.0009, +0.0071] (+23 alerts, +1.1%) | not kept: adds no pair c5 does not |
| **c5. `py.xml.stdlib_parse`: c2 only in files that import a web framework or an HTTP or socket library** | +0.16 [+0.00, +0.46] (+6 pairs) | +0.11 | +0.0032 [+0.0015, +0.0058] (+24 alerts, +1.1%) | **keep** |
| c6. Jinja2 `Environment(autoescape=False)`, explicit | +0.00 [+0.00, +0.00] (+0 pairs) | -0.03 | +0.0003 [+0.0000, +0.0007] (+2 alerts, +0.1%) | revert (no detection; 1 finding in the data) |
| c7. Jinja2 `Environment` with no `autoescape` in a file that imports a web framework | +0.03 [+0.00, +0.10] (+1 pair) | -0.03 | +0.0008 [+0.0002, +0.0018] (+6 alerts, +0.3%) | keep (merged into c9) |
| c8. Jinja2 `Environment` with no `autoescape` and a `FileSystemLoader` or `PackageLoader` | +0.08 [+0.00, +0.20] (+3 pairs) | +0.00 | +0.0038 [+0.0011, +0.0084] (+28 alerts, +1.3%) | keep (merged into c9) |
| **c9. `py.xss.autoescape_off` = c7 or c8, one finding per call** | +0.08 [+0.00, +0.20] (+3 pairs) | +0.03 | +0.0038 [+0.0011, +0.0083] (+28 alerts, +1.3%) | **keep** |

`py.xss.autoescape_off` failed in round 2 (`p8`: +9 pairs for +71 alerts, +3.4%; `p8b`: +7 for +45, +2.1%). Narrowed to file
loaders and web files it keeps 3 of those pairs for 28 alerts. The c6 shape (explicit `autoescape=False`) is the narrowest
one the brief named; the data has one instance of it, so it does not pass. c3 passes the 2% line alone but is the worst
ratio of the changes tried, and c3 and c5 together would take the round past 2% of the alert rate; it is left out and is a
one-line addition (`_STDLIB_XML_FILE` in `python_rules.py`) if the review prefers the rule applied strictly.

The final scanner against `r3-t0`, paired (Python; JavaScript and TypeScript did not change):

| Run | Subset | Detection % | Fix-aware % | Alerts/KLOC (after) | Alerts/KLOC (unchanged) | Precision % |
| --- | --- | --- | --- | --- | --- | --- |
| `r3-t0` | python (3,778 in scope) | 4.87 [3.18, 7.40] | 3.39 | 0.281 | 0.318 | 11.7 |
| round 3 | python | 5.11 [3.34, 7.76] | 3.52 | 0.288 | 0.325 | 11.9 |
| `r3-t0` | all (8,806) | 5.97 [4.57, 7.72] | 4.28 | 0.526 | 0.355 | 12.6 |
| round 3 | all | 6.08 [4.64, 7.83] | 4.34 | 0.530 | 0.360 | 12.7 |

Change: Python detection **+0.24 points** [+0.06, +0.57] (+9 pairs), fix-aware +0.13, alerts per KLOC +0.0070 [+0.0037,
+0.0121] (+52 alerts, **+2.4%**). That is just over the 2% line, as in round 2: each kept change is under it alone, and
together they are not. The Bandit-only pairs fall from 102 to 93 (both 131 to 140); Bandit still detects more Python pairs
on this data (233 against 193). The gap that remains is mostly `mark_safe` (round 1 measured it) and import-level checks.

### The jQuery switch

`js.dom.xss_sink` kept 3,875 of its findings in the jQuery `.html(x)` form. They are now `js.dom.xss_sink.jquery`
(on by default); `rules.disable = ["js.dom.xss_sink.jquery"]` turns them off. Measured as the final scanner against the
final scanner without that rule id (paired, JavaScript and TypeScript, 5,028 in scope): detection **-0.86 points**
[-1.30, -0.52] (-43 pairs), fix-aware -0.30, alerts per KLOC **-0.309** [-0.536, -0.143] (-2,013 alerts, **-44.7%**). With
round 2's narrower forms (`j7`: -123 pairs and -53.5% of the alerts; `j7b`: -26 pairs and -34.7%) the trade-off is steady
at every width: 19 to 59 alerts avoided for each detected pair lost. The switch hands the choice to the project;
the default stays on, since the benchmark counts those pairs.

### Speed

One core, every dev file of the Python/JavaScript/TypeScript benchmark (39,420 files), all eight shards in turn, two repetitions each, scanner of the starting commit against the final scanner, same node (job 11327757, node c0616): baseline 38.5 and 42.1 files per second, final 41.9 and 41.7 (means 40.3 and 41.8). No measurable slowdown (the limit was 10%; the first baseline repetition was the slow one); the scanner still has no runtime dependencies.

### What round 3 does not show

- Tuning numbers only: the gap was read, and the rules written and kept, on the same data they are scored on. The next
  held-out set is `test3` (see Phase 1). Nine more detected pairs of 3,778 is inside every interval.
- Bandit's `mark_safe` tests are 46 of the 102 gap pairs and stay open: round 1 showed the rule costs 31% more alerts.
- The XML rule reports a risk (entity expansion and size) the Python documentation lists, not an external-entity read;
  its CWE is 776 and its severity low. The Jinja rule is a default that is often right for plain-text templates.
- Bandit's test ids B404, B403 and B405 are import checks; matching them would add alerts without a weakness at the line.

## Phase 2: PHP and SQL (2026-10-24)

Phase 2 of the [language roadmap](../research/language-roadmap.md) adds PHP (nine `php.*` rules, a bounded tokenizer, request
sources for plain PHP, Laravel, Symfony, WordPress, CodeIgniter and CakePHP, Blade) and SQL files (three `sql.*` rules). The PHP
rules were tuned on a development split of a new PHP benchmark and then run **once** on its held-out split next to Psalm's
taint analysis. Aggregates: [`research/results/codebench/`](../../research/results/codebench/README.md).

### Data and method

- **Source:** the PHP file changes of the CVEfixes v1.0.8 fix commits (CC BY 4.0). `kestrixvul`'s working database keeps only Python,
  JavaScript and TypeScript, so `kestrixcodebench php-dump` streamed the same pinned archive once more and kept the 12,464
  files labelled PHP (job 11332692, 16 minutes). **The advisory-database miner fetches Python, JavaScript and TypeScript only, so
  there are no advisory PHP pairs and no unchanged PHP files** (the benchmark has no "unchanged" column; false alarms are counted
  on the fixed files and on the clean corpora below).
- **Filters and split:** the benchmark's own (`research/hpc/codebench/codebench_php_build.sbatch`, job `--only-language php`): 8,039 changed files read,
  no test, vendored, bundled, minified or generated files, no duplicates (see `php-manifest.json`). **Dev: 5,274 pairs from 529
  projects, 1,764 CVEs, 3,464 pairs in scope, 3,304 KLOC of fixed files. Held-out: 1,456 pairs from 210 projects, 510 CVEs, 1,121 in
  scope.** The split is the seeded hash of connected components of repositories, CVEs and file contents, so no project, CVE or file
  is on both sides. CWE-98 (file inclusion) was added as the family `fileinclusion`; dev has no pair with that CWE.
- **Metrics, intervals, keep rule:** as above (detection within 3 lines of a changed line, 95% bootstrap over whole repositories).
  Kept changes must buy detection at a price near the scanner's usual 11 alerts per extra detected pair.
- **Comparison tool: Psalm 6.20.1 (MIT)**, `--taint-analysis`, one file at a time (so a before-file and its after-file cannot see
  each other), with Psalm's taint types mapped to CWEs by what each type documents (`TaintedSql` 89, `TaintedHtml` 79,
  `TaintedShell` 78, `TaintedInclude` 98, `TaintedFile` 22, `TaintedSSRF` 918, `TaintedUnserialize` 502, `TaintedEval` 95,
  `TaintedCallable` 94). Installed with Composer on the transfer node, run offline on PHP 8.5.12 (conda-forge); licence recorded in
  [`dataset-licenses.md`](../research/dataset-licenses.md). Psalm needs about 4 s per file, Kestrix about 0.03 s.
- Rounds (all on dev only): `p1`/`p2` showed that about 13% of files hit a recursion error (a variable assigned from itself, such as
  `$x = $x . 'a'`) and were reported as not analyzable; `p3` fixed it and measured the changes below; `p4`/`p5` are the narrowed scanner (`p4` is the frozen tree of
  the held-out run, `p5` the shipped tree without the three removed rules). Jobs (account `aai6610.202610`, partition `short`): dump 11332692; baseline scan `p1` 11346621; Psalm dev scan 11346773; final scan `p5` 11350856; speed 11350619; held-out 11350678; scripts `research/hpc/codebench/codebench_php_*`.

### Tuning on dev: the untainted "built" findings

Round `p3` also reported SQL, command and `eval` text built from a value that is not a literal (no request data needed), like
`py.sql.string_built`. Leave-one-out against `p3` (final scanner against itself without one change; paired intervals):

| Change | Detection, points | Alerts per KLOC | Alerts per detected pair | Decision |
| --- | --- | --- | --- | --- |
| all untainted built findings (SQL, command, eval) | -3.06 [-6.47, -1.23] (-106 pairs) | -0.941 [-1.260, -0.635] (-3,109) | 29 | split below |
| built `eval`/`assert`/`create_function` | -0.09 [-0.22, 0.00] (-3) | -0.087 (-289) | 96 | **removed** |
| built command | -0.23 [-0.48, -0.05] (-8) | -0.078 (-257) | 32 | **removed** |
| built SQL | -2.74 [-6.17, -0.90] (-95) | -0.776 [-1.099, -0.467] (-2,563) | 27 | narrowed |
| ... following `$sql` back to its string | -0.84 [-1.19, -0.53] (-29) | -0.460 (-1,519) | 52 | **dropped** |
| ... counting parameters and globals | -0.81 [-1.21, -0.45] (-28) | -0.422 (-1,393) | 50 | **dropped** |
| ... counting table, column and prefix names | -0.12 [-0.23, -0.03] (-4) | -0.062 (-204) | 51 | **dropped** |
| all three dropped (`tightC`) | -1.36 [-1.84, -0.90] (-47) | -0.652 (-2,153) | 46 | = the narrowing |

What stays is the strict reading of SQL text built from a call result or a variable assigned in the function inside a
concatenation or interpolation (medium severity, low confidence); the text of a lone `$sql` is still followed for the request-data
finding, only the untainted finding does not follow it. Measured on the final scanner, **built SQL gives +1.59 points of detection (+55 pairs)
for +0.179 alerts per KLOC (+592), 10.8 alerts per extra pair**: kept.

Rules that were written and tested but are **not shipped** because on dev they had no detection and only alerts: `unserialize()` of request data
(0 of 34 deserialization pairs, 8 alerts on fixed files), `eval()`/string `assert()`/`create_function()` (0 of 98 code-injection pairs, 4 alerts)
and `preg_replace` with `/e` (0 of those pairs, 5 alerts). They return when data shows detection.

### The shipped scanner on dev (round `p5`, 5,274 pairs, 3,464 in scope)

| Tool | Detection % | Fix-aware % | Fix-weighted % | Alerts per KLOC on fixed files | Precision % (proxy) | Files per second |
| --- | --- | --- | --- | --- | --- | --- |
| kestrix-scan | 5.3 [3.0, 8.9] | 4.2 [2.2, 7.7] | 5.9 [4.4, 7.8] | 0.97 [0.57, 1.40] | 10.8 [5.5, 20.8] | 35.9 |
| Psalm 6.20.1 taint analysis | 2.4 [1.7, 3.4] | 1.8 [1.2, 2.6] | 3.5 [2.5, 4.8] | 0.81 [0.43, 1.39] | 10.5 [6.5, 18.5] | 0.3 |

Kestrix minus Psalm in detection: +2.8 points [+0.9, +6.5] (paired). Of the 3,464 pairs, both detect 72, only Kestrix 110, only Psalm 12,
neither 3,270; the union is 5.6%. By family (pairs, Kestrix, Psalm): SQL injection 885: 10.4% and 1.0%; XSS 1,605: 4.9% and 3.8%; command
injection 104: 3.8% and 5.8%; path traversal 292: 1.4% and 2.1%; SSRF 142: 1.4% and 1.4%; CSRF 480, code injection 98, deserialization 34, redirect 36 and the
rest: 0% for both. Psalm reads PHP with real type and call information and still finds little in single files; the fix lines of most CVEs are
not request-to-sink flows inside one function, which is all either tool can see here.

Per rule on the shipped scanner (`codebench-rates-php-final.json`; alerts are on the 3,304 KLOC of fixed files):

| Rule | Detected pairs | Alerts (per KLOC) | Note |
| --- | --- | --- | --- |
| `php.sql.injection` | 92 | 789 (0.239) | 8.6 alerts per detected pair |
| `php.xss.echo` | 79 | 1,930 (0.584) | 24 per detected pair, above the usual 11; it is the XSS rule and gives most of the detection |
| `php.exec.command` | 4 | 23 (0.007) | |
| `php.path.traversal` | 4 | 260 (0.079) | 65 per detected pair: weak; kept because requested |
| `php.ssrf.request` | 2 | 81 (0.025) | 40 per detected pair: weak; kept because requested |
| `php.include.dynamic` | n/a | 86 (0.026) | **no data**: dev holds no pair with CWE-98, so the benchmark cannot show detection; kept because requested |
| `php.extract.request` | 0 | 0 | no alerts, no detection |
| `php.crypto.weak_password_hash` | n/a | 0 family alerts (CWE-916 maps to no family); 160 findings on before-files, 117 on after-files (0.035 per KLOC) | lint-level |
| `php.blade.unescaped`, `sql.*` | n/a | 0 findings in dev | no Blade or SQL files in the data; unit tests only |

The scanner's overall alerts are 0.97 per KLOC, higher than Python (0.3) and JavaScript (0.7), because XSS and SQL findings on legacy PHP
that fix commits leave elsewhere in the same file count as alerts here.

### Clean PHP code (no CVE fix touched it)

Findings per KLOC of the shipped scanner on current library and application source (shallow clones on the cluster, counts only; an upper
bound on false alarms, the findings may be real): WordPress 702 KLOC, 63 findings (0.091 per KLOC: 49 `php.sql.injection`, 10 `php.xss.echo`,
3 `php.crypto.weak_password_hash`, 1 each `php.include.dynamic` and `php.ssrf.request`); phpMyAdmin 242 KLOC, 6 findings (0.025); laravel/framework
584 KLOC, 20 findings (0.034: 16 `php.blade.unescaped`, 2 `php.crypto.weak_password_hash`, 2 `php.sql.injection`); the Composer packages that Psalm pulls
in, 471 KLOC, 0 findings. Nine `.sql` files in phpMyAdmin gave no finding.

### Speed

One core, every dev file of the Python, JavaScript and TypeScript benchmark (39,420 files, the mixed-language repositories of the earlier
rounds), all eight shards in turn, two repetitions, the scanner of the commit the phase started from (`7106001`) against the final scanner, same job
(11350619): baseline 39.6 and 42.4 files per second (mean 41.0), final 42.3 and 42.5 (mean 42.4); the findings are identical (8,593 in both). The
new code costs those files nothing (the limit was 10%): one more suffix test per file. On the PHP benchmark itself the scanner reads 36 to 47 files per
second; Psalm reads 0.3 to 0.4. Pathological inputs (quote, heredoc, comment, backtick and backslash floods,
80,000 chained assignments, 400 nested arrays, 200,000 statements) are bounded and tested; a bound is reported as `too_complex`.

### Held-out run (`php-v1`)

Run once on the 1,456-pair test split (1,121 in scope, 210 projects, 711 KLOC of fixed files), after the claim file
[`php-heldout-claim.json`](../../research/results/codebench/php-heldout-claim.json) was committed and the lock (`LOCKED_EVAL.json`, scanner tree
`c03f738+8944d155`) was claimed by job 11350678. Scanner frozen; no rule or threshold changed in response.

| Tool | Detection % | Fix-aware % | Fix-weighted % | Alerts per KLOC on fixed files | Precision % (proxy) | Files per second |
| --- | --- | --- | --- | --- | --- | --- |
| kestrix-scan | 5.4 [2.8, 10.2] | 4.2 [1.8, 8.5] | 5.9 [3.5, 9.0] | 0.80 [0.52, 1.29] | 23.2 [11.2, 36.8] | 46.9 |
| Psalm 6.20.1 taint analysis | 3.3 [1.5, 6.7] | 2.9 [1.3, 6.0] | 4.0 [1.9, 6.5] | 0.66 [0.34, 1.14] | 32.8 [11.5, 57.2] | 0.4 |

Kestrix minus Psalm in detection: **+2.1 points [+0.8, +4.5]** (paired bootstrap); both detect 33 pairs, only Kestrix 27, only Psalm 4, neither
1,057 (union 5.7%). Both claims in the claim file hold: Kestrix detection is above Psalm's, and Kestrix alerts per KLOC (0.80) are inside the dev
interval [0.57, 1.40]. By family (pairs, Kestrix, Psalm): XSS 538: 9.9% and 6.5%; SQL injection 329: 2.1% and 0.0%; path traversal 50: 0.0% and 4.0%;
CSRF 209, code injection 39 and deserialization 34: 0% for both. **SQL detection fell from 10.4% on dev to 2.1% here** (7 of 329 pairs): the dev
figure may lean on a few projects with many SQL fixes (not checked here; the Python benchmark's SQL result did); read the SQL rate as somewhere between 2% and 10%, not 10%. The overall detection (5.4% against 5.3% on dev) did not move because XSS rose.

Per rule on the held-out split (`codebench-rates-php-locked.json`): `php.xss.echo` detects 53 pairs with 243 alerts on fixed files (0.342 per KLOC);
`php.sql.injection` 7 pairs with 178 alerts (0.250); `php.exec.command` 0 pairs with 20 alerts; `php.path.traversal` 0 with 74; `php.ssrf.request` 0 with 23;
`php.include.dynamic` 0 with 12. So `php.exec.command`, `php.path.traversal` and `php.ssrf.request`, which had a few detections on dev, had none here.
The three rules removed after the lock claim (`unserialize`, `eval`/`assert`/`create_function`, `preg_replace` `/e`) produced one finding on the test
files (an `unserialize` on a before-file, no detection, no alert on fixed files), so removing them does not change any held-out number above.
The held-out run scanned with the 15-rule tree; the shipped tree has 12 rules.

### What this does not show

- Only CVEfixes: no advisory PHP pairs, no unchanged PHP files; the projects are few (529 on dev, 210 held out), and a handful of them hold many pairs.
- CSRF (480 pairs), missing authorization, information exposure and the other families that are not request-to-sink flows inside one function
  are out of reach of both tools; the detection rates are low in absolute terms and describe what a single-function taint pass can see.
- SQL built by concatenation in other languages: `py.sql.string_built` and `js.sql.string_built` already exist; no change to them was written or measured in this phase.
- The three SQL rules and `php.blade.unescaped` have no detection data at all (no `.sql` or Blade files in the CVE data); `php.include.dynamic` has
  alerts and no CWE-98 pairs to score against. They are covered by unit tests and the clean-corpus counts only.
- Psalm was run on one file at a time, without the project's other files, stubs or config, so it sees less than it would in a project; that is the same
  view Kestrix has, and the fair comparison for this file-pair benchmark.
- The three removed rules were removed after the held-out run had started (the lock was already claimed) on dev evidence alone; the held-out numbers
  describe the scanner with those rules, and their held-out contribution is stated next to them.

## Phase 4: Go, Java, Kotlin, C# and Ruby (2026-10-24)

Phase 4 of the [language roadmap](../research/language-roadmap.md) adds Go, Java, Kotlin, C# and Ruby on Rails: one bounded tokenizer for
Go, Java, Kotlin and C#, one for Ruby, a shared in-function taint index, and 21 rules (`go.*` 4, `java.*` 7 for Java and Kotlin, `cs.*` 4,
`rb.*` 6 for Ruby and ERB templates). The rules were tuned on a development split of a new benchmark and then run **once** on its
held-out split next to gosec (Go) and Opengrep with the opengrep-rules fork of the LGPL Semgrep rules (all five languages). Aggregates:
[`research/results/codebench/`](../../research/results/codebench/README.md).

### Data and method

- **Source:** the Go, Java, C# and Ruby file changes of the CVEfixes v1.0.8 fix commits (CC BY 4.0), plus any file whose path ends in
  `.kt`, `.kts` or `.erb` (CVEfixes has no Kotlin or ERB label). `kestrixcodebench php-dump --label-set p4` streamed the pinned archive once
  more and kept 7,068 file changes (job 11353597, 15 minutes). **As for PHP, the advisory-database miner fetches Python, JavaScript and
  TypeScript only, so there are no advisory pairs and no unchanged files** in this benchmark; false alarms are counted on the fixed files and
  on the clean corpora below.
- **Filters and split:** the benchmark's own (`research/hpc/codebench/codebench_p4_build.sbatch`, `--only-language p4`, job 11353598): 6,215
  changed files read; 1,013 test, 91 generated, 24 bundled, 13 minified, 6 vendored files, 636 files of another language (such as `.jsp` or
  `.gradle`) and 35 duplicates dropped (see `p4-manifest.json`). The split is the seeded hash of connected components of repositories, CVEs
  and file contents, so no project, CVE or file is on both sides.

| Split | Pairs (Go / Java / Kotlin / C# / Ruby / ERB) | In scope (Go / Java / Kotlin / C# / Ruby / ERB) | Projects | CVEs | KLOC of fixed files |
| --- | --- | --- | --- | --- | --- |
| dev | 3,097 (898 / 1,349 / 66 / 289 / 448 / 47) | 1,407 (229 / 730 / 9 / 171 / 234 / 34) | 530 | 968 | 1,271 |
| held-out | 1,278 (461 / 377 / 20 / 65 / 328 / 27) | 409 (89 / 156 / 0 / 41 / 107 / 16) | 223 | 426 | 457 |

  Kotlin (9 in-scope dev pairs, none held out) and C# (171 and 41) are too small to support a claim of their own; a few projects hold many
  pairs (the largest Java project 176 dev pairs, the largest Ruby project 111).
- **Which families.** The rules follow the owner's list (roadmap) and the highest-volume weakness families of each ecosystem in the reviewed
  GitHub Advisory Database (CC BY 4.0, archive of 2026-10-25, `codebench-p4-advisory-families.json`; one advisory can count in several
  families): Go (4,884 advisories) path traversal 387, XSS 274, SSRF 158, command injection 122, SQL injection 78, TLS 74; Maven (7,081)
  XSS 981, deserialization 412, CSRF 380, path traversal 367, XXE 295, code injection 194, SSRF 147, SQL injection 112; NuGet (1,141) XSS
  107, path traversal 46, deserialization 24; RubyGems (1,092) XSS 193, path traversal 55, code injection 48, command injection 47. Most
  advisories (3,450 Go, 3,766 Maven, 865 NuGet, 566 RubyGems) map to no family: authorization, denial of service, information exposure,
  memory safety.
- **Metrics, intervals, keep rule:** as above (detection within 3 lines of a changed line, 95% bootstrap over whole repositories). A change is
  kept when it buys detection at a price near the scanner's usual 11 alerts per extra detected pair; a rule with alerts and no dev detection is
  not shipped unless the owner asked for that family, and then it is marked "kept because requested".
- **Comparison tools.** **gosec 2.30.0** (Apache-2.0), one file at a time in a module of its own (so a before-file and its after-file cannot
  see each other), with the pinned Go 1.27.3 toolchain: standard-library imports resolve, third-party imports do not (offline), and gosec reports
  them and goes on. gosec reports a CWE per finding. **Opengrep 1.32.0** (LGPL-2.1) with **opengrep-rules** `f1d2b562b414` (the fork of the
  LGPL-2.1 Semgrep rules taken before their licence changed; LGPL-2.1 with the Commons Clause, which forbids selling the rules; the rules'
  README says they are for research, testing and benchmarking): every rule of the `go`, `java`, `kotlin`, `csharp` and `ruby` folders, one run
  per shard directory, mapped by the CWEs in each rule's metadata. Opengrep does not read ERB. **Brakeman was not run:** its licence allows
  non-commercial use only. Both tools were downloaded on the transfer node and run offline; licences are in
  [`dataset-licenses.md`](../research/dataset-licenses.md). Opengrep's rule text was never read into Kestrix's rules.
- Rounds (dev only): `q1` first scanner; `q2` archive-entry and upload names as sources; `q3` a lookup such as `map.get(key)` stops taint;
  the leave-one-out measurements on `q3` decided the removals below; `q4` is the tuned scanner (the frozen tree of the held-out run,
  `69d9390+aa6ca8f0`). Jobs (account `aai6610.202610`, partition `short`): dump 11353597, build 11353598, gosec dev 11357210, Opengrep dev
  11357211, final dev scan `q4` 11357920, leave-one-out 11357973 to 11357987 (and 11357846 on `q3`), clean corpora 11357989, speed 11357988, held-out 11358007;
  scripts `research/hpc/codebench/codebench_p4_*`.

### Tuning on dev

Leave-one-out against the tuned scanner `q4` (the scanner against itself without one change; paired intervals; all five languages):

| Change | Detection it adds, points | Extra pairs | Alerts it adds on fixed files | Alerts per extra pair | Decision |
| --- | --- | --- | --- | --- | --- |
| untainted built SQL (all four languages) | +2.99 [+0.67, +6.63] | +42 | +223 (+0.175 per KLOC) | 5.3 | kept |
| ... a lone query name followed to its value | +1.00 [+0.20, +2.05] | +14 | +98 | 7.0 | kept |
| ... parameters counted as not literal | +1.21 [+0.07, +3.00] | +17 | +82 | 4.8 | kept (unlike PHP, where it cost 50 per pair) |
| `html_safe`/`raw`/`<%== %>` of a non-literal (low) | +0.85 [+0.07, +2.25] | +12 | +68 | 5.7 | kept |
| archive-entry and uploaded-file names as sources | +0.36 [+0.08, +0.78] | +5 | +28 | 5.6 | kept |

Measured on `q3` and **removed** (no detection, only alerts): `go.path.traversal` (0 of 41 Go path-traversal pairs, 18 alerts),
`go.ssrf.request` and `cs.ssrf.request` (no finding at all), Go request data written to the `http.ResponseWriter` (0 pairs, 11 alerts) and
`template.HTML` of a non-literal without request data (0 pairs, 14 alerts). Go's path-traversal and SSRF fixes in this data are mostly
archive extraction and webhook URL validation spread over several functions, which a single-function taint pass does not see.

### The tuned scanner on dev (run `q4`, 3,097 pairs, 1,407 in scope)

| Tool | Language | Detection % | Fix-aware % | Fix-weighted % | Alerts per KLOC on fixed files | Files per second |
| --- | --- | --- | --- | --- | --- | --- |
| kestrix-scan | Go | 2.2 [0.4, 4.8] | 1.3 [0.0, 3.1] | 3.4 [0.1, 7.3] | 0.26 [0.09, 0.53] | |
| gosec 2.30.0 | Go | 6.6 [2.9, 11.9] | 1.7 [0.4, 3.8] | 9.9 [3.7, 18.7] | 1.07 [0.69, 1.65] | 0.5 |
| Opengrep | Go | 2.2 [0.0, 5.9] | 1.3 [0.0, 3.2] | 4.8 [0.0, 12.8] | 0.82 [0.51, 1.27] | |
| kestrix-scan | Java and Kotlin | 12.9 [4.8, 27.7] | 11.6 [3.9, 26.2] | 15.6 [9.9, 22.6] | 0.33 [0.18, 0.55] | |
| Opengrep | Java and Kotlin | 9.7 [4.4, 19.0] | 8.0 [3.1, 16.8] | 11.3 [6.8, 17.3] | 0.53 [0.33, 0.70] | |
| kestrix-scan | C# | 0.6 [0.0, 2.5] | 0.6 [0.0, 2.5] | 2.9 [0.0, 10.0] | 0.08 [0.02, 0.17] | |
| Opengrep | C# | 0.0 | 0.0 | 0.0 | 0.07 [0.02, 0.17] | |
| kestrix-scan | Ruby | 17.9 [4.1, 24.3] | 3.4 [1.0, 9.4] | 13.3 [6.1, 21.1] | 1.81 [0.49, 2.54] | |
| Opengrep | Ruby | 6.4 [3.4, 13.4] | 2.1 [0.4, 6.7] | 11.7 [4.6, 19.6] | 3.99 [1.18, 5.70] | |
| kestrix-scan | ERB | 23.5 [0.0, 64.9] | 23.5 [0.0, 64.9] | 26.9 [0.0, 60.0] | 2.15 [0.00, 5.40] | |
| **kestrix-scan** | **all** | **10.7 [5.0, 17.9]** | 7.5 [3.4, 14.7] | 11.4 [7.9, 15.3] | **0.45 [0.23, 0.74]** | 53.3 |
| **Opengrep** | **all but ERB** | **7.3 [4.1, 12.1]** | 5.3 [2.5, 9.8] | 9.6 [6.4, 13.7] | **1.01 [0.62, 1.57]** | 3.4 |

Paired differences in detection: Kestrix minus gosec on Go **-4.4 points [-9.3, -0.8]** (both 3 pairs, only gosec 12, only Kestrix 2: gosec's
lead is its file-path rule G304/G305, 19.5% of 41 path-traversal pairs, which fires on any non-constant path at 1.07 alerts per KLOC); Kestrix
minus Opengrep: all +3.4 [-0.7, +8.0] (both 72, only Kestrix 79, only Opengrep 31; union 12.9%), Java and Kotlin +3.1 [-1.8, +10.2], Ruby
+11.5 [-4.1, +18.8], Go 0.0 [-2.9, +2.7], C# +0.6 [0.0, +2.5]. By family (pairs; Kestrix, Opengrep): Java XXE 89: **77.5%** and 44.9%; Java SQL
injection 87: 12.6% and 20.7%; Java deserialization 207: 3.4% and 3.4%; Java path traversal 90: 4.4% and 2.2%; Java SSRF 102: 2.9% and 0%; Java
XSS 80: 1.2% and 0%; Java code injection 23: 0% and 17.4%; Go SQL injection 36: 11.1% for all three tools; Go TLS 15: 6.7% (gosec 6.7%,
Opengrep 0%); Ruby SQL injection 127: 29.1% and 4.7%; Ruby XSS 59: 6.8% and 6.8%; C# path traversal 64:
1.6% and 0%. Ruby's fix-aware rate (3.4%) is far below its detection: most Ruby detections are the untainted built-SQL finding, which stays on
the fixed file when the fix quotes or casts the value without changing how the text is built.

Per rule on the tuned scanner (`codebench-rates-p4-final.json`; alerts on 1,271 KLOC of fixed files):

| Rule | Detected pairs | Alerts (per KLOC of its language) | Note |
| --- | --- | --- | --- |
| `java.xxe.parser` | 69 (68 Java, 1 Kotlin) | 7 (0.013) | the fix adds the secure feature next to the factory the rule points at |
| `rb.sql.injection` | 37 | 168 (1.28) | 4.5 alerts per detected pair; most findings are the untainted built reading |
| `java.sql.injection` | 11 | 44 (0.081) | |
| `rb.xss.html_safe` | 12 (4 Ruby, 8 ERB) | 68 (54 Ruby, 14 ERB) | all 12 from the low-confidence non-literal reading |
| `java.deserialize.unsafe` | 7 | 77 (0.14) | 11 alerts per detected pair |
| `go.sql.injection` | 4 | 23 (0.050) | |
| `java.path.traversal` | 4 | 32 (0.059) | |
| `java.ssrf.request` | 3 | 21 (0.039) | |
| `go.tls.insecure_skip_verify` | 1 | 54 (0.117) | 54 per detected pair: weak; kept because requested (many are test or internal clients) |
| `java.xss.response` | 1 | 1 | |
| `cs.path.traversal` | 1 | 2 | |
| `rb.path.traversal` | 1 | 11 (0.084) | 11 per detected pair |
| `cs.deserialize.unsafe` | 0 | 6 (0.054) | kept because requested (`BinaryFormatter`) |
| `cs.sql.injection` | 0 | 1 | kept because requested; dev holds 3 C# SQL-injection pairs |
| `rb.exec.command` | 0 | 1 | kept because requested; dev holds 5 Ruby command-injection pairs |
| `go.exec.command`, `go.xss.unescaped`, `java.exec.command`, `cs.exec.process` | 0 | 0 | kept because requested; no finding on dev |
| `rb.reflection.constantize`, `rb.reflection.send` | 0 | 0 family alerts (CWE-470 maps to no family); 2 and 3 findings on fixed files | kept because requested; no unsafe-reflection pairs to score |

### Clean code (no CVE fix touched it)

Findings per KLOC of the tuned scanner on current source of popular projects (shallow clones on the cluster, every file including tests, counts
only; an upper bound on false alarms, the findings may be real): Gitea 509 KLOC of Go, 31 findings (0.061: 29 `go.sql.injection`, all the
untainted reading, 2 `go.tls.insecure_skip_verify`); gin 25 KLOC, 4 (0.16, all `InsecureSkipVerify` in tests and examples); Prometheus 404 KLOC,
5 (0.012); Jenkins 341 KLOC of Java, 85 (0.25: 80 `java.deserialize.unsafe`, 71 of them in tests); Keycloak 1,289 KLOC, 38 (0.029); Ktor 306 KLOC
of Kotlin, 2 (0.007); OkHttp 148 KLOC, 1 (0.007); Jellyfin 368 KLOC of C#, 36 `cs.path.traversal` (0.098; controller parameters joined into file
paths); Bitwarden server 2,111 KLOC, 7 (0.003); Mastodon 199 KLOC of Ruby, 44 (0.22: 36 `rb.xss.html_safe` low, 8 `rb.sql.injection` built); Rails
594 KLOC, 247 (0.42: 190 `rb.xss.html_safe` low, 116 of them in tests, 56 `rb.sql.injection`, 54 in tests); **Discourse 1,538 KLOC, 3,895
(2.53): 3,702 `rb.xss.html_safe`, all the low-confidence non-literal reading and 3,139 of them in specs** (`"...#{x}...".html_safe` in test
helpers), 178 `rb.sql.injection` (170 the built reading), 8 `rb.path.traversal`, 6 `rb.reflection.send`, 1 `rb.reflection.constantize`. Outside
Discourse's specs the Ruby rules give 0.2 to 0.4 findings per KLOC; the low-confidence `html_safe` finding is the noisiest part of the phase.

### Speed

One core, every dev file of the Python, JavaScript and TypeScript benchmark (39,420 files), all eight shards in turn, two repetitions, the
scanner of the commit this phase started from (`6b0dfef`) against the tuned scanner, same job (11357988): baseline 41.3 and 43.4 files per second
(mean 42.4), tuned 43.2 and 43.7 (mean 43.4); **the findings are identical** (8,593 in both, every shard byte for byte). The new code costs those files
nothing (the limit was 10%). On the Phase 4 benchmark itself Kestrix reads 53 files per second on dev, Opengrep 3.4 and gosec 0.5 (one file per run,
with type checking). Pathological inputs (quote, interpolation, heredoc, percent-literal, comment and backslash floods, 400 nested blocks,
20,000-line assignment chains in Java, Go and Ruby) are bounded and tested; a bound is reported as `too_complex`.

### Held-out run (`p4-v1`)

Run once on the 1,278-pair test split (409 in scope, 223 projects, 457 KLOC of fixed files), after the claim file
[`p4-heldout-claim.json`](../../research/results/codebench/p4-heldout-claim.json) was committed and the lock (`LOCKED_EVAL.json`, scanner tree
`69d9390+aa6ca8f0`) was claimed by job 11358007. Scanner frozen; no rule or threshold changed in response.

| Tool | Language (in-scope pairs) | Detection % | Fix-aware % | Fix-weighted % | Alerts per KLOC on fixed files |
| --- | --- | --- | --- | --- | --- |
| kestrix-scan | Go (89 in scope) | 1.1 [0.0, 6.7] | 0.0 | 1.9 [0.0, 6.2] | 0.13 [0.03, 0.26] |
| gosec 2.30.0 | Go | 6.7 [1.5, 26.5] | 3.4 [0.0, 18.2] | 19.4 [5.6, 32.3] | 0.78 [0.45, 1.24] |
| Opengrep | Go | 2.2 [0.0, 12.5] | 2.2 [0.0, 12.5] | 11.1 [0.0, 29.4] | 0.60 [0.34, 0.95] |
| kestrix-scan | Java and Kotlin (156) | 10.9 [5.9, 18.4] | 8.3 [4.2, 14.8] | 14.6 [7.0, 24.6] | 0.20 [0.10, 0.35] |
| Opengrep | Java and Kotlin | 5.8 [1.8, 11.6] | 5.1 [1.3, 10.7] | 4.8 [1.1, 9.5] | 0.34 [0.17, 0.52] |
| kestrix-scan | C# (41) | 2.4 [0.0, 16.7] | 2.4 [0.0, 16.7] | 8.3 [0.0, 33.3] | 0.15 [0.00, 0.43] |
| Opengrep | C# | 0.0 | 0.0 | 0.0 | 0.05 [0.00, 0.20] |
| kestrix-scan | Ruby (107) | 4.7 [1.0, 10.0] | 0.9 [0.0, 3.5] | 7.6 [1.1, 15.3] | 1.55 [0.11, 2.32] |
| Opengrep | Ruby | 11.2 [3.0, 20.3] | 4.7 [0.0, 12.7] | 14.6 [5.4, 24.8] | 1.91 [1.25, 3.11] |
| kestrix-scan | ERB (16) | 81.2 [0.0, 100.0] (13 pairs) | 81.2 | 60.0 | 5.19 (7 alerts on 1.3 KLOC) |
| **kestrix-scan** | **all (409)** | **9.0 [4.8, 14.5]** | 6.8 [3.0, 11.8] | 11.4 [6.7, 16.7] | **0.50 [0.13, 1.00]** |
| **Opengrep** | **all but ERB** | **8.8 [4.5, 14.8]** | 6.8 [2.8, 11.8] | 10.0 [5.5, 15.1] | **0.93 [0.55, 1.31]** |

The claims, checked:

- **Kestrix at or above Opengrep over all Phase 4 pairs: holds as a point estimate only.** 9.0% against 8.8%, difference **+0.2 points
  [-2.8, +3.2]** (paired); both detect 26 pairs, only Kestrix 11, only Opengrep 10, neither 362 (union 11.5%). The dev lead (+3.4) did not carry over.
- **Kestrix alerts within the dev interval and below Opengrep's: holds.** 0.50 per KLOC on fixed files (dev interval [0.23, 0.74]) against 0.93.
- **gosec detects more Go than Kestrix: as expected.** 6.7% against 1.1%, difference -5.6 points [-22.7, -0.7]; gosec's lead is again its untainted
  file-path and command checks (path traversal 36.4% of 11 pairs, command injection 22.2% of 9), at 0.78 alerts per KLOC against 0.13.
- By language, Kestrix minus Opengrep: **Java and Kotlin +5.1 [+1.7, +10.1]** (10.9% against 5.8%); Ruby -6.5 [-15.1, +1.0] (4.7% against 11.2%) (Opengrep's deserialization and XSS rules
  found 4 and 5 pairs); Go -1.1 [-10.5, +3.5]; C# +2.4 [0.0, +16.7] (one pair).

By family (pairs; Kestrix, Opengrep): Java deserialization 16: 37.5% and 37.5%; Java XXE 28: 17.9% and 7.1%; Java path traversal 24: 16.7% and 0%; Java
SQL injection 20: 10.0% and 5.0%; Java XSS 34 and SSRF 14: 0% for both; Ruby SQL injection 10: 10.0% and 0%; Ruby XSS 31: 12.9% and 16.1%;
Ruby and ERB XSS 46: 37.0%; Go SQL injection 48: 0% for all three tools (gosec and Opengrep too); C# path traversal 5: 20.0% and 0%. **Java XXE fell
from 77.5% on dev to 17.9% here and Ruby SQL injection from 29.1% to 10.0%** (1 of 10 pairs): the dev figures lean on a few projects with many
such fixes; read them as somewhere between the two.

Per rule on the held-out split (`codebench-rates-p4-locked.json`): `rb.xss.html_safe` detects 17 pairs (4 Ruby, 13 ERB) with 57 alerts on fixed files;
`java.deserialize.unsafe` 6 with 3; `java.xxe.parser` 5 with 6; `java.path.traversal` 4 with 17; `java.sql.injection` 2 with 2; `rb.sql.injection` 1 with
67; `cs.path.traversal` 1 with 3; `go.exec.command` 1 with 1 (no detection on dev); `go.sql.injection` 0 with 13; `go.tls.insecure_skip_verify` 0 with 2;
`java.ssrf.request` 0 with 1; `rb.path.traversal` 0 with 1; the other rules 0 with 0.

### What this does not show

- Only CVEfixes: no advisory pairs, no unchanged files; 530 dev and 223 held-out projects, a handful of which hold many pairs. Kotlin and C# are too
  small to say anything per language; ERB has 34 dev pairs.
- Most fix lines are not a request-to-sink flow inside one function: CSRF, authorization, denial of service and the Go archive and webhook fixes
  are out of reach of every tool here. The absolute rates describe what single-file analysis can see.
- gosec and Opengrep ran with their defaults on one file at a time (gosec without third-party modules), so they see less than in a project with its
  dependencies; that is the same view Kestrix has, and the fair comparison for this file-pair benchmark.
- `go.exec.command`, `go.xss.unescaped`, `java.exec.command`, `cs.exec.process`, `cs.sql.injection`, `cs.deserialize.unsafe`, `rb.exec.command`,
  `rb.reflection.constantize` and `rb.reflection.send` have no detection on dev (`go.exec.command` detected one held-out pair); they are covered by
  unit tests and the clean-corpus counts and are kept because requested.
- The shipped tree differs from the frozen one (`69d9390+aa6ca8f0`) only in comments and formatting; scanned on every dev file it gives the same
  findings byte for byte (job 11358463).

## Phase 5: C and C++, Rust and Swift (2026-10-25)

Phase 5 of the [language roadmap](../research/language-roadmap.md) is narrow by design: 13 rules that flag only lexically obvious patterns
(`c.*` 7 for C and C++, `rust.*` 3, `swift.*` 3), read with the shared bounded tokenizer (`c_tokens.py`, extended to these languages). Memory-safety
bugs need a compiler front-end and a real analyser; these rules do not judge them, and the numbers below show how little of a C fix history a
lexical scanner sees. The rules were tuned on a development split and then run **once** on the held-out split next to flawfinder and Opengrep.
Aggregates: [`research/results/codebench/`](../../research/results/codebench/README.md).

### Data and method

- **Source:** the C, C++, Rust and Swift file changes of the CVEfixes v1.0.8 fix commits (CC BY 4.0), plus any file whose path ends in `.rs` or
  `.swift`. `kestrixcodebench php-dump --label-set p5` streamed the pinned archive once more (job 11358633, 11 minutes). **No advisory pairs and no
  unchanged files**, as for PHP and Phase 4; false alarms are counted on the fixed files and on the clean corpora below.
- **Filters and split:** the benchmark's own (`codebench_p5_build.sbatch`, `--only-language p5`, job 11358701): 8,776 changed files read; 286 test,
  63 oversized, 10 generated, 8 minified, 8 vendored files, 232 files whose extension is not one of these languages' and 33 duplicates dropped (`p5-manifest.json`). A `.h` header counts as C. Project-disjoint seeded split as in every other benchmark.

| Split | Pairs (C / C++ / Rust / Swift) | In scope (C / C++ / Rust / Swift) | Projects | CVEs | KLOC of fixed files |
| --- | --- | --- | --- | --- | --- |
| dev | 6,463 (5,049 / 1,221 / 166 / 27) | 1,437 (1,031 / 386 / 17 / 3) | 584 | 3,416 | 9,722 |
| held-out | 1,653 (1,399 / 162 / 76 / 16) | 427 (362 / 50 / 14 / 1) | 241 | 907 | 2,577 |

- **Two families were added** to the CWE table for this benchmark: `overflow` (writes past a buffer: CWE-119, 120, 121, 122, 131, 193, 242, 676,
  680, 785, 787, 805, 806) and `formatstring` (CWE-134). Out-of-bounds reads (125), use after free (416), NULL dereference (476) and integer overflow
  (190) stay out of scope: no rule here targets them, and they are 1,689 of the dev CWE labels. Pair families are fixed when a benchmark is built,
  so the earlier benchmarks' roots are unchanged. In scope on dev: overflow 1,176 pairs, TLS 56, command injection 34, format string 15, weak
  randomness 12, path traversal 82 (no rule here), others a handful. Rust has 17 in-scope dev pairs and Swift 3: **too few to measure anything**.
- **Metrics and keep rule:** as above (detection within 3 lines of a changed line, 95% bootstrap over whole repositories; a change must buy
  detection near the usual 11 alerts per extra detected pair; a rule with alerts and no dev detection is kept only when it is a requested family,
  marked "kept because requested").
- **Comparison tools.** **flawfinder 2.0.19** (GPL-2.0-or-later), run as an external program from its unpacked wheel, `flawfinder --csv .` per
  shard at its default level, mapped by the CWEs it reports. **Opengrep 1.32.0** with **opengrep-rules** `f1d2b562b414` (as in Phase 4), every rule
  of the `c`, `rust` and `swift` folders; its C rules target C, not C++, so it reports nothing on `.cpp` files. cppcheck was not run in this phase
  (flawfinder is the established lexical C analyser and the closer comparison); Clippy and cargo-audit do not apply to single files
  (Clippy needs a compiling crate; cargo-audit reads `Cargo.lock`, which Kestrix already checks against OSV). Licences:
  [`dataset-licenses.md`](../research/dataset-licenses.md).
- Rounds (dev only): `r1` the first scanner, which is also the frozen tree; two widenings measured against it and rejected (below). Jobs (account
  `aai6610.202610`, partition `short`): dump 11358633, build 11358701, flawfinder dev 11358847, Opengrep dev 11358848, Kestrix dev `r1` 11358850,
  dev metrics 11358976, widenings 11358999 and 11359001 (compares 11359000, 11359002), held-out 11359570, speed 11359571, clean corpora 11359572;
  scripts `research/hpc/codebench/codebench_p5_*` and `codebench_p4_ablate.sh` with `PHASE=p5`.

### Tuning on dev

| Change against `r1` | Extra detected pairs (C/C++) | Alerts it adds on fixed files | Alerts per extra pair | Decision |
| --- | --- | --- | --- | --- |
| report a non-literal `printf` format even when arguments follow it | +2 (+0.14 points [0.00, +0.43]) | +690 (+0.072 per KLOC) | 345 | **rejected** |
| report `strcpy`/`strcat`/`sprintf` into any destination, not only arrays declared with a size | +13 (+0.92 points [+0.34, +1.81]) | +1,209 (+0.126 per KLOC) | 93 | **rejected** |

### The scanner on dev (run `r1`, 6,463 pairs, 1,437 in scope)

| Tool | Language | Detection % | Fix-aware % | Fix-weighted % | Alerts per KLOC on fixed files | Files per second |
| --- | --- | --- | --- | --- | --- | --- |
| kestrix-scan | C and C++ (1,417) | 1.6 [0.7, 3.4] | 1.5 [0.6, 3.1] | 2.0 [0.9, 4.1] | 0.08 [0.05, 0.14] | 17.8 (all languages) |
| flawfinder 2.0.19 | C and C++ | 13.5 [9.6, 19.1] | 2.8 [1.7, 4.4] | 14.9 [11.3, 20.2] | 3.51 [2.87, 5.10] | 46.7 |
| Opengrep | C and C++ | 1.6 [0.7, 2.9] | 0.5 [0.1, 1.2] | 1.8 [0.7, 3.6] | 0.30 [0.22, 0.54] | 2.5 |
| kestrix-scan | Rust (17) | 0.0 | 0.0 | 0.0 | 0.14 [0.01, 0.40] | |
| Opengrep | Rust | 5.9 [0.0, 30.0] (1 pair) | 0.0 | 14.3 | 1.63 [0.46, 3.45] | |
| both | Swift (3) | 0.0 | 0.0 | 0.0 | 0.00 | |

Kestrix minus flawfinder on C and C++: −11.9 points [−16.8, −8.3] (both 22, only Kestrix 1, only flawfinder 170, neither 1,224). Kestrix minus
Opengrep: +0.1 [−1.0, +1.3] (both 8, only Kestrix 15, only Opengrep 14). flawfinder's lead comes from reporting every `strcpy`, `memcpy`, `sprintf`
and fixed `char` array at level 1 or more, near which many overflow fixes land, at 44 times Kestrix's alerts and a precision proxy of 1.5%.

Per rule (`codebench-rates-p5-r1.json`; alerts on the 9,722 KLOC of fixed files):

| Rule | Detected pairs | Alerts on fixed files | Note |
| --- | --- | --- | --- |
| `c.buffer.unbounded_copy` | 12 (C) | 511 | 43 per detected pair: weak; kept because requested |
| `c.input.scanf_string` | 9 | 38 | 4 per detected pair |
| `c.exec.command` | 2 | 79 | 40 per detected pair: weak; kept because requested |
| `c.format.nonliteral` | 0 of 15 format-string pairs | 74 | **no dev detection; kept because requested** |
| `c.random.rand` | 0 of 12 weak-randomness pairs | 35 | **kept because requested** |
| `c.tempfile.insecure` | 0 (no CWE-377 pair) | 9 | **kept because requested** |
| `c.buffer.gets` | no finding | 0 | no `gets` call left in the data; unit tests only |
| `rust.exec.shell`, `rust.unsafe.input`, `rust.tls.disabled` | 0 | 2, 5, 0 | **no data** (17 Rust pairs; none TLS or command injection); kept because requested |
| `swift.*` | 0 | 0 | **no data** (3 Swift pairs, no `.plist` files); unit tests and clean corpora only |

### Clean code (no CVE fix touched it)

Findings per KLOC of the final scanner on current source of popular projects (shallow clones on the cluster, every file including tests and
`.plist` files, counts only; an upper bound on false alarms): curl 303 KLOC, 4 findings (0.013, all `c.input.scanf_string`); Redis 425 KLOC, 24
(0.057: 14 `c.buffer.unbounded_copy`, 8 `c.random.rand`, 1 each `c.exec.command` and `c.format.nonliteral`); nginx 258 KLOC, 0; libuv 117 KLOC, 8
(0.069); LevelDB 29 KLOC, 0; fmt 71 KLOC, 0; Bitcoin Core 415 KLOC, 1 (0.002); ripgrep 55 KLOC, 0; Tokio 190 KLOC, 5 (0.026: 3 `rust.exec.shell`, 2
`rust.unsafe.input`); Alacritty 34 KLOC, 0; reqwest 28 KLOC, 10 (0.36, all `rust.tls.disabled`: the library's own tests and examples of
`danger_accept_invalid_certs(true)`); Alamofire 44 KLOC, 5 (0.11, `swift.tls.trust_all` uses of its `DisabledTrustEvaluator`); SwiftNIO 222 KLOC, 0;
Kingfisher 43 KLOC, 1 (0.023).

### Speed

One core, every dev file of the Python, JavaScript and TypeScript benchmark (39,420 files), all eight shards in turn, two repetitions, the
scanner of `main` after Phase 4 (`794d4a3`) against the final scanner, same job (11359571): baseline 39.5 and 42.4 files per second (mean 41.0),
final 42.2 and 42.5 (mean 42.4); **the findings are identical** (8,593 in both, every shard byte for byte). The new code costs those files nothing
(the limit was 10%). On the Phase 5 benchmark Kestrix reads 17.8 files per second on dev (C files are long: 1.5 KLOC on average), flawfinder 46.7
and Opengrep 2.5. Pathological inputs (quote, raw-string, comment, lifetime and interpolation floods, 400 nested calls, 20,000-line copy and `let`
chains, 20,000 `.arg()` calls, 20,000 property-list keys) are bounded and tested; a bound is reported as `too_complex`.

### Held-out run (`p5-v1`)

Run once on the 1,653-pair test split (427 in scope, 241 projects, 2,577 KLOC of fixed files), after the claim file
[`p5-heldout-claim.json`](../../research/results/codebench/p5-heldout-claim.json) was committed and the lock (`LOCKED_EVAL.json`, scanner tree
`4609f8c+754f9bad`, the same scanner as the dev run) was claimed by job 11359570. Scanner frozen; nothing changed in response.

| Tool | Language (in-scope pairs) | Detection % | Fix-aware % | Fix-weighted % | Alerts per KLOC on fixed files | Precision % (proxy) |
| --- | --- | --- | --- | --- | --- | --- |
| kestrix-scan | C and C++ (412) | 3.4 [0.7, 6.7] | 1.7 [0.6, 3.1] | 4.2 [1.0, 7.3] | 0.34 [0.10, 0.57] | 2.4 [1.3, 5.8] |
| flawfinder 2.0.19 | C and C++ | 19.4 [13.9, 24.9] | 4.9 [1.9, 8.5] | 21.0 [16.5, 25.9] | 6.13 [4.59, 7.38] | 1.0 [0.7, 1.8] |
| Opengrep | C and C++ | 4.6 [1.1, 8.6] | 1.5 [0.0, 3.5] | 3.5 [0.8, 6.2] | 0.62 [0.27, 0.93] | 3.6 [0.8, 10.1] |
| kestrix-scan | Rust (14) | 0.0 | 0.0 | 0.0 | 0.05 [0.00, 0.13] | |
| Opengrep | Rust | 0.0 | 0.0 | 0.0 | 2.33 [0.09, 6.46] | |
| both | Swift (1) | 0.0 | 0.0 | 0.0 | 0.00 | |

Kestrix minus flawfinder: **−16.0 points [−21.8, −11.2]** (both 14, only Kestrix 0, only flawfinder 66, neither 332). Kestrix minus Opengrep:
**−1.2 points [−4.9, +1.9]** (both 5, only Kestrix 9, only Opengrep 14). Claims in the claim file: flawfinder detects far more (held); Kestrix's alerts
per KLOC are below flawfinder's and Opengrep's (held); **Kestrix's alerts per KLOC stay within the dev interval [0.05, 0.14]: did not hold** (0.34);
Rust and Swift too small (as stated). Kestrix detected 12 overflow, 1 command-injection and 1 format-string pair (the format rule's first detection).

Per rule on the held-out split (`codebench-rates-p5-locked.json`): `c.buffer.unbounded_copy` 9 pairs with 667 alerts on fixed files (0.27 per KLOC,
most of the rise), `c.input.scanf_string` 3 with 51, `c.exec.command` 1 with 25, `c.format.nonliteral` 1 with 101 (43 of them in C++ files),
`c.random.rand` 0 with 17, `c.tempfile.insecure` 0 with 3, `rust.unsafe.input` 0 with 3.

### What this does not show

- Memory safety. Use after free, out-of-bounds reads, integer overflow and most overflow fixes (bounds computed wrongly, a length checked in the
  wrong place) are invisible to a lexical scanner; the absolute rates are what single-file pattern matching sees in a C fix history, not coverage.
- Only CVEfixes: no advisory pairs, no unchanged files; 584 dev and 241 held-out projects, and large projects hold many pairs.
- Rust (17 dev, 14 held-out in-scope pairs) and Swift (3 and 1) say nothing about their rules; the Swift and `.plist` rules are covered by unit tests
  and the clean corpora only.
- flawfinder and Opengrep ran with their defaults; a project that tunes flawfinder's minimum level would see fewer alerts and less detection.
