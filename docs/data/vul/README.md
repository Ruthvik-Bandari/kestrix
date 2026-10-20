# Code-vulnerability data: C5 results

This folder records slice C5 of ADR 0005: data acquisition, checks, relabelling, deduplication, license
annotation and the frozen split for a learned Python/JavaScript vulnerability model. The plan is
[`docs/research/code-vuln-ml-plan.md`](../../research/code-vuln-ml-plan.md); sources and licenses are in
[`../sources.md`](../sources.md). **Nothing was trained or evaluated.**

The files here are aggregate: counts, CWE ids, dates, hashes and record ids. They hold no code, commit
messages or CVE text. Raw data and every intermediate file stay private on the cluster under
`/scratch/$USER/kestrix/vul/` (directories 0700, files 0600). `/scratch` is purged on the first Tuesday of
each month; everything is rebuildable from the pins.

| File | Contents |
| --- | --- |
| `qc.json` | Verified pins, per-language counts, source labels, CWE and date distributions, file-filter shares |
| `labels.json` | PrimeVul relabelling counts per source and language |
| `dedup.json` | Exact and near-duplicate removal counts |
| `licenses-summary.json`, `licenses.csv` | Per-repository SPDX license (public GitHub metadata) and class counts |
| `split-manifest.json` | Record ids and SHA-256 per split (`manifest_sha256` `1e52811528832d0daf42f63399734b4643bcb7cc051708bd6f077cf4ce88986a`) |

## How it ran

| Step | Where | Job | Time | Peak memory |
| --- | --- | --- | --- | --- |
| `hpc/vul_acquire.sh` | transfer node | n/a | about 20 min, 19.2 GB | n/a |
| `hpc/vul_qc.sbatch` (dump load + report) | `short` | 11243417 | 32 min | 28 GB (load) |
| `hpc/vul_qc.sbatch` (report, load cached) | `short` | 11247714 | 10 min | under 19 GB |
| `hpc/vul_build.sbatch candidates` | `short` | 11252456 | 21 min | 0.8 GB |
| `licenses-fetch` | owner's machine, `gh api repos/{owner}/{repo}` | n/a | about 10 min | n/a |
| `hpc/vul_build.sbatch split` | `short` | 11252667 | 3 s | under 10 MB |

To reproduce (the license step runs where `gh` is signed in; the token never reaches the cluster):

```bash
ssh explorer-xfer 'cd ~/kestrix && bash -l hpc/vul_acquire.sh'
ssh explorer 'cd ~/kestrix && sbatch hpc/vul_qc.sbatch'                 # then:
ssh explorer 'cd ~/kestrix && sbatch hpc/vul_build.sbatch candidates'
scp explorer:/scratch/$USER/kestrix/vul/licenses/repos.txt .
uv run python -m kestrixvul licenses-fetch --repos repos.txt --out fetched.csv
scp fetched.csv explorer:/scratch/$USER/kestrix/vul/licenses/fetched.csv
ssh explorer 'cd ~/kestrix && sbatch hpc/vul_build.sbatch split'
```

The SHA-256 of every archive is pinned in `src/kestrixvul/sources.py` and re-verified before each QC run.

## Per-language counts in the sources

Fix commits only; MoreFixes counts use the authors' recommended `score >= 65`.

| Source | Language | File changes | Fix commits | CVEs | Projects | CVE dates |
| --- | --- | --- | --- | --- | --- | --- |
| CVEfixes v1.0.8 | Python | 2,753 | 1,059 | 1,089 | 530 | 2011-09 to 2024-07 |
| CVEfixes v1.0.8 | JavaScript | 3,656 | 1,302 | 1,337 | 800 | 2011-11 to 2024-07 |
| CVEfixes v1.0.8 | TypeScript | 2,563 | 767 | 799 | 474 | 2013-04 to 2024-07 |
| MoreFixes v4 | Python | 9,683 | 3,490 | 2,905 | 1,096 | 2006-12 to 2026-06 |
| MoreFixes v4 | JavaScript | 6,801 | 3,046 | 2,964 | 1,424 | 2008-07 to 2026-06 |
| MoreFixes v4 | TypeScript | 4,651 | 1,475 | 1,384 | 737 | 2013-09 to 2026-06 |

- **GitHub Advisory Database:** 6,350 reviewed PyPI advisories and 7,443 reviewed npm advisories, not withdrawn.
  Of these, 4,003 and 3,974 cite a fix commit (4,939 and 4,705 distinct commits). MoreFixes holds only
  1,736 and 1,683 of those commits, and CVEfixes 736 and 789, so the GHSA fix commits are a large unused pool. Turning them into
  function pairs would need the repositories to be cloned (a later slice).
- **SVEN:** 380 Python vulnerable/patched pairs (342 train, 38 val), across CWE-22, -78, -79 and -89, from
  141 projects.
- **Test window:** CVEfixes ends in July 2024, so every post-cutoff (test) record comes from MoreFixes.

**JavaScript is noisy before filtering.** In CVEfixes, 15.5% of JS file changes are minified, 7.1% are
dist or bundle files, 2.1% are vendored and 12.3% are tests. Lizard splits minified files into thousands
of "methods", so the source's own labels are meaningless there: 82,999 "vulnerable" before-fix method
rows come from just 3,656 JS file changes. MoreFixes JS is cleaner (4.9% minified, 3.9% dist). About 30%
of Python file changes are tests.

## How many functions survive each stage

A record is one vulnerable function (its before-fix version) with its patched counterpart.

| Stage | Python | JavaScript | TypeScript |
| --- | --- | --- | --- |
| Changed functions in kept fix-commit files (CVEfixes + MoreFixes) | 14,862 | 13,367 | 5,313 |
| Labelled vulnerable (OneFunc or NVDCheck), before size limits | 1,833 | 1,139 | 461 |
| Kept after the 3 to 400 line limit and before-version check, plus SVEN | 2,068 | 1,029 | 358 |
| After deduplication | **1,528** | **674** | **265** |
| In the split (train / dev / test) | 614 / 483 / 206 | 480 / 52 / 81 | 154 / 23 / 66 |
| Permissive-license pool (train / dev / test) | 349 / 224 / 122 | 278 / 25 / 59 | 97 / 17 / 40 |

- **Labels by rule:**
  - CVEfixes and MoreFixes Python: OneFunc 1,375, NVD names the function 414, NVD names the file 44,
    uncertain 13,029;
  - JavaScript: OneFunc 865, function name 259, file 15, uncertain 12,228.
- **"Uncertain" is excluded,** which is 88% (Python) to 92% (JavaScript) of changed functions. That is the intended cost of the
  PrimeVul rules.
- **20% to 24% of the changed functions that have a before-fix version had it cut from the file text.** CVEfixes and MoreFixes
  record a before-fix row only when a deleted line falls inside the function. A fix that only adds a check
  has no before-fix row, so the diff's line mapping recovered it (`pair_kind` `before_reconstructed`).
- **Deduplication** removed 37% of MoreFixes Python and 45% of MoreFixes JS. Most of it is MoreFixes
  repeating CVEfixes (651 records) or itself (263 records, forks and backports).
- **Split drops:** 308 records were published after the cutoff but belong to a project with earlier CVEs.
  They were dropped to keep train and dev before the cutoff and test on unseen projects.

## The split

- **Grouping:** connected components of repositories and CVE/GHSA ids, so projects and advisories are
  disjoint across splits (checked in code).
- **Test:** groups whose earliest CVE was published on or after 2024-10-01.
- **Dev:** all SVEN groups, plus a seeded 10% of the other pre-cutoff groups.
- **Train:** everything else.

| Split | Records | Projects | With patched counterpart | Sources |
| --- | --- | --- | --- | --- |
| train | 1,248 | 786 | 1,228 | CVEfixes 604, MoreFixes 644 |
| dev | 558 | 230 | 553 | SVEN 353, CVEfixes 83, MoreFixes 122 |
| test | 353 | 261 | 346 | MoreFixes 353 |

The test ids are frozen in `split-manifest.json`; no model has seen or scored them.

## Licenses

GitHub reports these classes for the 1,276 GitHub repositories in the pool:

| Class | Repositories |
| --- | --- |
| Permissive | 706 (MIT 452, Apache-2.0 166, BSD-3-Clause 56, BSD-2-Clause 13, ISC 13, Unlicense 5, 0BSD 1) |
| Copyleft | 187 (GPL-3.0 95, AGPL-3.0 59, GPL-2.0 31, …) |
| Weak copyleft | 32 |
| No license | 128 |
| `NOASSERTION` or unlisted | 206 |
| Not found | 17 |

- **The shipped-weight pool** (permissive only) is 827 Python, 404 JavaScript and 164 TypeScript records
  before the split.
- **In the split it has 349 Python and 278 JavaScript training records.**

## Label accuracy caveat

These labels are rule-based. PrimeVul measured 86% to 92% accuracy for the same rules on C/C++. No audit
has been done here. The plan requires a hand audit of at least 200 samples, plus the Qwen2.5-Coder cleaning
pass, before training. Two known weaknesses:

- **NVDCheck by file name.** It labels a function only when it is the only one changed in its file (PrimeVul's
  rule). 1,240 changed functions sat in a file the description names but had siblings, and were left uncertain.
- **Plain-word function names** (`parse`, `render`) count as named only in a code context.

## What this means for feasibility

- **Python, research tier:** 614 train, 483 dev and 206 test vulnerable functions, each with its patch.
  That is enough for paired evaluation and a small fine-tune, but it is two orders of magnitude below what
  published function-level detectors train on. Expect weak absolute numbers (plan, "Expectations").
- **Python, shipped weights:** 349 permissive training pairs. That is very small for training a classifier
  from scratch. Distillation from a larger teacher, or pairwise or contrastive objectives on the pairs, is the
  realistic path.
- **JavaScript:** 480 training records but only 52 for dev. Dev needs either a different seed or more data
  before any threshold is chosen.
- **Biggest lever:** at least 2,467 PyPI and 2,233 npm GHSA fix commits are in neither CVEfixes nor MoreFixes
  (more if the two overlap). Mining them (clone, extract functions, same labelling) could substantially
  enlarge the pool.
- **Missing negatives:** the pool holds vulnerable functions and their patches only. A realistic-prevalence
  test set also needs unchanged functions from the same files.
