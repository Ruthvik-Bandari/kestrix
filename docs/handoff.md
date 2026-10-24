# Session handoff

Maintained per session: overwrite these sections at the end of every Claude Code session (see `.claude/workflow.md`). Detailed history lives in git.

## Current git SHA

The tip of `main`, pushed to `origin/main` after every change. The working tree is clean after the commit that updates this file (2026-10-21).

## State on 2026-10-23

`main` is pushed after every change; the working tree is clean. Plugin repo `kestrix-claude-plugin` is rebuilt
from `scripts/build_plugin_repo.py` and pushed with it. Both repos are private.

**Measured accuracy (each locked/held-out test run once; details in the linked docs):**

| Area | Result | Doc |
| --- | --- | --- |
| Email | phishing flagged 49.4% -> 61.2%, normal mail flagged 5.0% -> 1.2%, precision 95.2% | `docs/research/mail-benchmark.md` |
| Files | benign false alarms (medium+) 4.26% -> 0.28%; synthetic catch 90 -> 168 of 180 | `docs/research/linkfile-benchmark.md` |
| Links | phishing at low+ 58.4% -> 83.3%, at medium+ 1.8% -> 3.6% | same |
| Code (round 1, CVEfixes test) | Python 4.4% / JS-TS 5.6% detection at 0.29 / 0.91 FA per KLOC | `docs/benchmarks/cvefixes.md` |
| Code (round 2, fresh test2) | 8.3% -> 9.1% overall; Bandit 10.2% Py at 4x the FAs | same |
| Vulnerability ranker model | teacher PR-AUC 0.249 on the locked test; not shipped | `docs/research/code-vuln-ml-plan.md` |

All held-out sets above are spent. New rounds need new held-out data (TREC 2007 for mail once approved; newer GHSA
advisories for code).

**Shipped this session:** redesign phases 1-8; emerald restyle of site and app; Pillow-style docs (47 pages, search,
Security and trust, native diagrams); README architecture diagram; whole-site website check with login probes and
one-time-code login detection; website exposure check (EOL/known-vulnerable announced versions, PHP2Shell data);
kestrix-scan: nine dependency ecosystems, index freshness warnings, conditional `db update`, daily CI template, wider
install guard; mail rules round 1 + casino/spam signals; forensics round-1 rules; code round 1 and 2; hosted security
(refresh grace window, re-auth for deletion, slow-request limits, optional shared SQLite rate limiter); strict CSP,
deploy preflight, CI security job; accessibility pass (contrast, headings, landmarks, 44 px targets, 200% text);
security contact ruthvik299@gmail.com; language roadmap (`docs/research/language-roadmap.md`).

**Cluster:** irreplaceable outputs archived to `~/kestrix-archive/20261022/kestrix-scratch-keep.tar.gz` (3.2 GB,
SHA-256 in `SHA256SUMS`): frozen splits, locks, manifests, features, reports, logs, teacher adapters, student fp16,
M1 adapters. `/scratch` (base models 139 GB, raw corpora) is purged 2026-11-03 and is reproducible from manifests.

**Owner-only before going public:** deploy (domain, DNS/TLS, Google/GitHub OAuth apps, production secrets, legal
review of `docs/legal/`, monitoring, backups, HSTS preload choice; checklist in `docs/deploy.md`); PyPI trusted
publishing (the wheel must bundle the built dashboard); making repos public; plugin marketplace submission (icon
missing); TREC 2007 application; the paid plugin A/B eval; check repo visibility (a gitdiagram.com diagram of the
repo was generated).

**Commands run at the end of the session:** `uv run pytest` 3155 passed, 1 skipped (RLIMIT_AS, Linux only);
`ruff check`, `mypy` clean; `scripts/check_claude_pack.py` 177/177; frontend lint, typecheck, 292 tests, build;
browser sweep 390 page loads with no overflow, console errors or CSP violations.

## Completed

- Kestrix 0.1.0 package, dashboard and documentation (`0b76c16`, `8798c97`, `911b87a`).
- HPC access to Northeastern Explorer:
  - SSH aliases `explorer` (login), `explorer-01` (fallback login node) and `explorer-xfer` (transfer node);
  - the repo is at `~/kestrix`;
  - jobs charge `aai6610.202610`.
- `src/kestrixbench/` (not in the wheel) also has `review-sheet`/`review-next`/`review-label`/`review-status`, `split` (preview, `--freeze`) and `variants` (verified impairment cases). It does three core things:
  - `acquire` fetches the pinned sources;
  - `qc` writes aggregate checks;
  - `replay` runs every supported rule on the pinned Elasticsearch against SigmaHQ regression and OTRF events.
- ADR 0002 widened the Sigma subset to lists of field maps, `|all`, and `1 of` / `all of`. 997 of 1,182 SigmaHQ rules are now supported (up from 192).
- Replay (job 11105959):
  - 0 engine errors;
  - fidelity 83/83 against SigmaHQ's declared match counts;
  - 176 rules with at least one positive and 43 with two or more.
  - Details are in `docs/data/qc/README.md`.
- Webcheck:
  - CSP strength, HSTS details and cookie prefix checks;
  - offline conformance pages;
  - `scripts/webcheck_conformance.py`, with 8/8 badssl.com endpoints as expected.
- Fixed bugs:
  - dated Sigma rules were rejected;
  - the engine client sent loopback traffic through `HTTP_PROXY`;
  - QC collapsed same-named OTRF archives (155 counted as 118);
  - two review findings on the subset widening (edit counting, underscore patterns).

## Commands actually run

| Command | Result |
| --- | --- |
| `uv run pytest` | 551 passed (engine up) |
| `uv run ruff check`, `ruff format --check`, `mypy` | clean (55 source files) |
| `uv run python scripts/webcheck_conformance.py` | 8/8 endpoints as expected |
| `ssh explorer-xfer 'cd ~/kestrix && bash -l research/hpc/detect/fetch_engine.sh'` | Elasticsearch 8.19.3 tarball, SHA-512 verified |
| `sbatch research/hpc/detect/qc.sbatch` (job 11105891) | COMPLETED, 0 problems |
| `sbatch research/hpc/detect/replay.sbatch` (job 11105959) | COMPLETED, 997 rules, 0 engine errors |

## Facts learned about the cluster

- Compute nodes have no internet, and the nodes set `http(s)_proxy` without `NO_PROXY`. Loopback traffic must bypass the proxy.
- The transfer node has internet and the same `/home` and `/scratch`. It runs CentOS 7 with no Apptainer, so never build the environment there. Slurm is not available on it.
- The login node `explorer-02` (129.10.0.146) timed out on 2026-10-15. `explorer-01` (129.10.0.145) worked.
- There is no Docker. Jobs run Elasticsearch from the official tarball. Its bundled S3 plugin probes cloud metadata unless `AWS_REGION` is set.
- `/scratch` is purged on the first Tuesday of each month.

## Failed or skipped checks

- Replay job 11105413: the health check went through the proxy. Fixed.
- Replay job 11105791: duplicate OTRF event ids were caught by the engine count check. Fixed.

## Next action

Gmail / Microsoft 365 read-only connector for the email check (design first: scopes, local vs hosted, Google
restricted-scope verification for a public hosted app).

## Repository cleanup 2026-10-24

- Deleted: 9 unreferenced `docs/screenshots/*.png`; the shipped redesign folder `docs/design/2026-10-21-redesign/` (only
  `DESIGN.md` kept, now `docs/design-system.md`); the old CyberGuard starter pack files in `docs/claude/`; the skills
  `cg-plan-slice`, `cg-connector`, `cg-telemetry-ingest`, `cg-model-training`, `cg-evaluate`, `cg-release-review`;
  unused landing samples (`file`, `url`, `detect`, `bitcoin`) and dead frontend exports.
- Moved: `docs/claude/workflow.md` and `skill_validation_cases.md` to `.claude/`;
  `docs/CyberGuard_Engineering_Plan.md` to `docs/history/cyberguard-engineering-plan.md`.
- Renamed: remaining `cg-*` skills to `kx-*`. `scripts/check_claude_pack.py` checks the new set.
- Added: `docs/README.md` (docs index); `bench-results/` and `.gstack/` in `.gitignore`.
