# Code benchmark aggregates

Counts, rates, 95% repository-bootstrap intervals and rule ids from `kestrixcodebench` (method and caveats:
[`docs/benchmarks/cvefixes.md`](../../benchmarks/cvefixes.md)). No code, file paths, repository names or CVE text. Raw
files stay on the cluster under `/scratch/$USER/kestrix/codebench/` (and `codebench2/` for test2). The round-1 locked test is in
`codebench-locked-codebench-v1.json`; test2 (a second held-out set) has a manifest only and has not been run.

| File | Contents |
| --- | --- |
| `split-manifest.json` | Dev and test counts, drop counts, SHA-256 of the id lists |
| `codebench-dev-base.json` | Dev metrics of kestrix-scan before round 1, Bandit and ESLint (per language, per family, overlap, error analysis, speed) |
| `codebench-dev-r1-final.json` | The same after the kept round-1 changes |
| `codebench-compare-r1-*.json` | Paired change against the baseline for each tried change (`v1` mark_safe, `v2` tar, `v3` jQuery, `v4` ReDoS, `all`/`all2` changes 1 to 4, `s1`..`s7` diagnostic splits, `t`, `c5`, `tc5` tar and deserialization, `final`) |
| `codebench-tuning-r2-*.json` | Round 2: kestrix on the tuning data (round-1 dev plus the spent round-1 test), round 1 (`t0`) and the final scanner |
| `codebench-compare-r2-*.json` | Paired change of each round-2 change against `t0` (`p*` Python, `j*` JavaScript and TypeScript; `final` all kept changes) |
| `test2-manifest.json` | Counts, drop counts, ids hash and overlap checks of the second held-out set (aggregates only) |
