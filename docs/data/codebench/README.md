# Code benchmark aggregates

Counts, rates, 95% repository-bootstrap intervals and rule ids from `kestrixcodebench` (method and caveats:
[`docs/benchmarks/cvefixes.md`](../../benchmarks/cvefixes.md)). No code, file paths, repository names or CVE text. Raw
files stay on the cluster under `/scratch/$USER/kestrix/codebench/`. Everything here is development data; the locked test
has not been run.

| File | Contents |
| --- | --- |
| `split-manifest.json` | Dev and test counts, drop counts, SHA-256 of the id lists |
| `codebench-dev-base.json` | Dev metrics of kestrix-scan before round 1, Bandit and ESLint (per language, per family, overlap, error analysis, speed) |
| `codebench-dev-r1-final.json` | The same after the kept round-1 changes |
| `codebench-compare-r1-*.json` | Paired change against the baseline for each tried change (`v1` mark_safe, `v2` tar, `v3` jQuery, `v4` ReDoS, `all`/`all2` changes 1 to 4, `s1`..`s7` diagnostic splits, `t`, `c5`, `tc5` tar and deserialization, `final`) |
