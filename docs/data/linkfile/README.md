# Link and file benchmark outputs (aggregate only)

Produced by `python -m kestrixlinkfilebench` on the Explorer cluster; method, results and caveats are in [`docs/research/linkfile-benchmark.md`](../../research/linkfile-benchmark.md). Every file holds counts, rates, intervals, finding-id and tag frequencies, or hashes. None holds a URL, host name, file name or file content. Raw downloads stay under `/scratch/$USER/kestrix/linkfilebench/` (directories 0700, files 0600); that area is purged on 2026-11-03.

| File | What it is |
| --- | --- |
| `linkfilebench-manifest.json` | URL, size, SHA-256, download time and license note of every download (the dataset manifest) |
| `link-build.json`, `file-build.json` | Items read, dropped (by reason) and kept per source and label; Govdocs thread, extension and size-band counts; synthetic family sizes |
| `link-split-manifest.json`, `file-split-manifest.json` | Dev/test counts per source and label, group counts, and SHA-256 of each split's item ids |
| `link-dev-metrics.json`, `file-dev-metrics.json` | Baseline (shipped rules) dev metrics with grouped bootstrap intervals, error analysis, and for links the leakage controls and matched subset; for files per-type, per-extension and per-finding rates and synthetic families |
| `link-dev-metrics-round1.json`, `file-dev-metrics-round1.json` | The same reports for the rules after round 1 (final code, dev only) |
| `linkfile-rules-round1.json` | Headline dev numbers, decision and Slurm job ids of every round-1 change, baseline and final code versions |
| `link-probe-baseline.json`, `file-probe-baseline.json` | Counts of curated host-shape and hosting-platform tags (links) or content classes (files) per cohort of dev items under the shipped rules (cells under 3 dropped); input to the round-1 decisions |

The locked test has not been run; when it does, `<kind>-locked-<name>.json` and `LOCKED_EVAL.json` are added here.
