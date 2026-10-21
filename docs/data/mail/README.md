# Email benchmark outputs (aggregate only)

Produced by `python -m kestrixmailbench` on the Explorer cluster; method, results and caveats are in [`docs/research/mail-benchmark.md`](../../research/mail-benchmark.md). Every file holds counts, rates, intervals, finding-id frequencies, weights or hashes. None holds a message body, address, subject or mailbox name. Raw messages stay under `/scratch/$USER/kestrix/mailbench/`.

| File | What it is |
| --- | --- |
| `mailbench-manifest.json` | URL, size, SHA-256, download time and license note of every archive (the dataset manifest) |
| `build.json` | Messages read, dropped (by reason) and kept per source, label and year |
| `split-manifest.json` | Dev/test counts per source, label and year, group counts, and SHA-256 of each split's message ids |
| `mail-dev-metrics.json` | Baseline metrics on dev for three feature sets, same-era strata, per source, subset and year, miss and false-alarm causes, synthetic families, and the leakage report |
| `mail-weights-<set>[_pooled].json` | Learned candidate weights, intercept, thresholds, targets, training manifest hashes. `<set>` is `all`, `content` (default), `content_strict` or `content_noera`; `_pooled` applies the false-alarm target to pooled ham instead of each ham source. Not wired into `kestrix.mail` |
| `mail-learn-content.json`, `mail-learn-content_noera.json` | Cross-validated learned-versus-baseline tables for the two sets the write-up discusses. The other six reports stay on the cluster (`reports/mail-learn-*.json`) |

The locked test has not been run; when it does, `reports/mail-locked-<name>.json` and `reports/LOCKED_EVAL.json` are added here.
