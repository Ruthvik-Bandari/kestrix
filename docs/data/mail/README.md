# Email benchmark outputs (aggregate only)

Produced by `python -m kestrixmailbench` on the Explorer cluster; method, results and caveats are in [`docs/research/mail-benchmark.md`](../../research/mail-benchmark.md). Every file holds counts, rates, intervals, finding-id frequencies, weights or hashes. None holds a message body, address, subject or mailbox name. Raw messages stay under `/scratch/$USER/kestrix/mailbench/`.

| File | What it is |
| --- | --- |
| `mailbench-manifest.json` | URL, size, SHA-256, download time and license note of every archive (the dataset manifest) |
| `build.json` | Messages read, dropped (by reason) and kept per source, label and year |
| `split-manifest.json` | Dev/test counts per source, label and year, group counts, and SHA-256 of each split's message ids |
| `mail-dev-metrics.json` | Baseline metrics on dev for three feature sets, same-era strata, per source, subset and year, miss and false-alarm causes, synthetic families, and the leakage report |
| `mail-dev-metrics-round1.json` | The same report for the rules after round 1 (final code, dev only) |
| `mail-rules-round1.json` | Headline dev numbers, decision and Slurm job ids of every round-1 rule change, content-only feature set |
| `mail-probe-baseline.json` | Counts of coarse message properties and curated candidate terms per cohort of dev messages under the shipped rules (cells under 3 dropped); input to the round-1 decisions |
| `mail-weights-<set>[_pooled].json` | Learned candidate weights, intercept, thresholds, targets, training manifest hashes. `<set>` is `all`, `content` (default), `content_strict` or `content_noera`; `_pooled` applies the false-alarm target to pooled ham instead of each ham source. Not wired into `kestrix.mail` |
| `mail-learn-content.json`, `mail-learn-content_noera.json` | Cross-validated learned-versus-baseline tables for the two sets the write-up discusses. The other six reports stay on the cluster (`reports/mail-learn-*.json`) |

The locked test has not been run; when it does, `reports/mail-locked-<name>.json` and `reports/LOCKED_EVAL.json` are added here.

Modern normal mail (section "Modern normal mail (2022-2026)" of the research page; mailing-list months, aggregates only):

| File | What it is |
| --- | --- |
| `modern-build.json` | Messages read, dropped (duplicates, per-month cap) and kept per list and year; the list-level dev/held-out split with hashes of each split's ids |
| `modern-dev.json` | Dev metrics for the current rules: flagged and malicious rates by source, list, year and source-year with group-bootstrap intervals, finding frequencies and flagging id sets, the auth-header analysis, the Reply-To exemption counts, the synthetic cohort |
| `modern-diag.json` | Dev-only structural shapes of the evidence behind the false alarms (hosts and addresses reduced to placeholders; shapes under 5 suppressed), per-list flagging ids, text/href mismatch link classes |
| `modern-variants.json` | Dev verdict rates of each proposed rule change on the modern dev lists and the old dev corpora |
| `modern-heldout.json`, `modern-locked-eval.json` | The one-time held-out measurement of the current rules and its claim file |

