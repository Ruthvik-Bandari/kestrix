# Benchmark data sources and license record

This file is the human-readable license record that plan section 11 requires. The pins themselves
live in `src/kestrixbench/sources.py`. Changing a pin creates a new dataset version: update this
file, then re-run `python -m kestrixbench acquire` and `qc`.

| Source | Pinned revision | License | What we use | Allowed use and obligations |
| --- | --- | --- | --- | --- |
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | release `r2026-07-01`, commit `552f3fee420ef232a8e5790c4fae591847e32347` | Detection Rule License 1.1 (rules). The specification and logo are public domain. | `rules/windows/process_creation`, plus the positive Sysmon EID 1 events in `regression_data/rules/windows/process_creation` | Use, modify and redistribute, including commercially. Keep author attribution in derived rules and in any output that shows a rule. Each rule's `author` field is the attribution. |
| [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) | commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` (2023-09-20) | MIT | `datasets/atomic/windows` recorded telemetry and the `datasets/atomic/_metadata` ATT&CK mappings | Use, copy, modify and redistribute with the MIT notice. |
| [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) | commit `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` (2026-09-05) | MIT | `atomics/` test definitions, read as data | Use with the MIT notice. Running a test is a separate act: it needs an authorized, isolated lab (see `policy.md`). |

## Models

| Model | Pinned revision | License | Use |
| --- | --- | --- | --- |
| [Qwen/Qwen2.5-Coder-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct) | `c03e6d358207e414f1eca0bb1891e29f1db0e242` | Apache-2.0 | B2, the unmodified baseline, and the base for M1 LoRA. Only weights, config and tokenizer are fetched (`hpc/fetch_model.sh`); it is loaded with `trust_remote_code=False`. |

## Recorded per acquisition

`<root>/manifests/<source>.json` records each acquisition:

- source URL, commit and revision label;
- license SPDX identifier, license file SHA-256, allowed use and attribution;
- capture method and collection time (UTC);
- SHA-256 of every materialized file, plus a content hash over the whole list.

QC re-verifies every file hash against its manifest before it reads anything. A changed file fails the run.

## Provenance labels

Each benchmark case carries exactly one fault provenance label, and results are reported separately by label:

- `natural`: a maintenance failure observed in a rule's real history;
- `lab_introduced`: a fault reproduced in a lab capture;
- `synthetic`: a programmatic corruption of a healthy root.

Event labels are `malicious`, `benign` or `unknown`. Each also has a scenario ID, a rule-relevance flag and the reviewer's rationale.

## Not used

- **NSL-KDD and UNSW-NB15:** these are flow tables with no process-event context (plan section 11).
- **Data from systems we are not authorized to collect from:** never used.
