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
| [Qwen/Qwen2.5-Coder-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct) | `c03e6d358207e414f1eca0bb1891e29f1db0e242` | Apache-2.0 | B2, the unmodified baseline, and the base for M1 LoRA. Only weights, config and tokenizer are fetched (`research/hpc/detect/fetch_model.sh`); it is loaded with `trust_remote_code=False`. |

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

## Code-vulnerability data (ADR 0005, slice C5)

The pins live in `src/kestrixvul/sources.py`; the plan is `docs/research/code-vuln-ml-plan.md`.
`python -m kestrixvul acquire` verifies each archive against the Zenodo record's size and MD5 and
against the SHA-256 pinned after the first verified download, and each git source against its
pinned commit. Raw files stay private on the cluster (`/scratch/$USER/kestrix/vul/raw`, 0700/0600).
Only aggregate reports are committed, in [`vul/`](vul/README.md).

| Source | Pinned revision | License | What we use | Allowed use and obligations |
| --- | --- | --- | --- | --- |
| [CVEfixes](https://github.com/secureIT-project/CVEfixes) | v1.0.8, [Zenodo 13118970](https://zenodo.org/records/13118970) (doi 10.5281/zenodo.13118970), `CVEfixes_v1.0.8.zip` | Data CC BY 4.0; collection code MIT | Fixes, CVE dates and descriptions, CWEs, and the Python, JavaScript and TypeScript file and method changes from the SQLite dump | Use and adapt with attribution (Bhandari, Naseer and Moonen, PROMISE '21). The mined code keeps each project's own license: see the per-repository license check. |
| [MoreFixes](https://github.com/JafarAkhondali/Morefixes) | v4, dump 2026-06-20, [Zenodo 20776007](https://zenodo.org/records/20776007) (doi 10.5281/zenodo.20776007), `dump-2026-06-20.sql.gz` and `patch-files2026-06-20.zip` | CC BY 4.0 | The same tables from the PostgreSQL dump, fix commits with `score >= 65` only (the authors' recommended threshold). The `users` table and CPE mappings are never read. The patch archive is acquired and verified but not used yet. | Use and adapt with attribution (Akhoundali et al., PROMISE '24). The record warns that mined repositories carry their own licenses. |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | commit `f192b634af70bbe4cbe055f5a0e45b62da28b910` (main, 2026-10-19) | CC BY 4.0 | `advisories/github-reviewed/**`, reviewed PyPI and npm advisories only: ids, CVE aliases, publication dates, CWEs and fix-commit references | Use, share and adapt with attribution to GitHub and the database contributors. |
| [SVEN](https://github.com/eth-sri/sven) | commit `e8449a0d54a5ae0bbdc6bb236330b8c7ec71df57` (master, 2024-07-14) | MIT | `data_train_val/`, the Python vulnerable/patched pairs, as a curated development set | Use with the MIT notice (He and Vechev, CCS '23). The functions keep their projects' licenses. |

Two tiers apply (plan, "Licensing principles"): the research model may use all of the above; weights
shipped with Kestrix may train only on functions whose repository GitHub reports as MIT, BSD-2/3-Clause,
Apache-2.0, ISC, 0BSD, Unlicense, Zlib or PSF-2.0. MPL, LGPL and EPL are weak copyleft and kept apart;
GPL and AGPL are copyleft; `NOASSERTION`, unlisted licenses, no license and unknown repositories never
count as permissive. The per-repository table is [`vul/licenses.csv`](vul/licenses.csv).

Not used, from the plan: DiverseVul, ReposVul, CleanVul and VUDENC (no license), MegaVul (GPL-3.0),
PySecDB (non-commercial), and labels written by commercial models (CleanVul, R2Vul).
