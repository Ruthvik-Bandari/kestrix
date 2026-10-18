# Session handoff

Maintained per session: overwrite these sections at the end of every Claude Code session (see `docs/claude/workflow.md`). Detailed history lives in git.

## Current git SHA

The tip of `main`, pushed to `origin/main` after every change (2026-10-15). The working tree is clean after the commit that adds this file.

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
| `ssh explorer-xfer 'cd ~/kestrix && bash -l hpc/fetch_engine.sh'` | Elasticsearch 8.19.3 tarball, SHA-512 verified |
| `sbatch hpc/qc.sbatch` (job 11105891) | COMPLETED, 0 problems |
| `sbatch hpc/replay.sbatch` (job 11105959) | COMPLETED, 997 rules, 0 engine errors |

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

State on 2026-10-17: the full pipeline has run on corrected code (review fixes 48b5b06 and 2869a39).

- Held-out development results:
  - B0 = B1 = 0.591;
  - M1 (3 seeds) = 0.568;
  - B2 = 0.523;
  - B1 and M1 never weaken a rule, while B0 and B2 weakened 3 each.
- Recommended baseline: B1. M1 does not ship.
- Tables: `docs/data/qc/README.md`, under "Corrected results".

Next:

1. **Owner:** human check of the 27 events in `/scratch/$USER/kestrix/data/review/human-check.txt`, using `review-next` and `review-label`. Run it on the login node; `review-status` must run inside a job (the login node kills it).
2. Freeze the split: `python -m kestrixbench split --freeze` in a job. Then rerun `variants.sbatch` (it writes the natural cases too), `evaluate` for b0, b1 and b2, `sft`, and M1 seeds 1 to 3 with `m1_eval`.
3. Locked test evaluation, once: `evaluate.sbatch <sys> --locked`, then `compare --locked`. Then finalize the dataset and model cards.
4. Optional: enlarge the split beyond 12/12/36 using the reserve (122 roots).
5. Owner: `/work` storage, IRB question, PyPI publishing decision.
