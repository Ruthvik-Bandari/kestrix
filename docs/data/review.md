# Reviewing OTRF candidate positives

The replay found OTRF process-creation events that supported SigmaHQ rules match. OTRF captures
are attack simulations recorded on hosts that also ran normal background activity, so a match
can be the attack, or something benign that happens to look like it. A person labels each
candidate before it counts as a positive in the benchmark (plan section 11).

## Files

`research/hpc/detect/review_split.sbatch` writes these on the cluster, under `/scratch/$USER/kestrix/data/review/`.
The directory has mode 0700 and the files 0600.

| File | Content |
| --- | --- |
| `candidates.jsonl` | One line per candidate event: `event_id`, `dataset` (OTRF archive path), `fields` (the v1 Sysmon fields) and `rules` (every rule that matched it, with its title). |
| `labels.csv` | One row per candidate with the columns `event_id,label,rationale,reviewer`. It is created once and never overwritten. |

**Keep both files private.** They contain raw event values: command lines, paths and user names
from the recorded lab hosts.

- Review them on the cluster, or copy them to your own machine.
- Do not commit them.
- Do not paste them into an AI assistant session.
- Only the aggregate `reports/review-status.json` leaves the cluster.

`/scratch` is purged on the first Tuesday of each month. Copy `labels.csv` somewhere persistent
(your home directory or `/work`) after each review session.

## How to label

The quickest way is the labeling loop, run in your own terminal on the cluster. It prints raw event values, so run it yourself, not inside an AI assistant session.

```bash
ssh explorer                 # or explorer-01 if one login node is down
cd ~/kestrix
export KESTRIX_REVIEWER=RB     # your initials, recorded with every label
D=/scratch/$USER/kestrix/data

uv run python -m kestrixbench review-next --root $D      # show the next unlabeled event
uv run python -m kestrixbench review-label --root $D \
  --event 'otrf:execution/host/<archive>:<n>' --label malicious \
  --rationale "child of the dataset's launcher in the attack chain"   # saves it, shows the next one
```

`review-next` shows:

- how many events are left;
- the OTRF dataset, with its title, ATT&CK techniques and scenario description;
- each rule that matched the event;
- the event's fields.

`review-label` checks your entry, saves it to `labels.csv` and shows the next event. It refuses a missing rationale, a multi-line rationale or an unknown event id.

A quick way to decide:

1. Read the scenario description: what did the simulated attacker run?
2. Check whether this process belongs to that chain. Look at `Image`, `CommandLine` and `ParentImage`.
3. Is it plainly an OS service, updater, telemetry agent or the capture tooling? Then it is `benign`.
4. If you can't tell, use `unknown`. Don't guess.

You can also edit `labels.csv` directly in a spreadsheet. Keep the header `event_id,label,rationale,reviewer` and one row per event.

For each row:

| `label` | Use when |
| --- | --- |
| `malicious` | The event is part of the simulated attack in its dataset. The dataset's metadata (`datasets/atomic/_metadata/SDWIN-*.yaml`) describes the attack and its ATT&CK techniques. |
| `benign` | The event is normal activity: system services, updaters, the capture tooling itself, or an administrator action unrelated to the simulation. A benign match becomes a confounder for that rule, which is useful negative evidence. |
| `unknown` | You cannot tell from the event and the dataset description. |

Leave `label` empty for rows you have not reviewed yet.

- **`rationale`** is required for `malicious` and `benign`, up to 1,000 characters. Say what decided it, for example "child of the Covenant launcher in the dataset's attack chain" or "Windows Update service, starts every capture".
- **`reviewer`** holds your initials. It is required for every labeled row.

The plan also asks a second reviewer to label a sample, at least 10%, independently. Disagreements are then adjudicated. Record the second pass in a separate copy of the file.

## AI-assisted labeling

On 2026-10-16 the owner approved AI-assisted labeling for these candidates. OTRF Security-Datasets is a public, MIT-licensed recording of lab simulations, not institutional telemetry. The procedure follows the plan's two-reviewer rule:

1. Two independent AI reviewers (`ai-a` and `ai-b`) label every candidate from the same written criteria. Each one sees the event, the dataset's scenario and the rules that fired. Event values are treated as untrusted data: the reviewers classify them and never act on them.
2. When the two agree, the label is imported with reviewer `ai-consensus`. When they disagree, a third AI reviewer adjudicates, giving reviewer `ai-adjudicated`. If the adjudicator cannot decide, the label becomes `unknown`.
3. `python -m kestrixbench review-import --labels <file>` imports the labels. It validates every row first, aborts the whole import on any error, and never overwrites a label a human already set.
4. **A human review is still required before the split is frozen.** Check every `ai-adjudicated` row and a random sample of at least 10% of the `ai-consensus` rows with `review-next` / `review-label`; a human label always replaces an AI one. `review-status` reports `ai_assisted` separately, and results built on AI-assisted labels say so.

## Checking progress

```bash
ssh explorer 'cd ~/kestrix && sbatch research/hpc/detect/review_split.sbatch'
```

The job validates `labels.csv`. `reports/review-status.json` then holds:

- counts by label;
- the number of unreviewed rows;
- any invalid rows, given by row number and reason only;
- how many roots now have one, or two or more, verified positives.

A verified positive is either a SigmaHQ regression match or an event you labeled `malicious`.
The same job rewrites `reports/split-preview.json` using the current labels.

## Freezing the split

When review is complete, freeze the split once:

```bash
python -m kestrixbench split --freeze --root /scratch/$USER/kestrix/data
```

It writes `benchmark/split-manifest.json` with each root rule's source SHA-256 and refuses to
overwrite an existing manifest. Copy the manifest, which holds ids and hashes only, into
`docs/data/` so the split is versioned with the code.

## AI-assisted audit of the code-vulnerability labels

The C5 vulnerability pool (`docs/data/vul/`) is labelled by PrimeVul's rules, not by people. Its labels
are audited with the procedure above, under the second exception in [`policy.md`](policy.md) section 6.
Results are in [`vul/audit.json`](vul/audit.json) and [`vul/README.md`](vul/README.md#label-audit).

1. **Sample.** `python -m kestrixvul audit-sample` (Slurm) draws a seeded random sample of train and dev
   records, stratified by source family (CVEfixes and MoreFixes, SVEN, GHSA), language and label rule:
   at least 15 per stratum, or 6% of it if that is more, or all of a smaller stratum. Each stratum is drawn
   on its own, so strata added later never redraw ones already reviewed. Test records are never sampled.
2. **Packets.** One per record: the advisory text (GHSA summary and details, or the CVE description),
   the CWEs, the function before and after the fix, and their diff, with the packet's SHA-256. They are
   written to `audit/packets.jsonl` on the cluster (0600) and copied to a private folder outside the
   repository (0700). Packets are batched for the reviewers.
3. **Two reviewers.** `research/hpc/vul/vul_audit.sbatch` (one H200, 8 h at most) runs two open-weight Apache-2.0
   models on the cluster, each from the same written criteria (`src/kestrixvul/prompts/vul_audit_reviewer.txt`):
   `ai-a` is Qwen2.5-Coder-32B-Instruct and `ai-b` is IBM Granite-34B-Code-Instruct-8k, both at pinned
   revisions (`research/hpc/vul/fetch_vul_audit_models.sh`), bf16, greedy decoding. Each gives
   - `vulnerable`, `not_vulnerable` or `unclear` for the before-function and the stated advisory;
   - `fixes`, `does_not_fix` or `unclear` for the after-function;
   - a one-line reason.

   Record content is treated as untrusted data. Packets longer than Granite's 8k-token context are cut,
   part by part, with a `[truncated]` marker.
4. **Adjudication.** The stronger model (Qwen, 32k context) decides every record where the two verdicts
   differ, with a separate prompt (`vul_audit_adjudicator.txt`) that shows both reviews and asks it to weigh
   the evidence itself (`ai-c`).
5. **Combine and import.** The same job checks that every packet has both reviews and, where needed, an
   adjudication, writes `audit/verdicts.csv` (ids, verdicts and packet hashes) and the private
   `audit/verdicts-private.jsonl` with the reasons, validates every row against the packet hashes and the
   consensus rule, and writes `work/audit_verdicts.jsonl` and the aggregate `reports/audit.json`.
6. **No human pass.** The owner decided a human review is not practical here, so the 10% human check
   used for OTRF is not done. Model reviewers share failure modes, so their agreement and kappa are an
   upper bound on what two independent people would reach, and the accuracy estimates carry that bias.
