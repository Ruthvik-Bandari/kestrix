// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { guide, list, note, p, section, see, steps, table } from "../blocks";
import type { DocPage } from "../model";
import { HOSTED_DOC_PATH } from "../model";
import { LIMITS_NAV, ref, toolOverview } from "./helpers";

/* Follows docs/modules/detect.md. */

const BASE = "tools/detection-repair";

export const detectPages: DocPage[] = [
  toolOverview("detect", BASE, [`${BASE}/how-it-works`, `${BASE}/using-it`, `${BASE}/findings`, `${BASE}/limits`]),
  {
    path: `${BASE}/how-it-works`,
    title: "Detection repair: how it works",
    nav: "How it works",
    summary: "The supported Sigma subset, the replay engine, the diagnosis families, the repair contract and the acceptance policy.",
    sections: [
      ref("detect", "How it works"),
      section(
        "The supported Sigma subset",
        p("Version one accepts one kind of rule: a single-event Windows `process_creation` rule built from named selections. Anything outside the subset is rejected with a reason code before conversion. The parser does not guess at semantics it cannot replay."),
        table(
          ["Element", "Accepted form and limits"],
          [
            ["YAML document", "Exactly one document, at most 100 KiB, nesting depth at most 16."],
            ["`logsource`", "`category: process_creation` and `product: windows`."],
            ["Selections", "1 to 32 named selections, each a map of `field` or `field|modifier` to values, or a list of 1 to 16 such maps."],
            ["Fields", "Sysmon Event ID 1 names: `Image`, `OriginalFileName`, `CommandLine`, `CurrentDirectory`, `User`, `LogonId`, `IntegrityLevel`, `Hashes`, `Product`, `Company`, `Description`, `FileVersion`, `ParentImage`, `ParentCommandLine`, `ParentUser`, `ProcessId`, `ParentProcessId`."],
            ["Modifiers", "None (exact match), `contains`, `startswith`, `endswith`; one of the last three may be followed by `|all`."],
            ["Values", "A string or integer, or a list of 1 to 64 of them. Each value is 1 to 4096 characters."],
            ["Condition", "One string built from selection names, `and`, `or`, `not`, parentheses, and the quantifiers `1 of <pattern>` and `all of <pattern>`."],
          ],
        ),
      ),
      section(
        "The replay engine",
        p("The pinned Elasticsearch 8.19.3 is the only matching oracle. Kestrix has no Python matcher standing in for it, and a successful conversion is never treated as proof that a rule works. Every run first checks that the engine reports version 8.19.3."),
        list(
          "Each dataset is loaded into a fresh single-shard index, deleted when the run ends, including after errors.",
          "Every JSON string is indexed as a `keyword` with a lowercase normalizer, so string matching is case-insensitive.",
          "A missing field never matches a positive predicate, and `NOT` on a missing field matches every event. Mapping drift on a filter field therefore disables the exclusion without any error.",
          "A conversion or engine error becomes an errored replay with `counts: null`. It is never scored as zero matches, which would read as \"missed every attack\".",
        ),
      ),
      section(
        "How a fault is diagnosed",
        p("Diagnosis compares the rule's fields with what the development events contain, then compares replay matches with labels. It can return several hypotheses at once; ambiguous evidence returns every plausible family instead of one guess."),
        table(
          ["Family", "Reason codes", "Raised when"],
          [
            ["`mapping`", "`mapped_field_absent`, `similar_field_observed`", "The mapped index field is absent from every development event, and at least one other observed field could hold it."],
            ["`missing_telemetry`", "`field_not_collected`", "The mapped field is absent everywhere and no alternative field qualifies."],
            ["`missing_telemetry`", "`field_absent_on_malicious_events`", "The field is present on some events but on none of the malicious ones."],
            ["`noise`", "`benign_events_matched`", "The original rule matched benign events."],
            ["`logic`", "`malicious_missed_fields_present`", "The rule missed malicious events while every field it needs is present."],
          ],
        ),
      ),
      section(
        "The repair contract",
        list(
          "A candidate is a structured envelope with 1 to 3 edit operations: `mapping`, `add_exclusion`, `set_predicate` or `set_condition`.",
          "At most 3 AST edits and at most 4 candidates, and a candidate can never drop or add a selection.",
          "A patched rule is re-serialized and parsed again, so it must pass the same validator as an imported rule.",
          "The baseline (B0) proposes candidates from the evidence without any model.",
        ),
      ),
      section(
        "The acceptance workflow",
        steps(
          "Parse the rule. An unsupported construct ends the run as `unsupported`.",
          "Load the mapping and fixtures, and profile the development schema.",
          "Check independence: validation fixtures must not share a file hash or any `event_id` with the development fixtures.",
          "Check the engine. If it is unreachable, the run ends as `engine_unavailable`.",
          "Replay the original rule on development events and diagnose it.",
          "Stop early: any `missing_telemetry` hypothesis ends the run as `insufficient_evidence` with telemetry recommendations; no hypotheses ends it as `unchanged`.",
          "Screen candidates on development events, keep the top four, and end as `abstained` if none survives.",
          "Freeze the top-ranked survivor. Validation results never influence which candidate is chosen.",
          "Validate it on the held-out fixtures against the original rule, or against a healthy reference if you supply one.",
          "Apply the policy. Only a candidate with no policy failure is `repaired`.",
        ),
        note("A passed suite establishes behavior only on the scenarios it tested. Zero benign matches on a small sample does not establish a zero false-positive rate in production.", "caution"),
      ),
    ],
  },
  {
    path: `${BASE}/using-it`,
    title: "Detection repair: using it",
    nav: "Using it",
    summary: "Start the engine, run a bundled case or your own rule from the dashboard or `kestrix detect`, and read the outcome.",
    sections: [
      section(
        "In the dashboard",
        p("The Detection repair page runs the same workflow on a bundled case or on your own rule, mapping and event files, and shows the outcome, the evidence and the diff. It runs on your own computer only. On the hosted service the page is a guide to installing and running it locally."),
        see("What the hosted service runs", HOSTED_DOC_PATH),
      ),
      section("On the command line", guide("detect")),
      section(
        "Commands",
        table(
          ["Command", "Arguments and options", "What it does"],
          [
            ["`detect cases`", "none", "Lists bundled cases with their expected outcome."],
            ["`detect demo CASE_ID`", "`--json`, `--evidence-dir PATH`", "Runs a bundled case end to end."],
            ["`detect run`", "`--rule`, `--mapping`, `--dev` (required); `--validation`, `--healthy-rule`, `--healthy-mapping`, `--json`, `--evidence-dir PATH`", "Runs the workflow on your files."],
            ["`detect engine-status`", "none", "Checks that the engine is reachable and runs the pinned version. Exit 0 when ready, 3 otherwise."],
            ["`detect engine-up`", "`--name` (default `kestrix-es`)", "Starts the pinned image with `docker run`, bound to `127.0.0.1:9200`. Exit 3 if Docker is missing or fails."],
          ],
        ),
        p("Without `--validation`, a repair is reported as provisional. `--evidence-dir` writes the report as a content-addressed JSON file. The engine URL comes from `KESTRIX_ES_URL` and defaults to `http://127.0.0.1:9200`."),
      ),
      section(
        "Your files",
        list(
          "The rule: a Sigma rule inside the supported subset.",
          "The mapping: a YAML file with `schema_version: 1`, a `name` and a `fields` map from each Sigma field to the index field that holds it in your environment.",
          "The events: JSON Lines, one event per line, each with a unique `event_id`, a `label` of `malicious`, `benign` or `unknown`, an optional `scenario_id`, and the event as your pipeline stores it under `data`. Only `data` is indexed; labels never reach the engine.",
        ),
      ),
      section(
        "The bundled cases",
        p("The 11 bundled cases are synthetic demonstrations of each path through the workflow, not a benchmark."),
        table(
          ["Case", "Fault", "Expected outcome"],
          [
            ["`c00-healthy-control`", "None; certutil download rule", "`unchanged`"],
            ["`c01-mapping-drift-commandline`", "`CommandLine` mapped to a field the data does not use", "`repaired` (mapping)"],
            ["`c02-mapping-drift-parentimage`", "Parent path renamed, with no name similarity", "`repaired` (mapping)"],
            ["`c03-noise-updater-temp`", "A legitimate updater runs from Temp", "`repaired` (rule)"],
            ["`c04-noise-installer-schtasks`", "An installer creates scheduled tasks", "`repaired` (rule)"],
            ["`c05-missing-telemetry-commandline`", "Command lines not collected", "`insufficient_evidence`"],
            ["`c06-missing-telemetry-parentimage`", "Parent process not collected", "`insufficient_evidence`"],
            ["`c07-logic-and-or`", "Condition requires two selections that never co-occur", "`repaired` (rule)"],
            ["`c08-modifier-exact-vs-endswith`", "`Image` compared exactly but holds a full path", "`repaired` (rule)"],
            ["`c09-unsupported-regex`", "Uses the `re` modifier", "`unsupported`"],
            ["`c10-logic-missing-not`", "Condition is `selection and filter_sccm`", "`repaired` (rule)"],
          ],
        ),
      ),
    ],
  },
  {
    path: `${BASE}/findings`,
    title: "Detection repair: findings reference",
    nav: "Findings reference",
    summary: "Every outcome and exit code, the policy failures, and the reason codes for a rule that is refused.",
    sections: [
      section(
        "Outcomes and exit codes",
        table(
          ["Outcome", "Meaning", "CLI exit"],
          [
            ["`repaired`", "A candidate passed (or, without validation fixtures, passed screening and is marked provisional). The report holds the diff and artifact.", "0"],
            ["`unchanged`", "No hypothesis was raised. The rule meets expectations on the development fixtures.", "0"],
            ["`abstained`", "No candidate survived screening, the selected candidate failed validation, or a required replay errored.", "10"],
            ["`insufficient_evidence`", "A field the rule needs is not collected for the attacks. Telemetry guidance is included.", "10"],
            ["`unsupported`", "The rule uses semantics outside the supported subset.", "11"],
            ["`engine_unavailable`", "The engine was not reachable at the start of the run. Static coverage is still reported.", "3"],
          ],
        ),
        p("Exit code 2 means the run could not produce an outcome: a rejected rule, mapping or fixture, an unknown case ID or missing file, an engine that is not the pinned version, or an engine error. The error is printed to stderr as `error: <reason>: <detail>`."),
      ),
      section(
        "Policy failures",
        p("A selected candidate is `repaired` only when its validation replay has none of these failures."),
        table(
          ["Code", "Meaning"],
          [
            ["`replay_error`", "The candidate's validation replay errored."],
            ["`no_attack_scenarios_in_suite`", "The validation suite has no malicious events, so it cannot show preservation."],
            ["`mandatory_scenario_missed`", "Some attack scenario in the suite was not detected."],
            ["`preservation_loss`", "A scenario the original rule detected is no longer detected."],
            ["`malicious_events_lost`", "The candidate detects fewer malicious events than the original."],
            ["`benign_matches_above_baseline`", "The candidate matches more benign events than the baseline."],
            ["`no_benign_reduction`", "Only when a `noise` hypothesis was raised: the candidate does not reduce benign matches below the original's count."],
          ],
        ),
      ),
      section(
        "Why a rule is refused",
        table(
          ["Rule content", "Reason code"],
          [
            ["Top-level `correlation`, `filter` or `action` key; `timeframe` under `detection`; more than one YAML document", "`unsupported_rule_type`"],
            ["Any other `logsource`", "`unsupported_logsource`"],
            ["Keyword lists, empty selections, list items that are not maps, or more than 16 alternative maps", "`unsupported_selection_form`"],
            ["Modifiers other than those supported (for example `re`, `base64`, `cidr`, `windash`)", "`unsupported_modifier`"],
            ["`null`, boolean, float or nested values; empty or over-long values; too many values", "`unsupported_value`"],
            ["An unescaped `*` or `?` in a value", "`unsupported_wildcard`"],
            ["A condition that is not one string, uses an aggregation pipe, a quantifier count other than `1`, or is malformed or too deep", "`unsupported_condition`"],
            ["Field outside the supported list", "`unknown_field`"],
            ["Condition names a selection that does not exist", "`undefined_selection`"],
            ["Missing `title`, `detection` not a map, empty condition, invalid selection name", "`invalid_rule`"],
            ["Invalid YAML or a duplicate key", "`malformed_yaml`"],
            ["YAML anchors or aliases, or explicit YAML tags", "`yaml_alias_not_allowed`, `yaml_tag_not_allowed`"],
            ["pySigma conversion fails or returns more than one query", "`conversion_failed`"],
          ],
        ),
        p("Codes that start with `unsupported_`, plus `unknown_field`, produce the `unsupported` outcome (exit 11). The others are input errors: the CLI exits 2 and the API returns HTTP 400."),
      ),
    ],
  },
  {
    path: `${BASE}/limits`,
    title: "Detection repair: limits and measured accuracy",
    nav: LIMITS_NAV,
    summary: "What a repair does and does not prove. No repair success rate has been measured.",
    sections: [
      ref("detect", "Limits"),
      section(
        "Measured accuracy",
        p("Not measured. Only the baseline (B0) ships. The 11 bundled cases are synthetic and are unit-level demonstrations of each path through the workflow, so they say nothing about real telemetry. The engine tests check that each case reaches its expected outcome; that is a correctness check, not an accuracy figure."),
        note("The research plan's later stages (retrieval, model-based proposals, fine-tuning) are not implemented in this package, and the plan's targets are goals, not measured results.", "caution"),
      ),
    ],
  },
];
