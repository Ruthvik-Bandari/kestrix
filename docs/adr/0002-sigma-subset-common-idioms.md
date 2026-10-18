# ADR 0002: Widen the Sigma subset to the four most common single-event idioms

- Status: accepted
- Date: 2026-10-14
- Decision owner: Ruthvik Bandari

## Context

The first QC run over SigmaHQ release r2026-07-01 (`docs/data/qc/README.md`) found that only 192 of the 1,182
Windows process_creation rules (16%) parse under the version one subset. Only 12 of those 192 have SigmaHQ
regression events. The plan's benchmark needs about 60 clean roots, so the subset was too narrow for the
benchmark. It also made `kestrix detect` unusable on most real rules.

Four constructs account for most of the exclusions. Each rule is counted under its first unsupported construct:

| Rules | Construct | Meaning |
| --- | --- | --- |
| 636 | A selection written as a list of maps | OR of the maps; each map is an AND of its fields |
| 161 | `field\|contains\|all` (also `startswith\|all`, `endswith\|all`) | Every value must match, not just one |
| 86 | `1 of <pattern>` | OR of the selections whose names match the pattern (`*` wildcard, or `them`) |
| 47 | `all of <pattern>` | AND of the same set |

Each of these is single-event Boolean logic over the same predicates. None of them needs aggregation, correlation,
regex or a new log source. Plan section 5 allows "simple Boolean selection combinations only when the pinned
backend and fixtures verify their behavior".

## Decision

1. **Parser** (`detect/rule.py`):
   - A selection is now a `Selection` made of one or more branches. Each branch is a map of predicates, and the
     branches are ORed.
   - A `Predicate` gains `match_all` for the `|all` suffix. The suffix is accepted only after `contains`,
     `startswith` or `endswith`.
   - Keyword (string-list) selections are still refused.
2. **Conditions:**
   - `1 of X` and `all of X` are expanded when the rule is parsed. They become an OR or an AND of the matching
     selection names, in definition order.
   - `them` means the same as `*`. As in pySigma, a selection whose name starts with `_` matches only a pattern that
     also starts with `_`.
   - A pattern that matches nothing is `undefined_selection`. Counts other than `1` are refused.
   - The internal tree stays `Ref | Not | And | Or`. The candidate contract, the edit counter and the condition
     mutations therefore keep working unchanged. Exported rules show the expanded condition, which has the same
     meaning. Every nested group is rendered with parentheses, so swapping `1 of` for `all of` counts as one edit.
3. **Candidates:**
   - `PredicateSpec` gains `match_all`, with default `false`, so existing candidates remain valid.
   - `set_predicate` still has to hit exactly one predicate on its field, now counted across all branches of the
     selection. Changing `match_all` counts as one AST edit.
4. **Verification:** each construct has a test on the pinned Elasticsearch 8.19.3. A rule using it is converted with
   pySigma and replayed against events labeled to match and not match. Conversion success alone is never accepted
   as proof.
5. **API:** in `POST /api/detect/parse`, `selections` becomes `{name: [[predicate, ...], ...]}`, a list of branches,
   and each predicate carries `match_all`. This is a breaking change while the version is below 1.0, and it is
   recorded in the changelog.

## Consequences

- Real SigmaHQ rules that use these idioms can be diagnosed and repaired, and they qualify as benchmark roots.
  The QC report measures the new support rate.
- Repairs still use at most 3 AST edits and never drop a selection. An exclusion is still added as a new
  single-branch selection.
- `windash`, `re`, `base64offset`, `cased`, wildcards, null matching and keyword selections stay out of scope. They
  will be reconsidered only with evidence from the benchmark.
