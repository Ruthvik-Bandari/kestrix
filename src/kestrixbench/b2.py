# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""B2: an unmodified open model that proposes structured candidates (plan section 12).

The model receives the same evidence as B0 and B1:

- the rule;
- the field mapping;
- field coverage;
- the diagnosis hypotheses, with the alternative index fields that were observed;
- the original replay counts.

Raw event values are deliberately absent, so log text cannot steer the model. The model must
answer with JSON patches under the candidate contract. Each proposal is validated by the same
Pydantic schema; anything malformed is dropped, and the drop is counted in the candidate's
reason codes. The model has no tools, and every surviving candidate still goes through screening,
freeze and validation on the pinned engine.

``Model`` is any ``prompt -> text`` callable. ``kestrixbench.hf`` provides the local GPU
implementation, and the tests use a fake one.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from kestrix.detect.candidate import MAX_AST_EDITS, MAX_CANDIDATES, Candidate
from kestrix.detect.diagnose import Hypothesis, coverage
from kestrix.detect.fixtures import Dataset, profile
from kestrix.detect.mapping import FieldMapping
from kestrix.detect.repair import Generator
from kestrix.detect.rule import Rule

Model = Callable[[str], str]

MODEL_REPO = "Qwen/Qwen2.5-Coder-7B-Instruct"
MODEL_REVISION = "c03e6d358207e414f1eca0bb1891e29f1db0e242"
MODEL_LICENSE = "Apache-2.0"
MAX_PROMPT_CHARS = 12_000

INSTRUCTIONS = f"""You repair Sigma detection rules. You are given a rule, its field mapping to the index,
field coverage in the development events, a diagnosis and replay counts. Propose at most
{MAX_CANDIDATES} candidate repairs, each with at most {MAX_AST_EDITS} patch operations, as JSON only:

{{"candidates": [{{"patch_kind": "mapping" | "rule", "patch": [<operation>, ...]}}]}}

Operations:
- {{"kind": "mapping", "sigma_field": F, "from_field": <current index field>, "to_field": <observed index field>}}
- {{"kind": "set_condition", "condition": "<condition over the existing selection names>"}}
- {{"kind": "set_predicate", "selection": S, "field": F, "predicate": {{"field": F, "modifier": "equals|contains|startswith|endswith", "values": [..], "match_all": false}}}}
- {{"kind": "add_exclusion", "predicates": [{{"field": F, "modifier": "equals", "values": [..]}}]}}

Rules: a mapping candidate holds only mapping operations; a rule candidate holds none. Keep every
existing selection in the condition. If no rule change can help (for example, a field is not
collected), return {{"candidates": []}}. Output the JSON object and nothing else."""


def build_prompt(
    rule: Rule, mapping: FieldMapping, dataset: Dataset, hyps: list[Hypothesis], matched: frozenset[str]
) -> str:
    schema = profile(dataset.events)
    labels = {e.event_id: e.label for e in dataset.events}
    counts = {
        "malicious_events": sum(1 for v in labels.values() if v == "malicious"),
        "malicious_matched": sum(1 for i in matched if labels.get(i) == "malicious"),
        "benign_events": sum(1 for v in labels.values() if v == "benign"),
        "benign_matched": sum(1 for i in matched if labels.get(i) == "benign"),
    }
    evidence = {
        "mapping": dict(sorted(mapping.fields.items())),
        "coverage": [c.as_dict() for c in coverage(rule, mapping, schema)],
        "observed_index_fields": sorted(schema.fields),
        "diagnosis": [h.as_dict() for h in hyps],
        "replay": counts,
    }
    prompt = f"{INSTRUCTIONS}\n\nRULE (YAML):\n{rule.to_yaml()}\nEVIDENCE (JSON):\n{json.dumps(evidence, indent=1)}\n"
    return prompt[:MAX_PROMPT_CHARS]


_JSON = re.compile(r"\{.*\}", re.S)


def parse(text: str, rule: Rule, prompt_sha256: str) -> tuple[list[Candidate], int]:
    """Valid candidates and the number of proposals dropped as malformed or out of contract."""
    match = _JSON.search(text)
    if not match:
        return [], 1
    try:
        doc: Any = json.loads(match.group(0))
    except ValueError:
        return [], 1
    proposals = doc.get("candidates") if isinstance(doc, dict) else None
    if not isinstance(proposals, list):
        return [], 1
    out: list[Candidate] = []
    dropped = 0
    for n, item in enumerate(proposals[:MAX_CANDIDATES], 1):
        if not isinstance(item, dict):
            dropped += 1
            continue
        try:
            out.append(
                Candidate.model_validate(
                    {
                        "proposal_id": f"b2-{n}",
                        "original_sha256": rule.sha256,
                        "patch_kind": item.get("patch_kind"),
                        "patch": item.get("patch"),
                        "reason_codes": ["b2_open_model"],
                        "model_revision": f"{MODEL_REPO}@{MODEL_REVISION}",
                        "prompt_sha256": prompt_sha256,
                    }
                )
            )
        except ValidationError:
            dropped += 1
    return out, dropped + max(0, len(proposals) - MAX_CANDIDATES)


def generator(model: Model, stats: dict[str, int] | None = None) -> Generator:
    """``stats`` (optional) accumulates calls, valid candidates and dropped proposals."""

    def propose(
        rule: Rule, mapping: FieldMapping, dataset: Dataset, hyps: list[Hypothesis], matched: frozenset[str]
    ) -> list[Candidate]:
        prompt = build_prompt(rule, mapping, dataset, hyps, matched)
        candidates, dropped = parse(model(prompt), rule, hashlib.sha256(prompt.encode()).hexdigest())
        if stats is not None:
            stats["calls"] = stats.get("calls", 0) + 1
            stats["valid"] = stats.get("valid", 0) + len(candidates)
            stats["dropped"] = stats.get("dropped", 0) + dropped
        return candidates

    return propose
