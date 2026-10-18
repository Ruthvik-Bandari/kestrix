"""End-to-end diagnose → repair → validate workflow shared by the CLI and API.

Outcomes (plan section 8): ``repaired``, ``unchanged``, ``abstained``, ``unsupported``,
``insufficient_evidence`` and ``engine_unavailable``. Development replay only screens
candidates; acceptance is decided on the separate validation fixtures. Without them a
repair is reported as provisional.
"""

from __future__ import annotations

import difflib
import time
from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import version
from pathlib import Path
from typing import Any

import yaml

from ..core.errors import Reason, Rejected
from ..core.evidence import now, run_manifest
from .candidate import MAX_CANDIDATES, Candidate, apply
from .diagnose import Family, Hypothesis, coverage, guidance, hypotheses
from .engine import PINNED_IMAGE, Elasticsearch
from .fixtures import Dataset, load_dataset, profile
from .mapping import FieldMapping, parse_mapping
from .repair import Generator, generate
from .replay import Replayer, ReplayResult
from .rule import Rule, parse_rule

SCHEMA_VERSION = 1
UNSUPPORTED_REASONS = frozenset(
    {
        Reason.UNSUPPORTED_LOGSOURCE,
        Reason.UNSUPPORTED_RULE_TYPE,
        Reason.UNSUPPORTED_SELECTION_FORM,
        Reason.UNSUPPORTED_MODIFIER,
        Reason.UNSUPPORTED_VALUE,
        Reason.UNSUPPORTED_WILDCARD,
        Reason.UNSUPPORTED_CONDITION,
        Reason.UNKNOWN_FIELD,
    }
)


class Outcome(StrEnum):
    REPAIRED = "repaired"
    UNCHANGED = "unchanged"
    ABSTAINED = "abstained"
    UNSUPPORTED = "unsupported"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    ENGINE_UNAVAILABLE = "engine_unavailable"


@dataclass(frozen=True)
class Inputs:
    rule_text: str
    mapping_text: str
    dev_path: Path
    validation_path: Path | None = None
    healthy_rule_text: str | None = None
    healthy_mapping_text: str | None = None


def policy_failures(
    cand: ReplayResult, original: ReplayResult, benign_baseline: int, require_noise_reduction: bool
) -> list[str]:
    """Acceptance policy (plan section 10). An empty list means the candidate passes.
    ``original`` must be an error-free replay of the unmodified rule on the same suite."""
    if cand.error:
        return ["replay_error"]
    failures = []
    if not cand.scenarios_expected:
        failures.append("no_attack_scenarios_in_suite")
    if cand.scenarios_expected - cand.scenarios_detected:
        failures.append("mandatory_scenario_missed")
    if original.scenarios_detected - cand.scenarios_detected:
        failures.append("preservation_loss")
    if cand.tp < original.tp:
        failures.append("malicious_events_lost")
    if cand.fp > benign_baseline:
        failures.append("benign_matches_above_baseline")
    if require_noise_reduction and cand.fp >= original.fp:
        failures.append("no_benign_reduction")
    return failures


def _diff(before: str, after: str, name: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), f"a/{name}", f"b/{name}"))


def _mapping_yaml(m: FieldMapping) -> str:
    return yaml.safe_dump(m.to_yaml_dict(), sort_keys=False)


@dataclass
class _Screened:
    """A candidate that survived development screening, with its report entry."""

    entry: dict[str, Any]
    candidate: Candidate
    rule: Rule
    mapping: FieldMapping
    result: ReplayResult

    def rank(self) -> tuple[int, int, int, int]:
        """Development-only rank: most scenarios, most attack events, fewest benign matches, smallest patch."""
        r = self.result
        return (-len(r.scenarios_detected), -r.tp, r.fp, len(self.candidate.patch))


class _Run:
    """One workflow execution; accumulates the report so every exit returns the same shape."""

    def __init__(self, inputs: Inputs, engine: Elasticsearch, generator: Generator) -> None:
        self.generator = generator
        self.started = now()
        self.t0 = time.perf_counter()
        self.inputs = inputs
        self.engine = engine
        self.report: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "outcome": None, "reason": None}

    def finish(self, outcome: Outcome, reason: str | None = None, **fields: object) -> dict[str, Any]:
        self.report.update(fields, outcome=outcome.value, reason=reason)
        self.report["manifest"] = run_manifest(
            self.started,
            elapsed_ms=round((time.perf_counter() - self.t0) * 1000),
            engine_image=PINNED_IMAGE,
            pysigma=version("pysigma"),
            pysigma_backend_elasticsearch=version("pysigma-backend-elasticsearch"),
        )
        return self.report

    def execute(self) -> dict[str, Any]:
        inputs = self.inputs
        try:
            rule = parse_rule(inputs.rule_text)
        except Rejected as exc:
            if exc.reason in UNSUPPORTED_REASONS:
                return self.finish(Outcome.UNSUPPORTED, f"{exc.reason}: {exc.detail}")
            raise
        mapping = parse_mapping(inputs.mapping_text)
        dev = load_dataset(inputs.dev_path)
        val = load_dataset(inputs.validation_path) if inputs.validation_path else None
        if val is not None and (
            val.sha256 == dev.sha256 or {e.event_id for e in val.events} & {e.event_id for e in dev.events}
        ):
            raise Rejected(
                Reason.INVALID_FIXTURE, "validation fixtures must not share events with development fixtures"
            )
        schema = profile(dev.events)
        self.report.update(
            rule={"title": rule.title, "id": rule.rule_id, "sha256": rule.sha256},
            mapping={"name": mapping.name, "sha256": mapping.sha256},
            datasets={"development": dev.sha256, "validation": val.sha256 if val else None},
            schema_profile=schema.as_dict(),
            coverage=[c.as_dict() for c in coverage(rule, mapping, schema)],
        )
        try:
            self.engine.require_pinned()
        except Rejected as exc:
            if exc.reason is not Reason.ENGINE_UNAVAILABLE:
                raise
            return self.finish(Outcome.ENGINE_UNAVAILABLE, exc.detail)

        with self.engine.replay_index(dev.events) as dev_index:
            replayer = Replayer(self.engine, dev_index, dev)
            original = replayer.run(rule, mapping)
            if inputs.healthy_rule_text or inputs.healthy_mapping_text:
                # Recorded for reviewers: what the known-good rule does on the same development events.
                healthy_dev = replayer.run(
                    parse_rule(inputs.healthy_rule_text) if inputs.healthy_rule_text else rule,
                    parse_mapping(inputs.healthy_mapping_text) if inputs.healthy_mapping_text else mapping,
                )
                self.report["healthy_reference"] = {"development": healthy_dev.as_dict()}
            hyps = hypotheses(rule, mapping, schema, dev, original)
            self.report.update(original={"development": original.as_dict()}, hypotheses=[h.as_dict() for h in hyps])
            if original.error:
                return self.finish(Outcome.ABSTAINED, f"original replay failed: {original.error}")
            families = {h.family for h in hyps}
            if Family.MISSING_TELEMETRY in families:
                missing = [f for h in hyps if h.family is Family.MISSING_TELEMETRY for f in h.fields]
                return self.finish(
                    Outcome.INSUFFICIENT_EVIDENCE,
                    "required fields are not collected for the attacks; no rule change can restore them",
                    telemetry_recommendations=[{"field": f, "guidance": guidance(f)} for f in missing],
                )
            if not hyps:
                return self.finish(Outcome.UNCHANGED, "original rule meets expectations on the development fixtures")
            screened, rejected = _screen(
                rule, mapping, dev, hyps, original=original, replayer=replayer, generator=self.generator
            )
            self.report["candidates"] = [s.entry for s in screened]
            self.report["rejected_candidates"] = rejected

        if not screened:
            return self.finish(Outcome.ABSTAINED, "no candidate improved development replay without losing scenarios")
        if val is None:
            return self._select(rule, mapping, screened[0], provisional=True)
        # The plan freezes the selected artifact before the independent suite runs, so validation
        # judges exactly one candidate and can never influence which one is chosen.
        return self._validate(rule, mapping, val, screened[0], noise=Family.NOISE in families)

    def _validate(
        self, rule: Rule, mapping: FieldMapping, val: Dataset, selected: _Screened, *, noise: bool
    ) -> dict[str, Any]:
        with self.engine.replay_index(val.events) as val_index:
            replayer = Replayer(self.engine, val_index, val)
            original = replayer.run(rule, mapping)
            self.report["original"]["validation"] = original.as_dict()
            if original.error:
                return self.finish(Outcome.ABSTAINED, f"original validation replay failed: {original.error}")
            baseline = original.fp
            if self.inputs.healthy_rule_text or self.inputs.healthy_mapping_text:
                healthy_rule = parse_rule(self.inputs.healthy_rule_text) if self.inputs.healthy_rule_text else rule
                healthy_map = (
                    parse_mapping(self.inputs.healthy_mapping_text) if self.inputs.healthy_mapping_text else mapping
                )
                healthy = replayer.run(healthy_rule, healthy_map)
                self.report.setdefault("healthy_reference", {})["validation"] = healthy.as_dict()
                if healthy.error:
                    return self.finish(Outcome.ABSTAINED, f"healthy reference replay failed: {healthy.error}")
                baseline = healthy.fp
            result = replayer.run(selected.rule, selected.mapping)
        failures = policy_failures(result, original, baseline, noise)
        selected.entry.update(validation=result.as_dict(), policy_failures=failures, passed=not failures)
        if failures:
            return self.finish(Outcome.ABSTAINED, f"selected candidate failed validation: {', '.join(failures)}")
        return self._select(rule, mapping, selected, provisional=False)

    def _select(self, rule: Rule, mapping: FieldMapping, best: _Screened, *, provisional: bool) -> dict[str, Any]:
        if best.candidate.patch_kind == "mapping":
            before, after, name, digest = (
                _mapping_yaml(mapping),
                _mapping_yaml(best.mapping),
                "mapping.yml",
                best.mapping.sha256,
            )
        else:
            before, after, name, digest = rule.to_yaml(), best.rule.to_yaml(), "rule.yml", best.rule.sha256
        return self.finish(
            Outcome.REPAIRED,
            "development evidence only; supply validation fixtures before approval" if provisional else None,
            selected=best.candidate.proposal_id,
            provisional=provisional,
            diff=_diff(before, after, name),
            artifact={"kind": best.candidate.patch_kind, "content": after, "sha256": digest},
        )


def run(inputs: Inputs, engine: Elasticsearch, generator: Generator = generate) -> dict[str, Any]:
    """Run the full workflow. Invalid inputs raise ``Rejected``; everything else is an outcome.

    ``generator`` proposes candidates (default: the deterministic B0). Research systems swap it,
    and every candidate still goes through the same contract, screening, freeze and validation."""
    return _Run(inputs, engine, generator).execute()


def _screen(
    rule: Rule,
    mapping: FieldMapping,
    dev: Dataset,
    hyps: list[Hypothesis],
    *,
    original: ReplayResult,
    replayer: Replayer,
    generator: Generator,
) -> tuple[list[_Screened], list[dict[str, str]]]:
    """Replay every generated candidate on development fixtures and keep the ones that improve
    without losing attacks. Returns the best ``MAX_CANDIDATES`` and a record of every rejection."""
    kept, rejected = [], []
    for cand in generator(rule, mapping, dev, hyps, original.matched_ids):
        try:
            new_rule, new_mapping = apply(rule, mapping, cand)
        except Rejected as exc:
            rejected.append({"proposal_id": cand.proposal_id, "reason": f"{exc.reason}: {exc.detail}"})
            continue
        result = replayer.run(new_rule, new_mapping)
        if result.error:
            rejected.append({"proposal_id": cand.proposal_id, "reason": f"replay_error: {result.error}"})
        elif result.tp < original.tp or original.scenarios_detected - result.scenarios_detected:
            rejected.append({"proposal_id": cand.proposal_id, "reason": "loses attack events on development fixtures"})
        elif result.tp <= original.tp and result.fp >= original.fp:
            rejected.append({"proposal_id": cand.proposal_id, "reason": "no improvement on development fixtures"})
        else:
            entry = {"candidate": cand.model_dump(mode="json"), "development": result.as_dict()}
            kept.append(_Screened(entry, cand, new_rule, new_mapping, result))
    kept.sort(key=_Screened.rank)
    rejected += [{"proposal_id": s.candidate.proposal_id, "reason": "outranked"} for s in kept[MAX_CANDIDATES:]]
    return kept[:MAX_CANDIDATES], rejected
