"""HTTP routes for detection repair."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from .. import ATTRIBUTION
from ..core.errors import Rejected
from . import cases
from .engine import PINNED_IMAGE, PINNED_VERSION, Elasticsearch
from .rule import parse_rule, render_condition
from .workflow import Inputs, run

router = APIRouter(prefix="/api/detect", tags=["detect"])

MAX_API_FIXTURE_CHARS = 25 * 1024 * 1024
MAX_RULE_CHARS = 100 * 1024


def engine_url() -> str:
    return os.environ.get("KESTRIX_ES_URL", "http://127.0.0.1:9200")


class RuleBody(BaseModel):
    rule: str = Field(max_length=MAX_RULE_CHARS)


class RunBody(BaseModel):
    rule: str = Field(max_length=MAX_RULE_CHARS)
    mapping: str = Field(max_length=MAX_RULE_CHARS)
    development: str = Field(max_length=MAX_API_FIXTURE_CHARS, description="Labeled JSONL fixtures")
    validation: str | None = Field(default=None, max_length=MAX_API_FIXTURE_CHARS)
    healthy_rule: str | None = Field(default=None, max_length=MAX_RULE_CHARS)
    healthy_mapping: str | None = Field(default=None, max_length=MAX_RULE_CHARS)


@contextmanager
def _staged(*texts: str | None) -> Iterator[list[Path | None]]:
    """Write uploaded JSONL to private temp files for the size-checked loader."""
    with tempfile.TemporaryDirectory(prefix="kestrix-detect-") as tmp:
        paths: list[Path | None] = []
        for i, text in enumerate(texts):
            if text is None:
                paths.append(None)
                continue
            path = Path(tmp) / f"fixtures-{i}.jsonl"
            path.write_text(text)
            paths.append(path)
        yield paths


@router.get("/engine")
def engine_status() -> dict[str, Any]:
    es = Elasticsearch(engine_url(), timeout=3)
    try:
        version: str | None = es.version()
    except Rejected:
        version = None
    finally:
        es.close()
    return {
        "reachable": version is not None,
        "version": version,
        "pinned_version": PINNED_VERSION,
        "pinned": version == PINNED_VERSION,
        "image": PINNED_IMAGE,
    }


@router.get("/cases")
def list_cases() -> list[dict[str, Any]]:
    return cases.list_cases()


@router.post("/cases/{case_id}/run")
def run_case(case_id: str) -> dict[str, Any]:
    es = Elasticsearch(engine_url())
    try:
        report = run(cases.inputs(case_id), es)
    finally:
        es.close()
    report["case"] = cases.manifest(case_id)
    return report


@router.post("/parse")
def parse(body: RuleBody) -> dict[str, Any]:
    rule = parse_rule(body.rule)
    return {
        "generated_by": ATTRIBUTION,
        "title": rule.title,
        "id": rule.rule_id,
        "sha256": rule.sha256,
        "fields": sorted(rule.fields),
        "condition": render_condition(rule.condition),
        "selections": {
            name: [
                [
                    {"field": p.field, "modifier": p.modifier, "values": list(p.values), "match_all": p.match_all}
                    for p in b
                ]
                for b in sel.branches
            ]
            for name, sel in rule.selections.items()
        },
    }


@router.post("/run")
def run_custom(body: RunBody) -> dict[str, Any]:
    es = Elasticsearch(engine_url())
    try:
        with _staged(body.development, body.validation) as (dev, val):
            assert dev is not None
            return run(Inputs(body.rule, body.mapping, dev, val, body.healthy_rule, body.healthy_mapping), es)
    finally:
        es.close()
