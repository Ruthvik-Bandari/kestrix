"""Environment field mappings (the processing pipeline) and Lucene conversion."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from ..core.errors import Reason, Rejected
from ..core.safe_load import load_yaml
from .rule import PROCESS_CREATION_FIELDS, Rule, sha256_text

INDEX_FIELD = re.compile(r"[A-Za-z_@][A-Za-z0-9_@.\-]{0,254}")


@dataclass(frozen=True)
class FieldMapping:
    """Maps Sigma field names to index field names for one environment."""

    name: str
    fields: dict[str, str]

    @property
    def sha256(self) -> str:
        return sha256_text(self.canonical())

    def canonical(self) -> str:
        return json.dumps({"name": self.name, "fields": self.fields}, sort_keys=True, separators=(",", ":"))

    def target(self, sigma_field: str) -> str:
        return self.fields.get(sigma_field, sigma_field)

    def with_field(self, sigma_field: str, index_field: str) -> FieldMapping:
        return FieldMapping(self.name, {**self.fields, sigma_field: index_field})

    def to_yaml_dict(self) -> dict[str, object]:
        return {"schema_version": 1, "name": self.name, "fields": dict(sorted(self.fields.items()))}


def parse_mapping(text: str) -> FieldMapping:
    doc = load_yaml(text)
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise Rejected(Reason.INVALID_MAPPING, "mapping requires schema_version: 1")
    name, fields = doc.get("name"), doc.get("fields")
    if not isinstance(name, str) or not isinstance(fields, dict):
        raise Rejected(Reason.INVALID_MAPPING, "mapping requires name and fields")
    for src, dst in fields.items():
        if src not in PROCESS_CREATION_FIELDS:
            raise Rejected(Reason.UNKNOWN_FIELD, f"mapping source {src!r} is not a supported field")
        if not isinstance(dst, str) or not INDEX_FIELD.fullmatch(dst):
            raise Rejected(Reason.INVALID_MAPPING, f"invalid index field for {src!r}")
    return FieldMapping(name, dict(fields))


def _pysigma_mapping(mapping: FieldMapping) -> dict[str | None, str | list[str]]:
    """pySigma's annotation also admits ``None`` keys and list targets; we use neither."""
    fields: dict[str | None, str | list[str]] = {k: v for k, v in mapping.fields.items()}
    return fields


def to_lucene(rule: Rule, mapping: FieldMapping) -> str:
    """Convert with the pinned pySigma Lucene backend. Rules are re-parsed every call
    because pySigma pipelines mutate the rule objects they process."""
    pipeline = ProcessingPipeline(
        name=f"cyberguard-{mapping.name}",
        items=[
            ProcessingItem(
                identifier="cg_field_mapping", transformation=FieldMappingTransformation(_pysigma_mapping(mapping))
            )
        ],
    )
    try:
        queries = LuceneBackend(pipeline).convert(SigmaCollection.from_yaml(rule.to_yaml()))
    except SigmaError as exc:
        raise Rejected(Reason.CONVERSION_FAILED, str(exc)) from None
    if len(queries) != 1 or not isinstance(queries[0], str):
        raise Rejected(Reason.CONVERSION_FAILED, f"expected one query, got {len(queries)}")
    return queries[0]
