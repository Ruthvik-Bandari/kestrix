"""Labeled event fixtures and schema profiling (FR01, FR02)."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ..core.errors import Reason, Rejected
from ..core.safe_load import MAX_TELEMETRY_BYTES, iter_jsonl

Label = Literal["malicious", "benign", "unknown"]
_LABELS = frozenset({"malicious", "benign", "unknown"})
_EVENT_ID = re.compile(r"[A-Za-z0-9_.:\-]{1,128}")
_MAX_DISTINCT = 10_000


@dataclass(frozen=True)
class Event:
    event_id: str
    label: Label
    scenario_id: str | None
    data: dict[str, Any]


@dataclass(frozen=True)
class Dataset:
    name: str
    events: tuple[Event, ...]
    sha256: str

    def ids(self, label: Label) -> frozenset[str]:
        return frozenset(e.event_id for e in self.events if e.label == label)


def load_dataset(path: Path, max_bytes: int = MAX_TELEMETRY_BYTES) -> Dataset:
    """Load ``{"event_id", "label", "scenario_id", "data"}`` lines. Labels never reach the index."""
    events: list[Event] = []
    seen: set[str] = set()
    for lineno, obj in iter_jsonl(path, max_bytes):
        event_id, label, data = obj.get("event_id"), obj.get("label"), obj.get("data")
        if not isinstance(event_id, str) or not _EVENT_ID.fullmatch(event_id):
            raise Rejected(Reason.INVALID_FIXTURE, f"{path.name}:{lineno} invalid event_id")
        if event_id in seen:
            raise Rejected(Reason.INVALID_FIXTURE, f"{path.name}:{lineno} duplicate event_id {event_id}")
        if label not in _LABELS:
            raise Rejected(Reason.INVALID_FIXTURE, f"{path.name}:{lineno} label must be one of {sorted(_LABELS)}")
        if not isinstance(data, dict):
            raise Rejected(Reason.INVALID_FIXTURE, f"{path.name}:{lineno} data must be an object")
        scenario = obj.get("scenario_id")
        if scenario is not None and not isinstance(scenario, str):
            raise Rejected(Reason.INVALID_FIXTURE, f"{path.name}:{lineno} scenario_id must be a string")
        seen.add(event_id)
        events.append(Event(event_id, label, scenario, data))
    if not events:
        raise Rejected(Reason.INVALID_FIXTURE, f"{path.name} contains no events")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return Dataset(path.name, tuple(events), digest)


def flatten(data: dict[str, Any], prefix: str = "") -> Iterator[tuple[str, Any]]:
    for key, value in data.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            yield from flatten(value, f"{path}.")
        else:
            yield path, value


def lookup(data: dict[str, Any], path: str) -> Any:
    """Resolve a dotted index field against nested event data (None when absent)."""
    if path in data:
        return data[path]
    node: Any = data
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


@dataclass
class FieldStats:
    present: int = 0
    null: int = 0
    types: set[str] = field(default_factory=set)
    _distinct: set[str] = field(default_factory=set, repr=False)
    cardinality_capped: bool = False

    def add(self, value: Any) -> None:
        self.present += 1
        if value is None:
            self.null += 1
            return
        self.types.add(type(value).__name__)
        if len(self._distinct) < _MAX_DISTINCT:
            self._distinct.add(str(value))
        else:
            self.cardinality_capped = True

    @property
    def cardinality(self) -> int:
        return len(self._distinct)

    def as_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "null": self.null,
            "types": sorted(self.types),
            "cardinality": self.cardinality,
            "cardinality_capped": self.cardinality_capped,
        }


@dataclass(frozen=True)
class SchemaProfile:
    total_events: int
    fields: dict[str, FieldStats]

    def presence(self, index_field: str) -> int:
        stats = self.fields.get(index_field)
        return 0 if stats is None else stats.present - stats.null

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_events": self.total_events,
            "fields": {name: stats.as_dict() for name, stats in sorted(self.fields.items())},
        }


def profile(events: Iterable[Event]) -> SchemaProfile:
    fields: dict[str, FieldStats] = {}
    total = 0
    for event in events:
        total += 1
        for path, value in flatten(event.data):
            fields.setdefault(path, FieldStats()).add(value)
    return SchemaProfile(total, fields)
