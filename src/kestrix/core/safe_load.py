# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Bounded, tag-free loading of untrusted YAML and JSONL."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml
from yaml.events import AliasEvent

from .errors import Reason, Rejected

MAX_RULE_BYTES = 100 * 1024
MAX_TELEMETRY_BYTES = 250 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_DEPTH = 16

_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"
_PLAIN_TAGS = frozenset("tag:yaml.org,2002:" + t for t in ("str", "int", "bool", "null", "float", "seq", "map")) | {
    _TIMESTAMP_TAG
}


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that also refuses aliases (billion-laughs), explicit tags and duplicate keys."""

    def construct_mapping(self, node, deep=False):  # type: ignore[no-untyped-def]
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise Rejected(Reason.MALFORMED_YAML, f"duplicate key {key!r}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)

    def compose_node(self, parent, index):  # type: ignore[no-untyped-def]
        if self.check_event(AliasEvent):
            raise Rejected(Reason.YAML_ALIAS, "anchors and aliases are not supported")
        node = super().compose_node(parent, index)
        if node is not None and node.tag not in _PLAIN_TAGS:
            raise Rejected(Reason.YAML_TAG, f"tag {node.tag!r} is not allowed")
        return node


# Sigma rules carry ``date: 2025-12-25``; keep it as the literal text so loaded documents stay
# JSON-serializable and never depend on date parsing.
def _timestamp_as_text(loader: _StrictLoader, node: yaml.Node) -> str:
    return str(node.value)


_StrictLoader.add_constructor(_TIMESTAMP_TAG, _timestamp_as_text)


def check_depth(value: Any, limit: int = MAX_DEPTH) -> None:
    """Raise once nesting exceeds ``limit``."""
    stack = [(value, 1)]
    while stack:
        item, d = stack.pop()
        if d > limit:
            raise Rejected(Reason.NESTING_TOO_DEEP, f"nesting exceeds {limit}")
        if isinstance(item, dict):
            stack.extend((v, d + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, d + 1) for v in item)


def load_yaml(text: str | bytes, max_bytes: int = MAX_RULE_BYTES) -> Any:
    raw = text.encode() if isinstance(text, str) else text
    if len(raw) > max_bytes:
        raise Rejected(Reason.INPUT_TOO_LARGE, f"{len(raw)} bytes exceeds {max_bytes}")
    try:
        docs = list(yaml.load_all(raw.decode("utf-8"), Loader=_StrictLoader))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise Rejected(Reason.MALFORMED_YAML, str(exc).splitlines()[0]) from None
    if len(docs) != 1:
        raise Rejected(Reason.UNSUPPORTED_RULE_TYPE, "exactly one YAML document is required")
    check_depth(docs[0])
    return docs[0]


def iter_jsonl(path: Path, max_bytes: int = MAX_TELEMETRY_BYTES) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield ``(line_number, object)`` from a JSONL file within size and depth limits."""
    size = path.stat().st_size
    if size > max_bytes:
        raise Rejected(Reason.INPUT_TOO_LARGE, f"{path.name}: {size} bytes exceeds {max_bytes}")
    with path.open("rb") as fh:
        for lineno, line in enumerate(fh, 1):
            if len(line) > MAX_LINE_BYTES:
                raise Rejected(Reason.INPUT_TOO_LARGE, f"{path.name}:{lineno} line too long")
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise Rejected(Reason.MALFORMED_JSONL, f"{path.name}:{lineno} {exc}") from None
            if not isinstance(obj, dict):
                raise Rejected(Reason.MALFORMED_JSONL, f"{path.name}:{lineno} is not an object")
            check_depth(obj)
            yield lineno, obj
