# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Pinned Elasticsearch replay engine (plan section 10, "Engine fidelity").

The loader writes only to disposable ``cg-replay-*`` indexes. Queries run through
``query_string`` exactly as the backend produced them, paginated with a point in time
so every match is retrieved.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any

import httpx

from ..core.errors import Reason, Rejected
from .fixtures import Event

PINNED_VERSION = "8.19.3"
PINNED_IMAGE = (
    "docker.elastic.co/elasticsearch/elasticsearch:8.19.3"
    "@sha256:bbac63ecd50e9263565fbb616172a5287d5f99e486d76453e81e32cafcba3838"
)
INDEX_PREFIX = "cg-replay-"
_BULK_CHUNK = 5_000
_PAGE = 5_000

# Strings index as keywords with a lowercase normalizer, giving Sigma's case-insensitive
# matching for exact and wildcard terms. Date and numeric detection are off so that
# string fixtures keep their declared type.
INDEX_BODY = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "-1",
        "analysis": {"normalizer": {"cg_lower": {"type": "custom", "filter": ["lowercase"]}}},
    },
    "mappings": {
        "date_detection": False,
        "numeric_detection": False,
        "dynamic_templates": [
            {
                "strings": {
                    "match_mapping_type": "string",
                    "mapping": {"type": "keyword", "normalizer": "cg_lower", "ignore_above": 32766},
                }
            }
        ],
    },
}


@dataclass(frozen=True)
class QueryResult:
    matched_ids: frozenset[str]
    total_hits: int


class Elasticsearch:
    def __init__(self, url: str = "http://127.0.0.1:9200", timeout: float = 30.0) -> None:
        # trust_env=False: the engine is a local replay oracle, so HTTP(S)_PROXY settings must not
        # route its traffic (including 127.0.0.1) through a proxy.
        self._http = httpx.Client(base_url=url, timeout=timeout, follow_redirects=False, trust_env=False)

    def close(self) -> None:
        self._http.close()

    def _call(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            resp = self._http.request(method, path, **kwargs)
        except httpx.TransportError as exc:
            raise Rejected(Reason.ENGINE_UNAVAILABLE, type(exc).__name__) from None
        body = resp.json() if resp.content else {}
        if resp.status_code >= 400:
            err = body.get("error", {}) if isinstance(body, dict) else {}
            kind = err.get("type", "error") if isinstance(err, dict) else "error"
            reason = err.get("reason", "") if isinstance(err, dict) else str(err)
            raise Rejected(Reason.ENGINE_ERROR, f"{resp.status_code} {kind}: {reason}"[:500])
        return body

    def version(self) -> str:
        return str(self._call("GET", "/")["version"]["number"])

    def require_pinned(self) -> None:
        found = self.version()
        if found != PINNED_VERSION:
            raise Rejected(Reason.ENGINE_ERROR, f"engine {found} is not the pinned {PINNED_VERSION}")

    @contextmanager
    def replay_index(self, events: Sequence[Event]) -> Iterator[str]:
        """Create a run-specific index, load and verify events, and always delete it."""
        name = f"{INDEX_PREFIX}{secrets.token_hex(8)}"
        self._call("PUT", f"/{name}", json=INDEX_BODY)
        try:
            self._load(name, events)
            yield name
        finally:
            with suppress(Rejected):
                self._call("DELETE", f"/{name}")

    def _load(self, index: str, events: Sequence[Event]) -> None:
        if not index.startswith(INDEX_PREFIX):
            raise Rejected(Reason.ENGINE_ERROR, "loader may only write disposable replay indexes")
        for start in range(0, len(events), _BULK_CHUNK):
            lines = []
            for event in events[start : start + _BULK_CHUNK]:
                lines.append(json.dumps({"index": {"_index": index, "_id": event.event_id}}))
                lines.append(json.dumps(event.data, separators=(",", ":")))
            body = self._call(
                "POST",
                "/_bulk",
                content=("\n".join(lines) + "\n").encode(),
                headers={"content-type": "application/x-ndjson"},
            )
            if body.get("errors"):
                first = next(i for i in body["items"] if i["index"].get("error"))
                raise Rejected(
                    Reason.ENGINE_ERROR,
                    f"bulk load failed for {first['index']['_id']}: {first['index']['error'].get('reason', '')}"[:500],
                )
        self._call("POST", f"/{index}/_refresh")
        count = self._call("GET", f"/{index}/_count")["count"]
        if count != len(events):
            raise Rejected(Reason.INDEX_COUNT_MISMATCH, f"indexed {count} of {len(events)} events")
        # Strings beyond ignore_above are stored but not searchable; they would silently never match.
        ignored = self._call("POST", f"/{index}/_count", json={"query": {"exists": {"field": "_ignored"}}})["count"]
        if ignored:
            raise Rejected(Reason.INVALID_FIXTURE, f"{ignored} events hold values too long to index (over 32766 chars)")

    def search_ids(self, index: str, lucene: str) -> QueryResult:
        """Return every matching document id; fail rather than truncate."""
        pit = self._call("POST", f"/{index}/_pit", params={"keep_alive": "1m"})["id"]
        ids: set[str] = set()
        total = 0
        search_after: list[Any] | None = None
        try:
            while True:
                body: dict[str, Any] = {
                    "size": _PAGE,
                    "_source": False,
                    "track_total_hits": True,
                    "query": {"query_string": {"query": lucene}},
                    "pit": {"id": pit, "keep_alive": "1m"},
                    "sort": ["_shard_doc"],
                }
                if search_after is not None:
                    body["search_after"] = search_after
                resp = self._call("POST", "/_search", json=body)
                if resp.get("timed_out") or resp.get("_shards", {}).get("failed"):
                    raise Rejected(Reason.ENGINE_ERROR, "search timed out or had shard failures")
                total = resp["hits"]["total"]["value"]
                hits = resp["hits"]["hits"]
                ids.update(h["_id"] for h in hits)
                if len(hits) < _PAGE:
                    break
                search_after = hits[-1]["sort"]
        finally:
            with suppress(Rejected):
                self._call("DELETE", "/_pit", json={"id": pit})
        if len(ids) != total:
            raise Rejected(Reason.ENGINE_ERROR, f"retrieved {len(ids)} of {total} hits")
        return QueryResult(frozenset(ids), total)
