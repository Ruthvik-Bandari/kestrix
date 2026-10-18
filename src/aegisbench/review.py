"""Human review of OTRF candidate positives (plan section 11, "Label and license record").

``write_sheet`` resolves the OTRF events that supported rules matched during replay and writes,
under ``<root>/review/`` on the cluster only:

- ``candidates.jsonl``: one line per candidate event, with its v1 fields and the rules that matched it;
- ``labels.csv``: one row per event for the reviewer (``label``, ``rationale``, ``reviewer``).
  It is created once and never overwritten, so a reviewer's work is never lost.

Both files hold raw event values, so they are private to the user (mode 0600, directory 0700).
They must stay off the repository and out of AI-assistant sessions. ``status`` validates the
labels file and returns counts only.
"""

from __future__ import annotations

import csv
import fcntl
import io
import json
import os
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from aegissec.core.errors import Rejected

from .positives import otrf_events, supported_rules

LABELS = ("malicious", "benign", "unknown")
LABEL_COLUMNS = ("event_id", "label", "rationale", "reviewer")
MAX_LABELS_BYTES = 5 * 1024 * 1024
MAX_RATIONALE_CHARS = 1000


class ReviewError(ValueError):
    pass


def _private_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    os.replace(tmp, path)


def candidates(root: Path, report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """OTRF events matched by at least one rule, keyed by event id, with the matching rules."""
    pool = {p.event.event_id: p for p in otrf_events(root / "otrf")}
    rules, _ = supported_rules(root / "sigma")
    out: dict[str, dict[str, Any]] = {}
    for rule_id, entry in sorted(report["per_rule"].items()):
        for event_id in entry.get("matched_event_ids", []):
            if not event_id.startswith("otrf:"):
                continue
            if event_id not in pool:
                raise ReviewError(f"replay event {event_id} is not in the current OTRF pool; re-run replay")
            item = out.setdefault(
                event_id,
                {
                    "event_id": event_id,
                    "dataset": pool[event_id].source,
                    "fields": pool[event_id].event.data,
                    "rules": [],
                },
            )
            title = rules[rule_id].title if rule_id in rules else None
            item["rules"].append({"rule_id": rule_id, "title": title})
    return out


def write_sheet(root: Path, report: dict[str, Any]) -> dict[str, int]:
    found = candidates(root, report)
    review = root / "review"
    _private_write(
        review / "candidates.jsonl",
        "".join(json.dumps(found[k], sort_keys=True, ensure_ascii=False) + "\n" for k in sorted(found)),
    )
    labels = review / "labels.csv"
    created = 0
    if not labels.exists():
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(LABEL_COLUMNS)
        writer.writerows([k, "", "", ""] for k in sorted(found))
        _private_write(labels, buf.getvalue())
        created = 1
    return {
        "candidate_events": len(found),
        "rules": len({r["rule_id"] for c in found.values() for r in c["rules"]}),
        "datasets": len({c["dataset"] for c in found.values()}),
        "labels_file_created": created,
    }


def label_problem(label: str, rationale: str, reviewer: str) -> str | None:
    if label not in LABELS:
        return f"label must be one of {', '.join(LABELS)}"
    if not reviewer:
        return "reviewer is required"
    if label != "unknown" and not rationale:
        return f"rationale is required for {label}"
    if len(rationale) > MAX_RATIONALE_CHARS:
        return f"rationale exceeds {MAX_RATIONALE_CHARS} characters"
    if any(c in rationale + reviewer for c in "\r\n"):
        return "rationale and reviewer must be one line"
    return None


def read_labels(path: Path, known: set[str]) -> tuple[dict[str, str], list[str]]:
    """Validated ``event_id -> label`` for reviewed rows, plus problems (row numbers and reasons only)."""
    if path.stat().st_size > MAX_LABELS_BYTES:
        raise ReviewError(f"labels file exceeds {MAX_LABELS_BYTES} bytes")
    labels: dict[str, str] = {}
    problems: list[str] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if tuple(reader.fieldnames or ()) != LABEL_COLUMNS:
            raise ReviewError(f"labels.csv header must be {','.join(LABEL_COLUMNS)}")
        for n, row in enumerate(reader, start=2):
            event_id = (row.get("event_id") or "").strip()
            label = (row.get("label") or "").strip().lower()
            rationale = (row.get("rationale") or "").strip()
            reviewer = (row.get("reviewer") or "").strip()
            if event_id not in known:
                problems.append(f"row {n}: unknown event id")
            elif event_id in labels:
                problems.append(f"row {n}: duplicate event id")
            elif not label:
                continue  # not reviewed yet
            elif problem := label_problem(label, rationale, reviewer):
                problems.append(f"row {n}: {problem}")
            else:
                labels[event_id] = label
    return labels, problems


def status(root: Path, report: dict[str, Any]) -> dict[str, object]:
    """Review progress and the roots that reviewed labels would yield; counts and rule ids only."""
    found = candidates(root, report)
    labels, problems = read_labels(root / "review" / "labels.csv", set(found))
    malicious = {e for e, label in labels.items() if label == "malicious"}
    per_rule = report["per_rule"]
    verified: Counter[str] = Counter()
    for rule_id, entry in per_rule.items():
        verified[rule_id] = int(entry["own_regression_matched"]) + sum(
            e in malicious for e in entry["matched_event_ids"]
        )
    return {
        "schema_version": 1,
        "candidate_events": len(found),
        "reviewed": len(labels),
        "unreviewed": len(found) - len(labels),
        "labels": dict(sorted(Counter(labels.values()).items())),
        "ai_assisted": _ai_assisted(root / "review" / "labels.csv", set(labels)),
        "problems": problems,
        "roots": {
            "with_1plus_verified_positive": sum(n >= 1 for n in verified.values()),
            "with_2plus_verified_positives": sum(n >= 2 for n in verified.values()),
        },
    }


# ---------------------------------------------------------------- interactive labelling (run by the reviewer)


def _load_sheet(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    review = root / "review"
    sheet = [
        json.loads(line) for line in (review / "candidates.jsonl").read_text(encoding="utf-8").splitlines() if line
    ]
    with (review / "labels.csv").open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if tuple(reader.fieldnames or ()) != LABEL_COLUMNS:
            raise ReviewError(f"labels.csv header must be {','.join(LABEL_COLUMNS)}")
        rows = [dict(r) for r in reader]
    return sheet, rows


def dataset_info(otrf_root: Path) -> dict[str, dict[str, Any]]:
    """OTRF metadata (title, description, ATT&CK techniques) keyed by archive path, for the reviewer."""
    from .qc import MAX_METADATA_BYTES, OTRF_WINDOWS, _read_yaml

    out: dict[str, dict[str, Any]] = {}
    for path in sorted((otrf_root / "datasets/atomic/_metadata").glob("SDWIN-*.yaml")):
        try:
            doc = _read_yaml(path, MAX_METADATA_BYTES)
        except Rejected:
            continue  # metadata is advisory for the reviewer; QC reports unreadable files
        if not isinstance(doc, dict):
            continue
        techniques = sorted(
            str(m["technique"]) + (f".{m['sub-technique']}" if m.get("sub-technique") else "")
            for m in doc.get("attack_mappings") or []
            if isinstance(m, dict) and m.get("technique")
        )
        info = {
            "id": path.stem,
            "title": doc.get("title"),
            "description": doc.get("description"),
            "techniques": techniques,
        }
        for item in doc.get("files") or []:
            link = item.get("link") if isinstance(item, dict) else None
            if isinstance(link, str) and OTRF_WINDOWS + "/" in link:
                out[link.split(OTRF_WINDOWS + "/", 1)[1].removesuffix(".zip")] = info
    return out


def next_candidate(root: Path) -> tuple[dict[str, Any] | None, int]:
    """The first unlabelled candidate (with its dataset metadata) and how many remain."""
    sheet, rows = _load_sheet(root)
    labelled = {r["event_id"] for r in rows if (r.get("label") or "").strip()}
    todo = [c for c in sheet if c["event_id"] not in labelled]
    if not todo:
        return None, 0
    item = dict(todo[0])
    item["dataset_info"] = dataset_info(root / "otrf").get(item["dataset"])
    return item, len(todo)


def format_candidate(item: dict[str, Any], remaining: int) -> str:
    info = item.get("dataset_info") or {}
    lines = [
        f"{remaining} left to label",
        f"event    {item['event_id']}",
        f"dataset  {item['dataset']}"
        + (f"  ({info.get('id')}: {info.get('title')})" if info else "  (no OTRF metadata)"),
    ]
    if info.get("techniques"):
        lines.append(f"ATT&CK   {', '.join(info['techniques'])}")
    if info.get("description"):
        lines.append(f"scenario {' '.join(str(info['description']).split())}")
    lines.append("matched by:")
    lines += [f"  - {r['title']} ({r['rule_id']})" for r in item["rules"]]
    lines.append("fields:")
    lines += [f"  {k}: {v}" for k, v in sorted(item["fields"].items())]
    return "\n".join(lines)


def _set_label(root: Path, event_id: str, label: str, rationale: str, reviewer: str) -> None:
    """Record one decision in labels.csv, keeping every other row as it was."""
    label, rationale, reviewer = label.strip().lower(), rationale.strip(), reviewer.strip()
    if problem := label_problem(label, rationale, reviewer):
        raise ReviewError(problem)
    _, rows = _load_sheet(root)
    hits = [r for r in rows if r["event_id"] == event_id]
    if len(hits) != 1:
        raise ReviewError(f"{event_id} is not exactly one row of labels.csv")
    hits[0].update(label=label, rationale=rationale, reviewer=reviewer)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=LABEL_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    _private_write(root / "review" / "labels.csv", buf.getvalue())


AI_REVIEWER_PREFIX = "ai-"


def _import_labels(root: Path, rows: list[dict[str, Any]]) -> dict[str, int]:
    """Bulk-record ``event_id, label, rationale, reviewer`` rows. Every row is validated first; any
    invalid row aborts the whole import. A label a human already set is never overwritten."""
    _, current = _load_sheet(root)
    by_id = {r["event_id"]: r for r in current}
    problems = []
    for n, row in enumerate(rows, 1):
        if row.get("event_id") not in by_id:
            problems.append(f"row {n}: unknown event id")
        elif problem := label_problem(_text(row, "label").lower(), _text(row, "rationale"), _text(row, "reviewer")):
            problems.append(f"row {n}: {problem}")
    if problems:
        raise ReviewError("; ".join(problems[:10]))
    counts = {"imported": 0, "kept_existing_human_label": 0}
    for row in rows:
        existing = by_id[row["event_id"]]
        human = (existing.get("label") or "").strip() and not (existing.get("reviewer") or "").startswith(
            AI_REVIEWER_PREFIX
        )
        if human:
            counts["kept_existing_human_label"] += 1
            continue
        existing.update(
            label=_text(row, "label").lower(), rationale=_text(row, "rationale"), reviewer=_text(row, "reviewer")
        )
        counts["imported"] += 1
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=LABEL_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(current)
    _private_write(root / "review" / "labels.csv", buf.getvalue())
    return counts


def _ai_assisted(path: Path, reviewed: set[str]) -> int:
    """How many reviewed rows came from an AI reviewer (reported apart from human labels)."""
    with path.open(encoding="utf-8", newline="") as fh:
        return sum(
            1
            for r in csv.DictReader(fh)
            if r.get("event_id") in reviewed and (r.get("reviewer") or "").startswith(AI_REVIEWER_PREFIX)
        )


def _text(row: dict[str, Any], key: str) -> str:
    """A field as stripped text; missing or null values become empty strings."""
    value = row.get(key)
    return "" if value is None else str(value).strip()


@contextmanager
def _labels_lock(root: Path) -> Iterator[None]:
    """Serialize read-modify-write updates of labels.csv between concurrent reviewers."""
    lock = root / "review" / ".labels.lock"
    lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock.open("a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def set_label(root: Path, event_id: str, label: str, rationale: str, reviewer: str) -> None:
    """Record one decision in labels.csv, keeping every other row as it was."""
    with _labels_lock(root):
        _set_label(root, event_id, label, rationale, reviewer)


def import_labels(root: Path, rows: list[dict[str, Any]]) -> dict[str, int]:
    """Bulk-record labels atomically; never overwrites a human label (see ``_import_labels``)."""
    with _labels_lock(root):
        return _import_labels(root, rows)


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Aegis-Sec label check</title>
<style>
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1f;--mute:#6b6b70;--line:#e3e3e0;--mal:#b42318;--ben:#067647;--unk:#8a6d00;--acc:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1d1d20;--ink:#f2f2f2;--mute:#a1a1a6;--line:#333338;--acc:#7da2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,system-ui,sans-serif}
header{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:12px 16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;z-index:1}
main{max-width:980px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
.card.done{border-color:var(--acc)}
h2{font-size:15px;margin:0 0 4px;word-break:break-all}.mute{color:var(--mute);font-size:13px}
.ai{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}
.malicious{color:var(--mal)}.benign{color:var(--ben)}.unknown{color:var(--unk)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:10px 0;font-size:13px}
dt{color:var(--mute)}dd{margin:0;font-family:ui-monospace,Menlo,monospace;word-break:break-all;white-space:pre-wrap}
.choose{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.choose label{border:1px solid var(--line);border-radius:8px;padding:6px 10px;cursor:pointer}
input[type=text]{width:100%;margin-top:8px;padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:8px 14px;font-weight:600;cursor:pointer}
button:disabled{opacity:.4;cursor:not-allowed}
</style></head><body>
<header><strong>Aegis-Sec label check</strong><span id="count" class="mute"></span>
<label class="mute">Your initials <input id="who" type="text" style="width:90px;margin:0" maxlength="12"></label>
<button id="export" disabled>Export my labels</button></header>
<main><p class="mute">For each event: is this process part of the simulated attack described in the scenario
(<b>malicious</b>), clearly normal activity (<b>benign</b>), or can't you tell (<b>unknown</b>)? A rationale is
required for malicious and benign. Your label replaces the AI label. Event text below is shown as plain text only.</p>
<div id="list"></div></main>
<script id="data" type="application/json">__DATA__</script>
<script>
const items = JSON.parse(document.getElementById('data').textContent);
const state = JSON.parse(localStorage.getItem('aegis-check') || '{}');
const list = document.getElementById('list');
function el(tag, cls, text){const e=document.createElement(tag); if(cls) e.className=cls; if(text!=null) e.textContent=String(text); return e;}
function save(){localStorage.setItem('aegis-check', JSON.stringify(state)); refresh();}
function valid(s){return s && s.label && (s.label==='unknown' || (s.rationale||'').trim());}
function refresh(){
  const done = items.filter(i => valid(state[i.event_id])).length;
  document.getElementById('count').textContent = done + ' / ' + items.length + ' labeled';
  document.getElementById('export').disabled = !(done===items.length && document.getElementById('who').value.trim());
  items.forEach(i => document.getElementById('c-'+i.n).classList.toggle('done', !!valid(state[i.event_id])));
}
items.forEach((it, n) => {
  it.n = n; const c = el('div','card'); c.id = 'c-'+n;
  c.append(el('h2', null, (n+1)+'. '+it.event_id));
  c.append(el('div','mute', (it.dataset_title||'(no dataset title)') + (it.techniques&&it.techniques.length ? ' — '+it.techniques.join(', ') : '')));
  if (it.scenario) c.append(el('p','mute', 'Scenario: '+it.scenario));
  c.append(el('div','mute', 'Rules that fired: '+(it.rules||[]).join(' · ')));
  const dl = el('dl'); Object.keys(it.fields||{}).sort().forEach(k => {dl.append(el('dt',null,k)); dl.append(el('dd',null,it.fields[k]));}); c.append(dl);
  const ai = el('div', null); ai.append(el('span','ai '+it.ai_label, 'AI: '+it.ai_label+' ('+it.ai_reviewer+')')); ai.append(el('div','mute', it.ai_rationale)); c.append(ai);
  const ch = el('div','choose'); const s = state[it.event_id] || {};
  ['malicious','benign','unknown'].forEach(l => {const lab=el('label'); const r=el('input'); r.type='radio'; r.name='l'+n; r.value=l; r.checked=s.label===l;
    r.onchange=()=>{state[it.event_id]=Object.assign(state[it.event_id]||{}, {label:l}); save();}; lab.append(r, ' '+l); ch.append(lab);});
  c.append(ch);
  const t = el('input'); t.type='text'; t.placeholder='Your rationale (one line)'; t.maxLength=1000; t.value=s.rationale||'';
  t.oninput=()=>{state[it.event_id]=Object.assign(state[it.event_id]||{}, {rationale:t.value.replace(/[\\r\\n]+/g,' ')}); save();};
  c.append(t); list.append(c);
});
document.getElementById('who').value = localStorage.getItem('aegis-who') || '';
document.getElementById('who').oninput = e => {localStorage.setItem('aegis-who', e.target.value); refresh();};
document.getElementById('export').onclick = () => {
  const who = document.getElementById('who').value.trim();
  const rows = items.map(i => ({event_id:i.event_id, label:state[i.event_id].label, rationale:(state[i.event_id].rationale||'').trim(), reviewer:who}));
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(rows,null,1)],{type:'application/json'}));
  a.download = 'human-labels.json'; a.click();
};
refresh();
</script></body></html>
"""


def render_check_page(root: Path, event_ids: list[str]) -> str:
    """A self-contained HTML page for the human label check. Event data is embedded as JSON with
    ``<``, ``>`` and ``&`` escaped and rendered with ``textContent`` only, so nothing in an event can
    run as markup or script; a CSP blocks all network access."""
    sheet, rows = _load_sheet(root)
    by_event = {c["event_id"]: c for c in sheet}
    labels = {r["event_id"]: r for r in rows}
    info = dataset_info(root / "otrf")
    items = []
    for event_id in event_ids:
        if event_id not in by_event:
            raise ReviewError(f"{event_id} is not a review candidate")
        c, row, meta = by_event[event_id], labels.get(event_id, {}), info.get(by_event[event_id]["dataset"], {})
        items.append(
            {
                "event_id": event_id,
                "dataset_title": meta.get("title"),
                "techniques": meta.get("techniques"),
                "scenario": " ".join(str(meta.get("description") or "").split()),
                "rules": [r["title"] for r in c["rules"]],
                "fields": c["fields"],
                "ai_label": row.get("label") or "unlabeled",
                "ai_reviewer": row.get("reviewer") or "",
                "ai_rationale": row.get("rationale") or "",
            }
        )
    data = json.dumps(items).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return _PAGE.replace("__DATA__", data)
