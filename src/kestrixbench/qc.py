"""Quality checks over the acquired sources (plan section 11).

Reports are aggregate: counts, reason codes, rule ids and repository paths. No event
payloads, command lines or field values are written, so a report is safe to share and to
commit. Every input is parsed with the strict loaders in ``kestrix.core.safe_load``.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from collections import Counter, defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from kestrix.core.errors import Rejected
from kestrix.core.evidence import canonical_json
from kestrix.core.safe_load import check_depth, load_yaml
from kestrix.detect.mapping import FieldMapping, to_lucene
from kestrix.detect.rule import PROCESS_CREATION_FIELDS, parse_rule

MAX_SIGMA_BYTES = 100 * 1024
MAX_METADATA_BYTES = 256 * 1024
MAX_ATOMIC_BYTES = 2 * 1024 * 1024
MAX_EVENT_JSON_BYTES = 4 * 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 2 * 1024**3
SIGMA_RULES = "rules/windows/process_creation"
SIGMA_REGRESSION = "regression_data/rules/windows/process_creation"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
# Sysmon field names map to themselves, as in the raw regression events.
IDENTITY = FieldMapping("sysmon-identity", {})


def _read_yaml(path: Path, max_bytes: int) -> Any:
    data = path.read_bytes()
    return load_yaml(data, max_bytes=max_bytes)


def _detection_fingerprint(doc: dict[str, Any]) -> str | None:
    """Hash of the detection block alone: equal hashes are logic duplicates under other titles."""
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        return None
    return hashlib.sha256(canonical_json(detection)).hexdigest()


def _json_documents(text: str) -> list[Any]:
    """Parse one JSON value, a list, or several concatenated values (Sigma exports multi-event files that way)."""
    decoder = json.JSONDecoder()
    docs: list[Any] = []
    pos = 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos == len(text):
            break
        doc, pos = decoder.raw_decode(text, pos)
        check_depth(doc)
        docs.extend(doc if isinstance(doc, list) else [doc])
    if not docs:
        raise ValueError("empty JSON file")
    return docs


def _regression_events(case_dir: Path, info: dict[str, Any]) -> tuple[list[str], int, list[str]]:
    """Return (rule ids covered, Sysmon EID 1 event count, problems) for one regression folder."""
    problems: list[str] = []
    ids = [str(m["id"]) for m in info.get("rule_metadata") or [] if isinstance(m, dict) and "id" in m]
    events = 0
    for rule_id in ids:
        path = case_dir / f"{rule_id}.json"
        if not path.is_file():
            problems.append(f"{case_dir.name}: missing {path.name}")
            continue
        if path.stat().st_size > MAX_EVENT_JSON_BYTES:
            problems.append(f"{case_dir.name}: {path.name} exceeds size limit")
            continue
        try:
            records = _json_documents(path.read_text(encoding="utf-8"))
        except (ValueError, Rejected):
            problems.append(f"{case_dir.name}: {path.name} is not valid bounded JSON")
            continue
        for record in records:
            event = record.get("Event") if isinstance(record, dict) else None
            system = event.get("System") if isinstance(event, dict) else None
            data = event.get("EventData") if isinstance(event, dict) else None
            if not (isinstance(system, dict) and isinstance(data, dict)):
                problems.append(f"{case_dir.name}: {path.name} has a record without Event.System/EventData")
                continue
            if is_sysmon_process_creation(system):
                events += 1
    return ids, events, problems


def _qc_regression(root: Path) -> tuple[set[str], int, list[str]]:
    regression_ids: set[str] = set()
    regression_events = 0
    problems: list[str] = []
    for info_path in sorted((root / SIGMA_REGRESSION).glob("*/info.yml")):
        try:
            info = _read_yaml(info_path, MAX_METADATA_BYTES)
        except Rejected as exc:
            problems.append(f"{info_path.parent.name}: info.yml {exc.reason}")
            continue
        if not isinstance(info, dict):
            problems.append(f"{info_path.parent.name}: info.yml is not a mapping")
            continue
        covered, events, found = _regression_events(info_path.parent, info)
        regression_ids.update(covered)
        regression_events += events
        problems.extend(found)
    return regression_ids, regression_events, problems


def qc_sigma(root: Path) -> dict[str, object]:
    rules_dir = root / SIGMA_RULES
    outcome: Counter[str] = Counter()
    status: Counter[str] = Counter()
    details: Counter[str] = Counter()
    ids: Counter[str] = Counter()
    fingerprints: defaultdict[str, list[str]] = defaultdict(list)
    supported: list[str] = []
    missing_id = 0
    for path in sorted(rules_dir.rglob("*.yml")):
        rel = path.relative_to(root).as_posix()
        try:
            doc = _read_yaml(path, MAX_SIGMA_BYTES)
        except Rejected as exc:
            outcome[f"load:{exc.reason}"] += 1
            continue
        if not isinstance(doc, dict):
            outcome["load:not_a_mapping"] += 1
            continue
        rule_id = str(doc.get("id") or "")
        if rule_id:
            ids[rule_id] += 1
        else:
            missing_id += 1
        status[str(doc.get("status") or "missing")] += 1
        fp = _detection_fingerprint(doc)
        if fp:
            fingerprints[fp].append(rel)
        try:
            rule = parse_rule(path.read_text(encoding="utf-8"))
            to_lucene(rule, IDENTITY)
        except Rejected as exc:
            outcome[f"unsupported:{exc.reason}"] += 1
            # Drop the selection-name prefix so equal causes aggregate across rules.
            details[f"{exc.reason}: {exc.detail.split(': ', 1)[-1]}"] += 1
            continue
        except UnicodeDecodeError:
            outcome["load:not_utf8"] += 1
            continue
        outcome["supported"] += 1
        supported.append(rule_id or rel)

    regression_ids, regression_events, problems = _qc_regression(root)
    supported_set = set(supported)
    return {
        "rules_total": sum(outcome.values()),
        "outcomes": dict(sorted(outcome.items())),
        "top_unsupported_causes": details.most_common(25),
        "status": dict(sorted(status.items())),
        "missing_id": missing_id,
        "duplicate_ids": sorted(i for i, n in ids.items() if n > 1),
        "duplicate_detection_groups": sorted(sorted(v) for v in fingerprints.values() if len(v) > 1),
        "regression": {
            "rules_with_positive_events": len(regression_ids),
            "sysmon_eid1_events": regression_events,
            "supported_rules_with_positive_events": sorted(supported_set & regression_ids),
            "problems": problems,
        },
        "supported_rule_ids": sorted(supported_set),
        "v1_fields": sorted(PROCESS_CREATION_FIELDS),
    }


OTRF_WINDOWS = "datasets/atomic/windows"


def archive_key(windows: Path, path: Path) -> str:
    """Stable, unique id of an OTRF archive: its path below the windows folder, without .zip."""
    return path.relative_to(windows).as_posix().removesuffix(".zip")


def is_sysmon_process_creation(fields: dict[str, Any]) -> bool:
    return str(fields.get("EventID")) == "1" and fields.get("Channel") == SYSMON_CHANNEL


def iter_zip_records(path: Path) -> Iterator[tuple[str, Any]]:
    """Yield ``(member name, record)`` from every JSON-lines member of an OTRF archive.

    Raises ``ValueError`` on a malformed line and ``zipfile.BadZipFile``/``OSError`` on a bad archive."""
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            if member.is_dir() or member.file_size > MAX_ZIP_MEMBER_BYTES:
                continue
            name = member.filename.rsplit("/", 1)[-1]
            if member.filename.startswith("__MACOSX/") or name.startswith("._"):
                continue  # macOS archive metadata, not telemetry
            if not name.endswith((".json", ".jsonl")):
                continue
            with archive.open(member) as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        yield member.filename, json.loads(line)
                    except ValueError:
                        raise ValueError(f"{path.name}: {member.filename} has a malformed line") from None


def _zip_eid1_count(path: Path) -> tuple[int, int, str | None]:
    """Count (records, Sysmon EID 1 records); return an error string on failure."""
    records = eid1 = 0
    try:
        for _, rec in iter_zip_records(path):
            records += 1
            eid1 += isinstance(rec, dict) and is_sysmon_process_creation(rec)
    except ValueError as exc:
        return records, eid1, str(exc)
    except (zipfile.BadZipFile, OSError) as exc:
        return records, eid1, f"{path.name}: {type(exc).__name__}"
    return records, eid1, None


def qc_otrf(root: Path) -> dict[str, object]:
    meta_dir = root / "datasets/atomic/_metadata"
    windows = root / "datasets/atomic/windows"
    # OTRF files one dataset name under several tactic folders with different contents,
    # so archives are keyed by their path below datasets/atomic/windows, not by file name.
    zips = {archive_key(windows, p): p for p in windows.rglob("*.zip")}
    problems: list[str] = []
    techniques: Counter[str] = Counter()
    linked: set[str] = set()
    metadata_windows = 0
    for path in sorted(meta_dir.glob("SDWIN-*.yaml")):
        try:
            doc = _read_yaml(path, MAX_METADATA_BYTES)
        except Rejected as exc:
            problems.append(f"{path.name}: {exc.reason}")
            continue
        if not isinstance(doc, dict):
            problems.append(f"{path.name}: not a mapping")
            continue
        metadata_windows += 1
        for mapping in doc.get("attack_mappings") or []:
            if isinstance(mapping, dict) and mapping.get("technique"):
                techniques[str(mapping["technique"])] += 1
        for item in doc.get("files") or []:
            link = item.get("link") if isinstance(item, dict) else None
            if isinstance(link, str) and link.endswith(".zip"):
                linked.add(link.split(OTRF_WINDOWS + "/", 1)[-1].removesuffix(".zip"))
    with_eid1 = 0
    total_records = total_eid1 = 0
    for name in sorted(zips):
        records, eid1, error = _zip_eid1_count(zips[name])
        total_records += records
        total_eid1 += eid1
        with_eid1 += eid1 > 0
        if error:
            problems.append(f"{name}: {error.split(': ', 1)[-1]}")
    return {
        "windows_metadata_files": metadata_windows,
        "windows_zip_files": len(zips),
        "metadata_links_missing_zip": sorted(linked - zips.keys()),
        "zips_without_metadata": len(zips.keys() - linked),
        "records_total": total_records,
        "sysmon_eid1_records": total_eid1,
        "zips_with_sysmon_eid1": with_eid1,
        "attack_techniques": len(techniques),
        "top_techniques": techniques.most_common(15),
        "problems": problems,
    }


def qc_atomic(root: Path) -> dict[str, object]:
    problems: list[str] = []
    executors: Counter[str] = Counter()
    techniques = tests = windows_tests = 0
    for path in sorted((root / "atomics").glob("T*/T*.yaml")):
        try:
            doc = _read_yaml(path, MAX_ATOMIC_BYTES)
        except Rejected as exc:
            problems.append(f"{path.name}: {exc.reason}")
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("atomic_tests"), list):
            problems.append(f"{path.name}: missing atomic_tests list")
            continue
        techniques += 1
        for test in doc["atomic_tests"]:
            if not isinstance(test, dict):
                continue
            tests += 1
            if "windows" in (test.get("supported_platforms") or []):
                windows_tests += 1
                executor = test.get("executor")
                executors[str(executor.get("name")) if isinstance(executor, dict) else "missing"] += 1
    return {
        "techniques": techniques,
        "tests": tests,
        "windows_tests": windows_tests,
        "windows_executors": dict(executors.most_common()),
        "problems": problems,
    }


QC = {"sigma": qc_sigma, "otrf": qc_otrf, "atomic-red-team": qc_atomic}
