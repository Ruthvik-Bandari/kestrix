# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Phase 3 measurement on real public CI and infrastructure files: false-alarm rates and tool agreement.

Run by ``iac_measure.sbatch`` on a compute node (no network). Reads the corpus fetched by ``iac_fetch.sh``, scans it with
``kestrix_scan``, runs zizmor (MIT), hadolint (GPL-3.0, as an external program) and checkov (Apache-2.0) on the same files, and
writes two files under ``--out``: ``iac-aggregate.json`` (counts and rates only, safe to commit) and ``iac-samples.jsonl``
(a seeded sample of findings with path, line and snippet, which stays on the cluster for reading).
"""

from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

from kestrix_scan.analyze import scan_text
from kestrix_scan.ci_rules import _UNTRUSTED
from kestrix_scan.iac import iac_kind
from kestrix_scan.registry import RULES
from kestrix_scan.walk import Candidate

IAC_LANGS = {"github-actions", "dockerfile", "shell", "terraform", "kubernetes"}
APPLIES = {  # rule family -> kinds of file whose lines are the denominator
    "gha": ("workflow",),
    "docker": ("dockerfile",),
    "sh": ("shell", "workflow", "dockerfile"),
    "tf": ("terraform",),
    "k8s": ("kubernetes",),
}
# (label, kestrix rule ids, tool, tool check ids)
MAPPINGS = [
    ("template injection (all zizmor findings)", ["gha.injection.untrusted_context"], "zizmor", ["template-injection"]),
    (
        "template injection (zizmor findings on github.event.* and head_ref)",
        ["gha.injection.untrusted_context"],
        "zizmor:event",
        ["template-injection"],
    ),
    ("unpinned third-party actions", ["gha.action.unpinned"], "zizmor:third-party", ["unpinned-uses"]),
    ("dangerous triggers", ["gha.pr_target.checkout_head"], "zizmor", ["dangerous-triggers"]),
    (
        "workflow permissions",
        ["gha.permissions.write_all", "gha.permissions.missing"],
        "zizmor",
        ["excessive-permissions"],
    ),
    ("final user root", ["docker.user.root"], "hadolint", ["DL3002"]),
    ("latest or untagged base", ["docker.from.latest"], "hadolint", ["DL3007", "DL3006"]),
    ("final user root (checkov)", ["docker.user.root"], "checkov", ["CKV_DOCKER_3", "CKV_DOCKER_8"]),
    ("latest tag (checkov)", ["docker.from.latest"], "checkov", ["CKV_DOCKER_7"]),
    ("privileged pod", ["k8s.pod.privileged"], "checkov", ["CKV_K8S_16"]),
    ("privilege escalation", ["k8s.pod.privilege_escalation"], "checkov", ["CKV_K8S_20"]),
    ("host namespace", ["k8s.pod.host_namespace"], "checkov", ["CKV_K8S_19", "CKV_K8S_17", "CKV_K8S_18"]),
    (
        "run as root",
        ["k8s.pod.run_as_root", "k8s.pod.no_run_as_nonroot"],
        "checkov",
        ["CKV_K8S_6", "CKV_K8S_23", "CKV_K8S_40"],
    ),
    ("hostPath", ["k8s.pod.host_path"], "checkov", ["CKV_K8S_27"]),
    (
        "open admin port",
        ["tf.sg.open_admin_port"],
        "checkov",
        ["CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_260", "CKV_AWS_277"],
    ),
    (
        "public bucket",
        ["tf.s3.public_access"],
        "checkov",
        ["CKV_AWS_20", "CKV_AWS_57", "CKV_AWS_53", "CKV_AWS_54", "CKV_AWS_55", "CKV_AWS_56"],
    ),
    (
        "unencrypted storage",
        ["tf.storage.unencrypted"],
        "checkov",
        ["CKV_AWS_3", "CKV_AWS_16", "CKV_AWS_8", "CKV_AWS_17"],
    ),
]


def run(cmd: list[str], timeout: int = 3600) -> tuple[int, str]:
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
    return out.returncode, out.stdout


def kestrix_pass(
    corpus: Path,
) -> tuple[list[dict[str, Any]], Counter[str], Counter[str], dict[str, int], float, Counter[str]]:
    active = frozenset(rid for rid, rule in RULES.items() if rule.language in IAC_LANGS)
    findings: list[dict[str, Any]] = []
    kinds: Counter[str] = Counter()
    lines: Counter[str] = Counter()
    skips: Counter[str] = Counter()
    per_file: dict[str, int] = {}
    started = time.perf_counter()
    for path in sorted(p for p in corpus.rglob("*") if p.is_file()):
        rel = path.relative_to(corpus).as_posix()
        try:
            text = path.read_bytes()[:1_048_576].decode("utf-8", "replace")
        except OSError:
            continue
        kind = iac_kind(rel.split("/", 1)[1] if "/" in rel else rel, text)
        if kind is None:
            continue
        kinds[kind] += 1
        lines[kind] += text.count("\n") + 1
        repo_rel = rel.split("/", 1)[1]
        got, _, _, skip = scan_text(text, Candidate(path=path, rel=repo_rel), active)
        if skip is not None:
            skips[f"{kind}:{skip.reason}"] += 1
        per_file[rel] = len(got)
        src = text.splitlines()
        for f in got:
            findings.append(
                {
                    "rule": f.rule_id,
                    "kind": kind,
                    "file": rel,
                    "line": f.line,
                    "severity": f.severity,
                    "snippet": src[f.line - 1].strip()[:160] if 0 < f.line <= len(src) else "",
                }
            )
    return findings, kinds, lines, per_file, time.perf_counter() - started, skips


def zizmor(tool: Path, corpus: Path) -> list[dict[str, Any]]:
    """zizmor's findings (auditor persona: every audit, false positives allowed), one run per repository directory."""
    rows: list[dict[str, Any]] = []
    for repo in sorted(p.name for p in corpus.iterdir() if p.is_dir()):
        if not any((corpus / repo).rglob("*.y*ml")):
            continue
        out = subprocess.run(  # noqa: S603
            [
                str(tool / "venv/bin/zizmor"),
                "--offline",
                "--format",
                "json",
                "--no-exit-codes",
                "--collect",
                "all",
                "--persona",
                "auditor",
                repo,
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
            cwd=corpus,
        ).stdout
        try:
            data = json.loads(out)
        except ValueError:
            continue
        for item in data if isinstance(data, list) else []:
            locations = item.get("locations", [])
            loc = next(
                (x for x in locations if x.get("symbolic", {}).get("primary")), locations[0] if locations else {}
            )
            key = (loc.get("symbolic", {}).get("key") or {}).get("Local", {})
            concrete = loc.get("concrete", {})
            row = (concrete.get("location", {}).get("start_point") or {}).get("row")
            rows.append(
                {
                    "id": item.get("ident"),
                    "file": str(key.get("given_path") or ""),
                    "line": (row or 0) + 1,
                    "feature": str(concrete.get("feature", ""))[:300],
                    "annotation": str(loc.get("symbolic", {}).get("annotation", ""))[:200],
                }
            )
    return rows


def hadolint(tool: Path, files: list[Path], corpus: Path) -> list[dict[str, Any]]:
    rows = []
    for path in files:
        _, out = run([str(tool / "hadolint"), "--no-fail", "--format", "json", str(path)], timeout=120)
        try:
            data = json.loads(out)
        except ValueError:
            continue
        rows.extend(
            {"id": d.get("code"), "file": path.relative_to(corpus).as_posix(), "line": d.get("line", 0)} for d in data
        )
    return rows


def checkov(tool: Path, corpus: Path) -> list[dict[str, Any]]:
    env_cmd = [
        str(tool / "venv/bin/checkov"),
        "-d",
        str(corpus),
        "--framework",
        "terraform",
        "kubernetes",
        "dockerfile",
        "--compact",
        "--quiet",
        "--skip-download",
        "-o",
        "json",
        "--soft-fail",
    ]
    _, out = run(env_cmd)
    try:
        data = json.loads(out)
    except ValueError:
        return []
    reports = data if isinstance(data, list) else [data]
    rows = []
    for report in reports:
        for check in (report.get("results") or {}).get("failed_checks", []):
            rng = check.get("file_line_range") or [0, 0]
            rows.append(
                {
                    "id": check.get("check_id"),
                    "file": str(check.get("file_path", "")).lstrip("/"),
                    "start": rng[0],
                    "end": rng[1],
                }
            )
    return rows


_FIRST_PARTY = re.compile(r"uses:\s*['\"]?(?:actions|github)/")


def tool_subset(rows: list[dict[str, Any]], variant: str) -> list[dict[str, Any]]:
    """The tool findings comparable with a Kestrix rule: ``event`` keeps template injections whose expanded context is one of the
    untrusted fields in the GitHub hardening guide (the list ``gha.injection.untrusted_context`` uses), ``third-party`` drops unpinned actions/* and github/* (Kestrix does not report those)."""
    if variant == "event":
        return [r for r in rows if _UNTRUSTED.search(r.get("annotation", ""))]
    if variant == "third-party":
        return [r for r in rows if not _FIRST_PARTY.search(r.get("feature", ""))]
    return rows


def overlap(
    kestrix: list[dict[str, Any]],
    tool_rows: list[dict[str, Any]],
    rules: list[str],
    ids: list[str],
    files_scanned: set[str],
) -> dict[str, Any]:
    k = [f for f in kestrix if f["rule"] in rules]
    t = [r for r in tool_rows if r["id"] in ids and r["file"] in files_scanned]
    k_files, t_files = {f["file"] for f in k}, {r["file"] for r in t}

    def near(f: dict[str, Any]) -> bool:
        for r in t:
            if r["file"] != f["file"]:
                continue
            lo, hi = r.get("start", r.get("line", 0)), r.get("end", r.get("line", 0))
            if lo - 2 <= f["line"] <= hi + 2:
                return True
        return False

    return {
        "kestrix_findings": len(k),
        "tool_findings": len(t),
        "kestrix_files": len(k_files),
        "tool_files": len(t_files),
        "both_files": len(k_files & t_files),
        "kestrix_findings_matched_by_tool": sum(1 for f in k if near(f)),
        "only_kestrix_files_sample": sorted(k_files - t_files)[:25],
        "only_tool_files_sample": sorted(t_files - k_files)[:25],
    }


def measure(
    name: str, corpus: Path, tools: Path, with_tools: bool, only: str | None = None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings, kinds, lines, per_file, seconds, skips = kestrix_pass(corpus)
    repos = {p.name for p in corpus.iterdir() if p.is_dir()}
    by_rule: dict[str, dict[str, Any]] = {}
    for rid, rule in RULES.items():
        if rule.language not in IAC_LANGS:
            continue
        loc = sum(lines[k] for k in APPLIES[rid.split(".")[0]])
        mine = [f for f in findings if f["rule"] == rid]
        by_rule[rid] = {
            "findings": len(mine),
            "files": len({f["file"] for f in mine}),
            "repos": len({f["file"].split("/")[0] for f in mine}),
            "per_kloc": round(1000 * len(mine) / loc, 3) if loc else None,
            "kloc": round(loc / 1000, 1),
            "severity": rule.severity,
        }
    aggregate: dict[str, Any] = {
        "name": name,
        "repos_with_files": len(repos),
        "files_by_kind": dict(kinds),
        "kloc_by_kind": {k: round(v / 1000, 1) for k, v in lines.items()},
        "skips": dict(skips),
        "files_with_findings": sum(1 for n in per_file.values() if n),
        "files_scanned": len(per_file),
        "scan_seconds": round(seconds, 2),
        "files_per_second": round(len(per_file) / seconds, 1) if seconds else None,
        "rules": by_rule,
    }
    if with_tools:
        scanned = set(per_file)
        docker_files = [
            p
            for p in corpus.rglob("*")
            if p.is_file() and iac_kind(p.relative_to(corpus).as_posix().split("/", 1)[-1]) == "dockerfile"
        ]
        tool_rows = {
            "zizmor": zizmor(tools, corpus) if only in (None, "zizmor") else [],
            "hadolint": hadolint(tools, docker_files, corpus) if only in (None, "hadolint") else [],
            "checkov": checkov(tools, corpus) if only in (None, "checkov") else [],
        }
        aggregate["tool_findings"] = {
            t: dict(Counter(r["id"] for r in rows).most_common(25)) for t, rows in tool_rows.items()
        }
        aggregate["tool_totals"] = {t: len(rows) for t, rows in tool_rows.items()}
        aggregate["agreement"] = [
            {
                "label": label,
                "tool": tool.split(":")[0],
                "kestrix_rules": rules,
                "tool_checks": ids,
                **overlap(
                    findings, tool_subset(tool_rows[tool.split(":")[0]], tool.partition(":")[2]), rules, ids, scanned
                ),
            }
            for label, rules, tool, ids in MAPPINGS
        ]
    rng = random.Random(20261023)  # noqa: S311 - a seeded sample, not security
    samples = []
    for rid in by_rule:
        mine = [dict(f, corpus=name) for f in findings if f["rule"] == rid]
        rng.shuffle(mine)
        samples.extend(mine[:30])
    return aggregate, samples


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", type=str, action="append", required=True, help="NAME=DIR, repeatable")
    ap.add_argument("--tools", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--no-tools", action="store_true")
    ap.add_argument("--only-tool", choices=("zizmor", "hadolint", "checkov"), help="run just this comparison tool")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {}
    all_samples: list[dict[str, Any]] = []
    for spec in args.corpus:
        name, _, directory = str(spec).partition("=")
        if not directory or not Path(directory).is_dir():
            continue
        result[name], samples = measure(name, Path(directory), args.tools, not args.no_tools, args.only_tool)
        all_samples.extend(samples)
    detail = {
        name: [{k: v for k, v in a.items() if k.startswith(("label", "only_"))} for a in section.get("agreement", [])]
        for name, section in result.items()
    }
    for section in result.values():
        for a in section.get("agreement", []):
            a.pop("only_kestrix_files_sample", None)
            a.pop("only_tool_files_sample", None)
    (args.out / "iac-agreement-detail.json").write_text(json.dumps(detail, indent=1) + "\n", encoding="utf-8")
    (args.out / "iac-aggregate.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    with (args.out / "iac-samples.jsonl").open("w", encoding="utf-8") as handle:
        for item in all_samples:
            handle.write(json.dumps(item) + "\n")
    print(
        json.dumps(
            {
                k: {x: v[x] for x in ("repos_with_files", "files_by_kind", "files_scanned", "scan_seconds")}
                for k, v in result.items()
            }
        )
    )


if __name__ == "__main__":
    sys.exit(main())
