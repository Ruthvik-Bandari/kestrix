#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Structural validator for the Kestrix Claude Code setup (.claude/).

Checks structure and template invariants only: the kx-* skill directories and
their frontmatter, read-only reviewer agents, path-scoped rules, settings.json and
its hook reference, and the workflow docs. It does NOT emulate Claude's
runtime: passing here does not prove that skills trigger, that permissions are
enforced, or that the hook runs inside a real Claude Code session.

Usage: python3 scripts/check_claude_pack.py   (exit 0 = pass, 1 = failures)
Stdlib only; uses a minimal frontmatter reader, not a full YAML parser.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLAUDE = ROOT / ".claude"

SKILLS = [
    "kx-repo-audit",
    "kx-schema-contract",
    "kx-sigma-adapter",
    "kx-replay-harness",
    "kx-repair-baselines",
    "kx-benchmark-design",
    "kx-platform-integration",
    "kx-security-review",
    "kx-documentation",
    "kx-skill-audit",
]
SKILL_SECTIONS = ["Expected inputs", "Steps", "Output evidence", "Failure conditions"]
AGENTS = ["architecture-reviewer", "detection-semantics-reviewer", "ml-evaluation-reviewer", "appsec-reviewer"]
ALLOWED_AGENT_TOOLS = {"Read", "Glob", "Grep"}
RULES = {"python": "src/kestrix/**/*.py", "ui": "frontend/**", "backend": "src/kestrix/server/**"}
REQUIRED_DENY = ["**/.env", "**/.env.*", "**/*.pem", "data/raw/**", "data/locked/**", "**/secrets/**"]
DOCS = [
    "CLAUDE.md",
    ".claude/handoff.md",
    ".claude/workflow.md",
    ".claude/skill_validation_cases.md",
    ".claude/hooks/test_protect_paths.py",
]

results: list[tuple[bool, str]] = []


def check(ok: bool, msg: str) -> bool:
    results.append((bool(ok), msg))
    return bool(ok)


def frontmatter(path: Path) -> tuple[dict, str] | None:
    """Return (fields, body). Scalars as str, block lists ("- x") as list[str]."""
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if not m:
        return None
    fields: dict = {}
    key = None
    for line in m.group(1).splitlines():
        if not line.strip():
            continue
        item = re.match(r"^\s+-\s+(.*)$", line)
        if item and key is not None:
            if not isinstance(fields.get(key), list):
                fields[key] = []
            fields[key].append(item.group(1).strip().strip("\"'"))
            continue
        kv = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if not kv:
            return None
        key, val = kv.group(1), kv.group(2).strip()
        fields[key] = val.strip("\"'") if val else []
    return fields, m.group(2)


def check_skills() -> None:
    skill_root = CLAUDE / "skills"
    present = sorted(p.name for p in skill_root.iterdir() if p.is_dir()) if skill_root.is_dir() else []
    check(
        set(SKILLS) <= set(present),
        f"all {len(SKILLS)} skill directories present ({len(set(SKILLS) & set(present))}/{len(SKILLS)})",
    )
    extra = sorted(set(present) - set(SKILLS))
    check(not extra, f"no unexpected skill directories {extra if extra else ''}".rstrip())
    for name in SKILLS:
        f = skill_root / name / "SKILL.md"
        if not check(f.is_file(), f"{name}: SKILL.md exists"):
            continue
        parsed = frontmatter(f)
        if not check(parsed is not None, f"{name}: frontmatter parses"):
            continue
        fm, body = parsed
        check(fm.get("name") == name, f"{name}: frontmatter name matches directory")
        desc = fm.get("description")
        check(isinstance(desc, str) and len(desc) >= 40, f"{name}: description non-empty and specific")
        check("allowed-tools" not in fm, f"{name}: no allowed-tools widening access")
        dmi = str(fm.get("disable-model-invocation", "")).lower()
        check(dmi in ("", "false"), f"{name}: model invocation not disabled")
        missing = [s for s in SKILL_SECTIONS if not re.search(rf"^##\s+{re.escape(s)}", body, re.M)]
        check(
            not missing,
            f"{name}: body has required sections {'(missing ' + ', '.join(missing) + ')' if missing else ''}".rstrip(),
        )
        check("Plan refs" in body, f"{name}: cites plan sections")


def check_agents() -> None:
    for name in AGENTS:
        f = CLAUDE / "agents" / f"{name}.md"
        if not check(f.is_file(), f"agent {name}: file exists"):
            continue
        parsed = frontmatter(f)
        if not check(parsed is not None, f"agent {name}: frontmatter parses"):
            continue
        fm, _ = parsed
        check(fm.get("name") == name, f"agent {name}: name matches file")
        check(bool(fm.get("description")), f"agent {name}: description present")
        tools = fm.get("tools", "")
        tool_set = {t.strip() for t in (tools if isinstance(tools, list) else str(tools).split(",")) if t.strip()}
        check(
            tool_set and tool_set <= ALLOWED_AGENT_TOOLS,
            f"agent {name}: tools limited to Read, Glob, Grep ({sorted(tool_set)})",
        )


def check_rules() -> None:
    for name, glob in RULES.items():
        f = CLAUDE / "rules" / f"{name}.md"
        if not check(f.is_file(), f"rule {name}.md exists"):
            continue
        parsed = frontmatter(f)
        paths = parsed[0].get("paths") if parsed else None
        paths = paths if isinstance(paths, list) else ([paths] if paths else [])
        check(glob in paths, f"rule {name}.md has paths frontmatter including {glob}")


def check_settings() -> None:
    f = CLAUDE / "settings.json"
    if not check(f.is_file(), "settings.json exists"):
        return
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except ValueError as exc:
        check(False, f"settings.json parses ({exc})")
        return
    check(True, "settings.json parses")
    check("model" not in data, "settings.json does not pin a model")
    check(
        not data.get("enableAllProjectMcpServers") and "mcpServers" not in data, "settings.json enables no MCP servers"
    )
    deny = data.get("permissions", {}).get("deny", [])
    for tool in ("Read", "Edit", "Write"):
        missing = [p for p in REQUIRED_DENY if f"{tool}({p})" not in deny]
        check(not missing, f"settings.json denies {tool} on protected paths {missing if missing else ''}".rstrip())
    allow = data.get("permissions", {}).get("allow", [])
    check(
        not any(a in ("Bash", "Bash(*)", "WebFetch", "WebSearch") for a in allow),
        "settings.json grants no blanket Bash/network",
    )
    hooks = data.get("hooks", {}).get("PreToolUse", [])
    matched = [
        h for h in hooks if set(h.get("matcher", "").split("|")) >= {"Write", "Edit", "MultiEdit", "NotebookEdit"}
    ]
    check(bool(matched), "PreToolUse hook matches Write|Edit|MultiEdit|NotebookEdit")
    found = False
    for h in matched:
        for cmd in h.get("hooks", []):
            m = re.search(r"\.claude/hooks/([A-Za-z0-9_]+\.py)", cmd.get("command", ""))
            if m and (CLAUDE / "hooks" / m.group(1)).is_file():
                found = True
    check(found, "hook command references an existing script in .claude/hooks/")


def check_docs() -> None:
    for rel in DOCS:
        check((ROOT / rel).is_file(), f"{rel} exists")
    claude_md = ROOT / "CLAUDE.md"
    if claude_md.is_file():
        n = len(claude_md.read_text(encoding="utf-8").splitlines())
        check(n < 80, f"CLAUDE.md is concise ({n} lines < 80)")
    cases = ROOT / ".claude/skill_validation_cases.md"
    if cases.is_file():
        text = cases.read_text(encoding="utf-8")
        missing = [s for s in SKILLS if f"## {s}" not in text]
        check(not missing, f"skill_validation_cases.md covers all skills {missing if missing else ''}".rstrip())


def main() -> int:
    check_skills()
    check_agents()
    check_rules()
    check_settings()
    check_docs()
    failed = [m for ok, m in results if not ok]
    for ok, msg in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {msg}")
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed. Structure only; Claude runtime not exercised.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
