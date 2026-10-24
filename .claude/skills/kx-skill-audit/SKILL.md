---
name: kx-skill-audit
description: Audit the Kestrix Claude setup - skills, agents, rules, settings.json and the protected path hook - for structure, triggering behavior and permission changes. Use after editing anything under .claude/, CLAUDE.md or docs/claude/. Do not use to review application code, and do not let it approve its own expected results.
---

# Claude project setup audit

Plan refs: sections 16 (Claude development boundary), 20, 21, 22 (hooks and MCP), 23 (skill verification protocol).

## Expected inputs

- The diff under `.claude/`, `CLAUDE.md`, `scripts/check_claude_pack.py`.
- `.claude/skill_validation_cases.md`.

## Steps

1. Run `python3 scripts/check_claude_pack.py` and `python3 .claude/hooks/test_protect_paths.py`; record real output.
2. Confirm every `kx-*` skill, each with name matching its directory and a specific description stating when to use and when not.
3. Confirm no skill adds `allowed-tools` that widen Bash or network access, and agents keep only Read, Glob, Grep.
4. Review `settings.json` permission changes like code: deny rules for `.env*`, `*.pem`, `data/raw/**`, `data/locked/**`, `**/secrets/**` remain; no model pinned; no MCP servers enabled without a documented need.
5. For changed skills, walk the positive, negative and adversarial cases in `skill_validation_cases.md`. Update cases when behavior intentionally changes; never weaken an adversarial expectation to make it pass.
6. In a real session (user-run): check the slash menu, `/status` settings sources, and a harmless hook probe against a synthetic protected path. Record the CLI version.

## Output evidence

- Validator and hook test output, list of checked cases, any runtime checks the user ran (or a note that none were run).

## Failure conditions (stop and report)

- A change widens permissions, disables the hook or removes deny rules without a documented reason.
- Structural validation is presented as proof of runtime invocation.
