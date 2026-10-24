# Claude Code session workflow

## One slice per implementation session

A session implements one reviewable slice. It does not build the
platform, span several slices, or touch paths outside the slice plan.

Canonical sequence (example: a Sigma parser change):

```text
/kx-repo-audit
/kx-sigma-adapter supported subset
/kx-security-review changed parser and upload paths
/kx-documentation support matrix
```

1. Start in plan mode (`claude --permission-mode plan`). Read `CLAUDE.md`, `.claude/handoff.md`
   and the relevant ADRs.
2. Run `/kx-repo-audit` when the checkout is new; otherwise skim the handoff.
3. Agree changed paths, contracts, failure states, tests and commands before editing.
4. Switch to the permission mode appropriate for normal development and implement only
   the agreed slice using the task skill (e.g. `/kx-sigma-adapter`).
5. Run the actual commands from real files. Do not assume a Makefile target exists.
6. Run `/kx-security-review` on changed input boundaries, routes or connectors.
   Optionally pass the gathered evidence to a read-only reviewer agent
   (`architecture-reviewer`, `detection-semantics-reviewer`, `ml-evaluation-reviewer`,
   `appsec-reviewer`). Reviewers cannot run code; the main session supplies output.
7. Run `/kx-documentation` to update the support matrix, docs and handoff.
8. Review the diff and command output yourself, then commit the verified change.

Sequential development is the default. If parallel agents are used later, give each
separate files or a separate worktree and name one integration owner.

## Session handoff procedure

Before ending a session, update `.claude/handoff.md`:

- Current git SHA (`git rev-parse HEAD`) and whether the tree is clean.
- Completed slice, and anything left partially done.
- Commands actually run, with pass/fail. Commands not run are listed as not run.
- Failed or skipped checks and why (e.g. Elasticsearch container unavailable).
- Artifact IDs and hashes produced (dataset versions, validation runs, evidence bundles).
- The single next action.

Keep detailed history in git; keep `CLAUDE.md` short. A new session begins by reading
the handoff.

## After editing the Claude setup

Run `/kx-skill-audit`, `python3 scripts/check_claude_pack.py` and
`python3 .claude/hooks/test_protect_paths.py`. Review permission changes like code.
