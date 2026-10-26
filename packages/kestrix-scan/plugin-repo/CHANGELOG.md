# Changelog

All notable changes to the Kestrix plugin for Claude Code. The plugin's version is the `version` in
`.claude-plugin/plugin.json` and matches the `kestrix-scan` release it was built from.

## 0.1.1

- When `kestrix-scan` is missing, the hint now says to install it from PyPI (`pip`, `pipx` or `uv tool`).
- Built from `kestrix-scan` 0.1.1, which fixes exponential backtracking in the install guard's Composer name pattern.

## 0.1.0

- A scan that could not run (`kestrix-scan` missing, timed out or crashed) is shown to you once per session for each
  cause, and Claude is told the file was not security-checked, instead of the hooks staying silent.
- Files changed by Bash commands are scanned in git repositories (`PostToolUse` and `PostToolUseFailure` on `Bash`).
- `/kestrix:status` shows the session's scans, findings and unchecked files.
- `secure-code-review` has a new description with concrete trigger phrases.
- README: a before / finding / after example, Coverage, an exact rule count, a first privacy paragraph, "Does it
  help?"; the A/B effectiveness eval in `evals/ab/` (not yet run).

First public release.

- Hooks: `PreToolUse` snapshots each file before Claude changes it; `PostToolUse` scans the changed file with the
  local `kestrix-scan` and returns only the medium-or-worse findings the edit introduced; an install guard on `Bash`
  denies installing packages that the local OSV index reports as malicious; an opt-in `Stop` gate blocks finishing
  while new high or critical findings remain (at most 3 times); `SessionStart` reports that the hooks are active.
- Commands: `/kestrix:scan`, `/kestrix:fix`, `/kestrix:review`.
- Skills: `secure-code-review`, `fixing-security-findings` (generated from the rule registry), `kestrix-security`.
- Every hook fails open, opens no network connection and installs nothing (`tests/test_no_network.py`).
- A `claude plugin eval` suite in `evals/`.
