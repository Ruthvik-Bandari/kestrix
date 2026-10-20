# Changelog

All notable changes to the Kestrix plugin for Claude Code. The plugin's version is the `version` in
`.claude-plugin/plugin.json` and matches the `kestrix-scan` release it was built from.

## 0.1.0

First public release.

- Hooks: `PreToolUse` snapshots each file before Claude changes it; `PostToolUse` scans the changed file with the
  local `kestrix-scan` and returns only the medium-or-worse findings the edit introduced; an install guard on `Bash`
  denies installing packages that the local OSV index reports as malicious; an opt-in `Stop` gate blocks finishing
  while new high or critical findings remain (at most 3 times); `SessionStart` reports that the hooks are active.
- Commands: `/kestrix:scan`, `/kestrix:fix`, `/kestrix:review`.
- Skills: `secure-code-review`, `fixing-security-findings` (generated from the rule registry), `kestrix-security`.
- Every hook fails open, opens no network connection and installs nothing (`tests/test_no_network.py`).
- A `claude plugin eval` suite in `evals/`.
