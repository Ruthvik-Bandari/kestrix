# Privacy

The Kestrix plugin for Claude Code collects no data and sends none. This page lists what it reads, what it
writes, and where its output goes, and points to the test or the code behind each statement.

## What the plugin does not do

| Statement | Evidence |
| --- | --- |
| **No network connections from any hook.** None of the hooks (`SessionStart`, `PreToolUse` on file tools, `PreToolUse` on `Bash`, `PostToolUse` on file tools, `PostToolUse` and `PostToolUseFailure` on `Bash`, `Stop`) opens a socket, and neither does the `kestrix-scan` or `git` process they start. | [`tests/test_no_network.py`](tests/test_no_network.py) runs every hook the way Claude Code does, including the Bash hooks in a git repository, with socket creation, `create_connection` and `getaddrinfo` made to raise in the hook process and in every Python process it starts. It asserts that the findings still come back and that no socket was attempted. Run it with `python3 -m unittest discover -s tests -v`. The same check runs in the Kestrix source tree on every change (`packages/kestrix-scan/tests/test_no_network.py`). |
| **No telemetry, analytics, crash reports or update checks.** | The same test: any of these would need a socket. The hook script, [`hooks/kestrix_hook.py`](hooks/kestrix_hook.py), imports only the Python standard library and no networking module. |
| **No data collection, no account, no credentials.** The plugin declares no `userConfig` and reads no token or key from your environment. | [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json) has no `userConfig`. Besides `PATH` and the temporary-directory settings, the only environment variables the hook script reads are `CLAUDE_PLUGIN_DATA`, `CLAUDE_PROJECT_DIR`, `KESTRIX_BLOCK_ON_STOP` and `KESTRIX_INSTALL_GUARD`. |
| **No installs.** No hook runs `pip`, `npm`, `uvx`, `npx` or any other installer or package launcher. | [`hooks/hooks.json`](hooks/hooks.json) runs only `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/kestrix_hook.py" <event>`. The script starts only the `kestrix-scan` (or `kestrix`) executable already on your PATH, never one inside the project directory. |

## What it reads and writes, all on your machine

- **Reads:** the hook JSON Claude Code passes on stdin; the file Claude is about to change or just changed (up to
  1 MiB); after a Bash command, the output of `git rev-parse`, `git status` and `git show HEAD:<file>` (run locally,
  with `core.fsmonitor` and `core.hooksPath` turned off) and the modification times of the files `git status` lists;
  the project's `.kestrix.json` and `[tool.kestrix]` settings; and, for the install guard, the local OSV
  index if you built one.
- **Writes:** only to the plugin's data directory, `${CLAUDE_PLUGIN_DATA}/sessions/<session id>/`, which Claude Code
  deletes when you uninstall the plugin. When that variable is not set, it uses a private directory,
  `<temp>/kestrix-claude-<uid>/`, with mode 0700. For each session it keeps the list of changed file paths, a copy
  of each changed file from before the session first touched it (for a file changed by a Bash command, its `HEAD`
  version), a short-lived copy from just before the current change, the time each running Bash command started,
  the Stop gate's block count, and an event log (`events.tsv`) of scan counts and the paths of files that could not
  be scanned, which `/kestrix:status` reads. Session directories older than 14 days are removed at the next session
  start.
- **Never:** reads or prints secret values. For a hard-coded secret, findings show only the kind, the location and
  the first four characters.

## Where the hook output goes

What a hook prints goes back to Claude Code, which adds it to your conversation like any tool result, so it is
handled under the terms of your Claude plan: findings are sent to Anthropic like any other conversation content. It
holds rule ids, CWE ids, file paths, line numbers, messages and fixes, and no code beyond what Claude already
wrote. A "not security-checked" notice holds the paths of the files that were not scanned. Secret values are never
included: a finding for a hard-coded secret shows only its kind, its location and its first four characters.

## The one network command

`kestrix-scan db update`, which you run yourself, downloads the public OSV advisory exports for PyPI and npm from
`https://storage.googleapis.com/osv-vulnerabilities/` into your cache directory. It sends nothing about your code.
No hook or skill runs it.

The optional `kestrix-security` skill can ask Claude to run commands of the separate Kestrix workbench that reach
the network when you ask for them (a website check, a Bitcoin chain lookup, the Docker image for Sigma replay); the
[README](README.md#the-one-network-action-kestrix-scan-db-update) lists them.

## Contact

Questions about privacy: open an issue in this repository. Security reports: see [SECURITY.md](SECURITY.md).
