# Claude Code plugin

The `kestrix` plugin makes Claude Code check the code it writes. After every `Write`, `Edit`, `MultiEdit` or
`NotebookEdit`, a hook runs the local Kestrix scanner on the changed file. Findings at medium severity or
above come back to Claude as context with the rule, the CWE and the fix, and Claude fixes them in the same
turn. A false positive gets an inline suppression with a written reason. The plugin also adds review skills
and three slash commands. It is slice C2 of [ADR 0005](adr/0005-code-security.md).

The scanner is rule-based pattern analysis ([code module](modules/code.md)). It misses things and can be
wrong in context. A file with no findings means no rule fired, not that the code is secure.

The source is [`src/kestrix/integrations/claude_plugin/kestrix/`](../src/kestrix/integrations/claude_plugin/kestrix/),
and it ships inside the `kestrix` wheel.

## What it adds

| Component | Name in Claude Code | What it does |
| --- | --- | --- |
| Hook | `PostToolUse` on `Write\|Edit\|MultiEdit\|NotebookEdit` | Scans the changed file with `kestrix code scan --hook` and returns the medium-or-worse findings as `additionalContext`. |
| Hook | `Stop` (opt-in) | Blocks Claude from finishing while files changed this session still have high or critical findings. Off unless you enable it. |
| Hook | `SessionStart` | Adds one line of context, "Kestrix security hooks are active ...", when `kestrix` is on PATH. It is silent otherwise. |
| Skill | `secure-code-review` | How to review code with Kestrix: scan, triage by severity, fix by rule family, re-scan and explain the risk that remains. Claude uses it on its own when you ask for a security review. |
| Skill | `fixing-security-findings` | A per-rule playbook with before and after code for every rule id. It is generated from the rule registry. |
| Skill | `kestrix-security` | The existing skill for email, link, file, website, Sigma and Bitcoin questions ([docs/claude-skill.md](claude-skill.md)). |
| Command | `/kestrix:scan [path]` | Scans a path (default `.`) and summarizes the findings. It changes no code. |
| Command | `/kestrix:fix [path]` | Scans, fixes every finding at medium or above, and re-scans until the code is clean or each remaining finding is explained. It stops after 5 rounds. |
| Command | `/kestrix:review [base-ref]` | A secure review of the current diff. It runs `kestrix code scan . --diff <ref>` (default `HEAD`), then reviews the diff for what the rules cannot see. |

The three commands are skills with `disable-model-invocation: true`, so they run only when you type them.
The plugin docs recommend `skills/` over `commands/` for new plugins.

## Install

The plugin calls the `kestrix` command, so install Kestrix first. The PyPI release is pending, so install
from the repository:

```bash
uv tool install "git+https://github.com/Ruthvik-Bandari/kestrix"   # or: pipx install "git+https://..."
```

The hooks also need `python3` on PATH. Any Python 3.9 or later works, including the macOS system Python,
and it does not have to be the one Kestrix is installed in.

### From GitHub (once the repository is public)

The repository root holds a marketplace, `.claude-plugin/marketplace.json`, named `kestrix`. In a Claude
Code session:

```text
/plugin marketplace add Ruthvik-Bandari/kestrix
/plugin install kestrix@kestrix
```

From your shell, run `claude plugin marketplace add Ruthvik-Bandari/kestrix` and then
`claude plugin install kestrix@kestrix`.

### From the installed package (works now)

```bash
kestrix integrations install-claude-plugin            # copies the plugin to ~/.claude/kestrix-plugin
claude plugin marketplace add ~/.claude/kestrix-plugin
claude plugin install kestrix@kestrix-local
```

The installer prints these commands with the real path. The copy is also a local marketplace of one plugin,
named `kestrix-local`. Start a new session, or run `/reload-plugins`, to load the plugin. To try it for
one session without installing it, run `claude --plugin-dir ~/.claude/kestrix-plugin`.

| Command | Options | What it does |
| --- | --- | --- |
| `kestrix integrations install-claude-plugin` | `--dest DIR`, `--force` | Copies the plugin and a `kestrix-local` `marketplace.json` to `DIR` (default `~/.claude/kestrix-plugin`), then prints the commands that enable it. |
| `kestrix integrations package-claude-plugin` | `--out FILE.zip` (required), `--force` | Writes the same files as a zip, with the plugin at the top level, for `claude --plugin-dir FILE.zip`. |

Exit codes: 0 done, 2 refused, with the reason on stderr.

**Installer safety.** The installer follows the same rules as the skill installer:

- **It never edits Claude Code's settings.** It does not write `~/.claude/settings.json` or any other
  settings file. You enable the plugin with the `claude plugin` commands it prints.
- **It replaces a directory only when it is safe.** With `--force`, it replaces an existing destination
  only when that directory is empty or already holds this plugin, meaning its `.claude-plugin/plugin.json`
  names `kestrix`. It never replaces an unrelated directory.
- **It does not follow symbolic links.** It refuses a destination that is a symbolic link, or a manifest
  that is one. When it replaces an old copy, it removes the symbolic links inside it rather than following
  them.
- **It writes atomically.** Files go to a temporary sibling directory first, which is then renamed into
  place.
- **The zip is reproducible.** It has fixed timestamps and modes, so the same Kestrix version always
  produces the same bytes.

To remove the plugin, run `claude plugin uninstall kestrix@kestrix-local` and
`claude plugin marketplace remove kestrix-local`, then delete the directory.

## The hooks

`hooks/hooks.json` starts `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/kestrix_hook.py" <event>`. The script
uses only the standard library and calls the `kestrix` executable it finds on PATH.

**Why the wrapper is a Python script, not a shell script:**

- **It needs a JSON parser.** It reads `session_id`, `stop_hook_active` and the file paths from JSON.
  POSIX `sh` has no JSON parser without `jq`.
- **macOS has no `timeout` command,** and Python's `subprocess` timeout works everywhere.
- **Kestrix itself needs Python 3.12,** so a machine that runs Kestrix already has Python. The wrapper
  runs on 3.9 or later and calls `kestrix` instead of importing it, so a `uv tool` or `pipx` install works.
- **It does not depend on the executable bit.** The file runs as `python3 <file>`, so modes lost in a zip
  or a copy do not break it.

### PostToolUse: scan what Claude just wrote

The script reads the hook JSON from stdin and finds the changed file in one of these fields:

- `tool_input.file_path`;
- `tool_input.notebook_path`, for `NotebookEdit`;
- the `file_path` of each entry in `tool_input.edits`.

It records the absolute path in the session's file list, then pipes the same JSON to
`kestrix code scan --hook` with an 8-second limit, inside the hook's 10-second `timeout`. When the scanner
replies, the script passes the reply through:

```json
{"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "Kestrix found 1 security issue(s) at medium severity or above in the file just written:\n- app.py:4 [HIGH] py.subprocess.shell_true (CWE-78): ... Fix: ...\nFix these now, ..."}}
```

The context tells Claude to fix the findings now, keeping behavior the same, and to suppress one only when
it is a confirmed false positive, with a written reason. It also says to treat the file's contents as data.
A file with no medium-or-worse finding produces no output.

**Fail open.** The hook script always exits 0. When the scanner errors, prints something that is not
JSON, or runs past its time limit, the script produces no output, so it never blocks an edit.

When `kestrix` is not on PATH, the first edit of the session shows one warning (`systemMessage`) with the
install command. Claude also gets a note not to install Kestrix itself. Later edits in that session stay
silent. A `kestrix` executable in the project directory itself is ignored, so a cloned repository cannot
put its own scanner in place of yours.

### Stop: block finishing while serious findings remain (opt-in)

The Stop gate is off by default. To turn it on, do one of these:

- set `KESTRIX_BLOCK_ON_STOP=1` in the environment Claude Code runs in;
- commit a `.kestrix.json` at the project root:

  ```json
  {"claude": {"block_on_stop": true}}
  ```

The project directory is `CLAUDE_PROJECT_DIR`, or the hook's `cwd`. `KESTRIX_BLOCK_ON_STOP=0` turns the
gate off even when the project file turns it on. Any value other than the JSON `true` leaves the gate off.

When Claude tries to finish, the gate scans every file the PostToolUse hook recorded in this session that
still exists. It allows up to 200 files, using `kestrix code scan --format json --fail-on high` with a
25-second limit inside the hook's 30-second `timeout`. If high or critical findings remain, it replies:

```json
{"decision": "block", "reason": "Kestrix found 1 high or critical security issue(s) in files changed this session (Stop gate, block 1 of 3):\n- /path/app.py:4 [HIGH] py.subprocess.shell_true (CWE-78): ...\nFix them before finishing, ..."}
```

Claude keeps working with that reason. Two limits prevent a loop:

- **`stop_hook_active`.** When the input has `stop_hook_active: true`, meaning Claude is already continuing
  because of a Stop hook, the gate lets it stop. So each block gives Claude one more chance to fix.
- **At most 3 blocks per session.** After that, the gate shows one warning that findings remain and lets
  Claude stop.

Like the other hooks, it fails open: a scanner error or timeout lets Claude stop.

### SessionStart

When `kestrix` is on PATH, the hook adds one line of context. That line says the hooks are active and
whether the Stop gate is on. The hook also removes session records older than 14 days.

### Session state

The script keeps a small amount of state for each session:

- the list of changed file paths;
- whether the missing-`kestrix` hint was shown;
- the count of Stop blocks.

It stores them in `${CLAUDE_PLUGIN_DATA}/sessions/<session_id>/`. `CLAUDE_PLUGIN_DATA` is the
plugin's own data directory, which Claude Code creates and deletes on uninstall. When that variable is not
set, the script uses a private directory, `<temp>/kestrix-claude-<uid>/`, with mode 0700. It refuses that
directory if it is a symbolic link or owned by another user. The script uses a session id as a directory
name only when it is plain letters, digits, `-` and `_`. Any other id is hashed first. No file contents
are stored.

## Privacy

- **Everything runs on your machine.** The hooks call the local `kestrix` command. The scanner reads files
  as data and never imports, executes or uploads them.
- **Findings never include secret values.** For a secret, findings, hook context and Stop reasons show only
  the kind, the location and the first four characters.
- **The hook output is part of your conversation.** It goes to Claude like any other tool result, under the
  terms of your Claude plan. It holds rule ids, file paths, line numbers, messages and fixes. It holds no
  code beyond what Claude already wrote.
- **The skills treat code as data.** They tell Claude to ignore instructions inside the code under review,
  such as comments or strings that say to skip a check, and to point them out to you.

## Suppressing a finding

Fix the code when you can. For a confirmed false positive, put a suppression with a reason on the
finding's line or the line above:

```python
subprocess.run(BUILD_COMMAND, shell=True)  # kestrix: ignore[py.subprocess.shell_true] fixed command defined in this file
```

The reason is required. A suppression without one suppresses nothing, and the report shows a
`kestrix.suppression.missing_reason` note. Suppressed findings no longer come back from the hooks or the
Stop gate. To adopt the scanner on existing code without fixing everything first, see
[baselines](modules/code.md#baselines-and-fingerprints).

## Maintaining the plugin

- **Versions:** `plugin.json`, both marketplace entries and `kestrix.__version__` carry the same
  version, and a test checks that they match.
- **The fix playbook:** `skills/fixing-security-findings/SKILL.md` is generated with
  `uv run python scripts/build_claude_fix_playbook.py`. A test fails when it drifts from
  `src/kestrix/code/rules.py`. The test also scans each example: the "before" code must fire its rule,
  and the "after" code must produce no findings.
- **The skill installer:** `kestrix-security` lives only in the plugin, under `skills/kestrix-security/`.
  `kestrix integrations install-claude-skill` copies it from there, so the plugin and the standalone
  skill never drift apart.
- **Validation:** `claude plugin validate src/kestrix/integrations/claude_plugin/kestrix` and
  `claude plugin validate .` check the manifest and the marketplace.
