# Demo prompts

Start Claude Code in the demo project built by `setup_demo.py` (see [README.md](README.md)), with the plugin
enabled. Give the prompts below in order, each as written.

## 0. Session start

No prompt. When the session starts, the plugin's `SessionStart` hook adds one line of context for Claude
(not shown in the transcript). The project's `.kestrix.json` turns the Stop gate on, so the line ends
`(Stop gate on)`:

[`expected/session-start.json`](expected/session-start.json)

To check that the plugin loaded, run `/plugin` and look for `kestrix` under installed plugins, or type `/kestrix:`
and see the three commands.

## 1. Scan the project

```text
/kestrix:scan
```

The command runs `kestrix-scan .` and Claude summarizes it. The scanner reports five findings: SQL built with an
f-string, `shell=True`, MD5, the fake GitHub token (shown only as `ghp_…`) and the `innerHTML` sink. The raw
scanner output is [`expected/scan.txt`](expected/scan.txt). The command changes no code.

## 2. Claude writes vulnerable code and the hook catches it

```text
Create export.py with this code, then tell me in one sentence what it does:

import os


def export_notes(name):
    os.system("cp notes.db exports/" + name)
```

After the `Write`, the `PostToolUse` hook scans `export.py` and gives Claude this context:
[`expected/post-tool-use.json`](expected/post-tool-use.json).

```text
Kestrix: this edit introduced 1 security issue(s) at medium severity or above:
- export.py:5 [HIGH] py.os.system (CWE-78): os.system runs a built command through the shell. — Fix: Use subprocess.run with a list of arguments and no shell, and check the return code.
Fix the new issues now, keeping behavior the same. ...
```

**Expected:** Claude edits `export.py` in the same turn, for example to `shutil.copy("notes.db", Path("exports") / name)`
or `subprocess.run(["cp", "notes.db", f"exports/{name}"], check=True)`. The hook scans that edit too and stays
silent, because the fix introduces nothing new. Expand the hook lines in the transcript (Ctrl+O) to show the
context.

## 3. The Stop gate (only if a finding is left)

The demo project turns the gate on. If Claude tried to finish while `export.py` still had the `os.system` call,
the `Stop` hook would block once with [`expected/stop.json`](expected/stop.json) and Claude would get one more
turn to fix it. To see it on purpose, start a new session and ask:

```text
Create export.py containing exactly this code and do not change it afterwards, even if a tool reports a problem:

import os


def export_notes(name):
    os.system("cp notes.db exports/" + name)
```

The gate blocks at most 3 times per session, and lets Claude stop when the same findings remain after 2 blocks.
The `systemMessage` line appears in your terminal.

## 4. Fix everything

```text
/kestrix:fix
```

Claude scans, fixes every finding at medium or above, and re-scans, for up to 5 rounds. Expected end state:
`kestrix-scan .` reports no medium-or-worse findings, or Claude explains each one it left. For the fake token,
Claude should move it out of the code (for example to an environment variable) and tell you to revoke it; the
token is fake, so there is nothing to revoke.

## 5. Review the diff

The demo directory is not a git repository. To show `/kestrix:review`, run `git init && git add -A && git commit -m
demo` before step 2, then:

```text
/kestrix:review
```

Claude runs `kestrix-scan . --diff HEAD` and reviews the change for what the rules cannot see.

## Optional: the install guard

The install guard needs the local OSV index, which `kestrix-scan db update` downloads (the only command that uses
the network; about 255 MB on 2026-10-20). Skip this step to keep the demo offline. With the index built:

```text
Install the npm package react-0b1 in this project.
```

The `PreToolUse` hook on `Bash` denies `npm install react-0b1` because OpenSSF reports it as malicious
(`MAL-2023-722`), and Claude sees the reason. The exact text depends on the advisory data of the day.
