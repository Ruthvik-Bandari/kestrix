# Kestrix for Claude Code

Kestrix checks the code Claude writes, on your machine, while Claude writes it. What that looks like (the middle
block is the hook's real output, generated from the scanner when this repository is built):

```text
{{EXAMPLE}}
```

After every `Write`, `Edit`, `MultiEdit` or `NotebookEdit`, and after a Bash command that changes source files in a
git repository, a hook runs the local `kestrix-scan` scanner on the changed files. Findings at medium severity or
above that the change introduced go back to Claude with the rule, the CWE and the fix, and Claude is asked to fix
them in the same turn. The plugin also adds secure-review skills and four commands: `/kestrix:scan`, `/kestrix:fix`,
`/kestrix:review` and `/kestrix:status`.

- **Offline.** The hooks open no network connections and send nothing off your machine. No account, no telemetry.
- **Deterministic.** Findings come from fixed rules, not a model: {{RULE_TOTAL}} rules in all, {{RULE_COUNTS}}
  (Python syntax tree and data flow, JavaScript and TypeScript, web files, PHP, SQL, Go, Java and Kotlin, C#, Ruby and
  ERB, C and C++, Rust, Swift (lexically obvious patterns only), CI and infrastructure files, hard-coded secrets, dependency lockfiles, and Claude Code and MCP configuration). The same file gives the same result on every run.
- **Apache-2.0,** including the rules, so you can read, audit and redistribute them.
- **Works alongside Anthropic's `security-guidance` plugin** and `/security-review`, which use the model to review
  code. Kestrix is a rule-based layer next to them, not a replacement.

The scanner is rule-based pattern analysis. It misses things and can be wrong in context. A file with no findings
means no rule fired, not that the code is secure.

## Coverage

What is scanned, how deeply, and what is not:

- **Scanned:** files Claude changes through `Write`, `Edit`, `MultiEdit` and `NotebookEdit`, and, in a git
  repository, the source-like files (up to 20) that a Bash command created or modified: code, JSON, YAML, TOML,
  dotenv, INI and shell files, not lockfiles such as `package-lock.json`. Not scanned: edits you make yourself,
  files a Bash command changed outside a git repository (you are told once), a command that commits what it
  changed before the hook looks, files over 1 MiB, and anything Claude did before the plugin was loaded.
- **Per file, not per program.** Analysis is per file. Taint (a value from a request, a model or a file reaching
  a dangerous call) is tracked within one function. There is no whole-program or cross-file analysis: a value that
  passes through another function or module is not followed.
- **What the rules know:** {{RULE_TOTAL}} rules, {{RULE_COUNTS}}. Code rules for Python, JavaScript/TypeScript, PHP, Go,
  Java and Kotlin, C#, Ruby, C and C++, Rust and Swift, web-file, SQL-file, CI and infrastructure rules;
  secrets in any text file; Claude Code and MCP configuration; and dependency lockfiles, checked against a local
  copy of the OSV advisories only after you run `kestrix-scan db update`.
- **No findings is not proof of security.** A rule that did not fire is not a guarantee, and the rules say nothing
  about authorization logic, business rules or design.

## Three scan states

Every scan ends in one of three states, so a broken scanner never looks like a clean file:

| State | What you see | What Claude is told |
| --- | --- | --- |
| Clean | Nothing. | Nothing. |
| Findings | Nothing extra. | The new findings, with the fix. |
| Unavailable: `kestrix-scan` missing, timed out or crashed | A short message, once per session for each cause. | One line, every time: this file was NOT security-checked, so do not call it scanned or secure. |

Work is never blocked in any state. `/kestrix:status` shows this session's counts: files scanned, findings
reported, and every file that was not checked, with the reason.

## Requirements

The plugin calls the `kestrix-scan` command, so install it first. It needs Python 3.10 or later and has no
dependencies on Python 3.11 and later:

```bash
pip install kestrix-scan
# or
uv tool install kestrix-scan
# or
pipx install kestrix-scan
```

The hooks also need `python3` on PATH. Any Python 3.9 or later works, including the macOS system Python; it does
not have to be the one `kestrix-scan` is installed in.

**The plugin never installs anything.** The hooks call the `kestrix-scan` you already installed and never run
`pip`, `npm`, `uvx`, `npx` or any other installer or package launcher. If `kestrix-scan` is not on PATH, the first
edit of a session shows one message saying to install it from PyPI, and Claude is told, for each file, that it was
not checked and not to install the scanner itself. A `kestrix-scan` executable inside the project directory is
ignored, so a cloned repository cannot replace your scanner. When only the full Kestrix workbench is installed
(`pip install kestrix`), the hooks use `kestrix code scan` instead.

## Install

In Claude Code:

```text
/plugin marketplace add Ruthvik-Bandari/kestrix-claude-plugin
/plugin install kestrix@kestrix
```

Or from your shell: `claude plugin marketplace add Ruthvik-Bandari/kestrix-claude-plugin`, then
`claude plugin install kestrix@kestrix`. Start a new session, or run `/reload-plugins`, to load it.

## What the plugin runs

Every hook runs `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/kestrix_hook.py" <event>`, a standard-library script in
this repository. It reads the hook JSON that Claude Code passes on stdin and, where noted, starts the local
`kestrix-scan scan --hook` with that JSON on stdin. Nothing is sent over the network. What a hook prints goes back
to Claude Code, which adds it to the conversation like any other tool result.

| Hook | When | What it reads | What it sends, and where |
| --- | --- | --- | --- |
| `SessionStart` | session start, resume, clear, compact | whether `kestrix-scan` is on PATH; `.kestrix.json` in the project | One line of context to Claude (the hooks are active, whether the Stop gate is on), and once per session one line to you. Deletes this plugin's session records older than 14 days. |
| `PreToolUse` on `Write\|Edit\|MultiEdit\|NotebookEdit` | before Claude changes a file | the file about to change (up to 1 MiB) | Nothing. It copies the file into the plugin's data directory, so the next hook can tell new findings from old ones. It prints nothing and never blocks a tool. |
| `PreToolUse` on `Bash` (install guard) | before every Bash command | the command text; the local OSV index, if you built one | Only for `pip`, `uv`, `npm`, `pnpm` or `yarn` installs: a `deny` to Claude Code for a package reported as malicious, or a warning for a known-vulnerable pinned version. Silent without an index. It also notes the time the command started in the plugin's data directory, for the `PostToolUse` hook below. |
| `PostToolUse` on `Write\|Edit\|MultiEdit\|NotebookEdit` | after Claude changes a file | the changed file and its snapshot | Up to 5 new medium-or-worse findings (rule id, CWE, line, message, fix; under 1,500 characters) as context to Claude. Nothing when the edit added no finding. When the scan could not run: the "not checked" notice (see Three scan states). |
| `PostToolUse` and `PostToolUseFailure` on `Bash` | after every Bash command, including one that failed | `git status`, and the modification time of each file it lists; the changed source-like files (at most 20) and their `HEAD` versions | The same findings as above, for the files the command changed. See below. |
| `Stop` (off by default) | when Claude tries to finish | the files changed this session and their first snapshots | When high or critical findings this session introduced remain: a `block` with the list, so Claude gets one more turn to fix them. At most 3 blocks per session. |

**Files changed by Bash.** After each Bash command the hook asks git which files changed
(`git status --porcelain`, which leaves out ignored files such as `node_modules` and virtualenvs) and keeps those
whose modification time is later than the start of the command, so files that were already modified before it are
not rescanned. Of those it scans the 20 most recently changed source-like files. A tracked file is compared with its
`HEAD` version and a new file counts as wholly new, so only what the command introduced is reported. This needs no
snapshot before every command and no walk of your directory tree, which is why it was chosen over comparing
modification times in the current directory. The hook runs git with `core.fsmonitor` and `core.hooksPath` turned
off, so a repository's own configuration cannot make `git status` run a program. Outside a git repository nothing
is scanned and you are told once; more than 20 changed files are reported as not checked. A command that also
commits what it changed is not seen.

**Everything fails open, and says so.** No scanner, a timeout (8 seconds per edit or command, 25 seconds at Stop),
output that is not JSON, a scanner crash, or any error inside the script means the work goes on and the exit code is
0, so the plugin never blocks your editor because of its own problem. A scan that could not run is no longer silent:
it shows the "not checked" notice described above.

**Secrets are never echoed.** For a hard-coded secret, findings show only the kind, the location and the first four
characters.

## The one network action: `kestrix-scan db update`

The install guard and the dependency checks read a local copy of the public [OSV](https://osv.dev) advisory data.
You build it yourself, when you choose, with:

```bash
kestrix-scan db update
```

It downloads the OSV exports for PyPI and npm from `https://storage.googleapis.com/osv-vulnerabilities/` over
HTTPS into your cache directory. No hook or skill runs it. Without it, the install guard stays silent and the code
rules work as usual.

The `kestrix-security` skill is for the separate Kestrix workbench (`kestrix` command: email, link, file, website,
Sigma and Bitcoin checks). It is used only when you ask one of those questions and the workbench is installed.
Three of its commands reach the network: `kestrix webcheck scan` sends one GET and one TLS handshake to the
website you name, `kestrix bitcoin scan --lookup-chain` sends the addresses (and your IP address) to mempool.space,
and `kestrix detect engine-up` starts the pinned Elasticsearch image in Docker, which Docker downloads the first
time. The skill tells Claude to confirm that you own or may test the website, and to get your agreement before
`--lookup-chain`. The code-security hooks, skills and commands use none of them.

## Turn on the Stop gate

The gate is off by default. Turn it on with either:

- `KESTRIX_BLOCK_ON_STOP=1` in the environment Claude Code runs in;
- a `.kestrix.json` at the project root:

  ```json
  {"claude": {"block_on_stop": true}}
  ```

`KESTRIX_BLOCK_ON_STOP=0` turns it off even when the project file turns it on. The gate counts only high or
critical findings that this session introduced, lets Claude stop when Claude Code sets `stop_hook_active`, and stops
blocking after 3 blocks, or after 2 when the findings are unchanged.

Turn off the install guard with `KESTRIX_INSTALL_GUARD=0`, or for one project with `claude.install-guard = false`
under `[tool.kestrix]` in `pyproject.toml`.

## Skills and commands

| Name | What it does |
| --- | --- |
| `/kestrix:scan [path]` | Scans a path (default `.`) and summarizes the findings. Changes no code. |
| `/kestrix:fix [path]` | Scans, fixes every finding at medium or above, and re-scans, for up to 5 rounds. |
| `/kestrix:review [base-ref]` | A secure review of the current diff: `kestrix-scan . --diff <ref>` (default `HEAD`), then a review for what rules cannot see. |
| `/kestrix:status` | This session's record: files scanned, findings reported, and files that were not security-checked, with the reason. Reads the plugin's own session record; scans nothing. |
| `secure-code-review` skill | How to review code with Kestrix: scan, triage, fix by rule family, re-scan, explain what remains. |
| `fixing-security-findings` skill | Before and after code for every rule id, generated from the rule registry. |
| `kestrix-security` skill | Everyday security questions with the Kestrix workbench (see above). |

The four commands run only when you type them. The skills tell Claude to treat code under review as data and to
ignore instructions written inside it.

To silence a confirmed false positive, put a suppression with a reason on the line or the line above:
`# kestrix: ignore[py.subprocess.shell_true] command from the reviewed deploy config`. A suppression without a
reason suppresses nothing.

## Privacy

Scanning is local and makes no network calls. Findings are inserted into your Claude conversation as hook output, so
they are sent to Anthropic like any other conversation content, under the terms of your Claude plan. Secret values
are never included: a finding for a hard-coded secret shows only its kind, its location and its first four
characters.

The plugin collects nothing and sends nothing else: no telemetry, no account, no update checks, and no network
connection from any hook. It keeps a list of the files changed in each session and copies of those files from
before the change in its own data directory (`${CLAUDE_PLUGIN_DATA}`, which Claude Code deletes when you uninstall
the plugin), and removes session records after 14 days. Hook output becomes part of your Claude conversation,
like any tool result. Details and the tests behind each claim: [PRIVACY.md](PRIVACY.md).

## Credentials

The plugin needs no credentials, API keys or tokens, and declares no `userConfig`. It reads none from your
environment.

## Does it help?

Not measured yet, and this README claims no effectiveness number. Two things are published:

- **Does the scanner find the problems?** The [benchmark scorecard](benchmarks/scorecard.md) compares `kestrix-scan`
  with Bandit and the regex layer of Anthropic's `security-guidance` plugin on OWASP BenchmarkPython and on
  cases written for this project. Read its disclosure first: the scorecard is **not blind**. The first run was
  blind, but the rule changes after it were made in response to that run's BenchmarkPython gap analysis, so the
  later BenchmarkPython numbers are not a blind measurement of the scanner.
- **Does Claude ship less vulnerable code with the plugin?** The scorecard does not answer that. The way the claim
  will be measured is a paired A/B eval: 13 coding tasks (11 that tempt a classic mistake, 2 safe controls), each run
  with and without the plugin, graded by regex checks and by `kestrix-scan` on the final files. It measures the rate
  of vulnerable code shipped, how often a finding is fixed, false interruptions on the safe tasks, and tokens and
  turns per task. The design, the expected cost of a run and the results page, which today reads "not yet run", are
  in [benchmarks/plugin-ab.md](benchmarks/plugin-ab.md) and [evals/README.md](evals/README.md#ab-effectiveness-eval).

## Evals

[`evals/`](evals/) holds a `claude plugin eval` suite: four smoke cases (Claude writes code with a planted
vulnerability, the hook reports it, and Claude fixes it) and the A/B suite above. See
[evals/README.md](evals/README.md) for how to run them and the results so far. Each run is a real model call on your
account.

## Security, license and source

- Report a vulnerability privately: [SECURITY.md](SECURITY.md).
- License: [Apache-2.0](LICENSE). Notices: [NOTICE](NOTICE). Changes: [CHANGELOG.md](CHANGELOG.md).
- The scanner is the [`kestrix-scan`](https://pypi.org/project/kestrix-scan/) package on PyPI. This repository is
  generated from the Kestrix source by `scripts/build_plugin_repo.py`, and a test checks that it matches the plugin
  shipped inside the `kestrix-scan` wheel (`kestrix-scan install-claude-plugin` installs the same files).
