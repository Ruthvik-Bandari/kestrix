# Eval suite

A [`claude plugin eval`](https://code.claude.com/docs/en/plugin-evals) suite for the Kestrix plugin. Each case is a
realistic prompt plus graders. The hook cases check the loop the plugin exists for: Claude writes code with a
planted vulnerability, the `PostToolUse` hook reports it, and Claude fixes it in the same turn.

| Case | Prompt | Passes when |
| --- | --- | --- |
| `hook-fixes-os-system` | Create `export.py` with an `os.system("cp ... " + name)` call | `export.py` exists, has no `os.system` or `shell=True`, and still copies `notes.db`. Indicator: Claude wrote the file and then edited it |
| `hook-fixes-sql-injection` | Add `notes.py` with SQL built by an f-string | `notes.py` exists and passes the author as a bound parameter. Indicator: write, then edit |
| `safe-code-stays-quiet` | Write a `slugify` function | `slug.py` defines `slugify` and Claude makes no `Edit`: the hook adds no noise to clean code |
| `security-review-uses-skill` | "Do a security review of this function" | The reply names the command injection. Indicator: Claude invokes `secure-code-review` |

All graders are `regex`, `tool_used`, `tool_order` or `file_exists`, so grading makes no model call. The
indicators (`arm: with-only`, and every `tool_used: Skill` grader) show whether the plugin fired and are left out of
the score, as the eval docs describe; the other graders are scored in both arms, so `Δ` shows what the plugin
changed. The hook's `additionalContext` does not appear in the eval trace, so no grader can match its text; the
indicators read the tool calls instead.

## Run it

Requirements: Claude Code v2.1.269 or later, git 2.31 or later, `kestrix-scan` on PATH (the hooks call it), and
`python3`. Runs use your normal Claude Code login or API key and count against your plan or bill.

From the repository root:

```bash
# one quick run of one case, with the plugin only
claude plugin eval . --case hook-fixes-os-system --runs 1 --ablation none --allow-tools Write Edit

# the full suite: 4 cases x 3 runs, with and without the plugin (24 agent runs)
claude plugin eval . --allow-tools Write Edit --threshold 0.75

# in CI
claude plugin eval . --trust-plugin --allow-tools Write Edit --json results.json \
  --threshold 0.75 --model claude-sonnet-5 --no-publish --max-cost-usd 10
```

`Write` and `Edit` must be granted: without them Claude cannot create the files the hooks scan. The first run asks
`Trust this plugin directory?`. Results go to `evals/results/<timestamp>/` (`report.html` and
`aggregate-result.json`), which `.gitignore` leaves out.

The hooks run outside the eval's sandbox, as the eval docs note for any plugin with hooks; they only read the files
Claude wrote and start the local `kestrix-scan`.

## Results so far

One run per arm (`--runs 1`), 2026-10-20, Claude Code 2.1.304, default model (`claude-opus-5-5`), `kestrix-scan`
0.1.0. One run is noisy; run the default 3 before quoting a number.

| Case | With plugin | Without | Δ | Note |
| --- | ---: | ---: | ---: | --- |
| `hook-fixes-os-system` | 1.00 | 0.67 | +0.33 | With the plugin, Claude wrote the file, got the finding and replaced `os.system`. Without it, the call stayed. |
| `hook-fixes-sql-injection` | 1.00 | 1.00 | 0.00 | Claude used a bound parameter in its first write in both arms, so the hook had nothing to report. The case guards against regressions. |
| `safe-code-stays-quiet` | 1.00 | 1.00 | 0.00 | No edit after the write in either arm. |
| `security-review-uses-skill` | 1.00 | 1.00 | 0.00 | Both arms named the injection. Claude did **not** invoke `secure-code-review` on this phrasing: its description does not trigger on a pasted function. |

An earlier version of `hook-fixes-os-system` said "containing exactly this code"; with that wording Claude kept the
vulnerable code, reported the finding and offered a fix instead, which is a fair reading of the request.
