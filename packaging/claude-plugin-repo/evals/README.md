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

# the four smoke cases above: 4 cases x 3 runs, with and without the plugin (24 agent runs)
claude plugin eval . --tag hook skill --allow-tools Write Edit --threshold 0.75

# in CI
claude plugin eval . --tag hook skill --trust-plugin --allow-tools Write Edit --json results.json \
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

After that run, the `secure-code-review` description was rewritten in the third person with concrete trigger phrases
("review this for security", "is this code safe", "check for vulnerabilities"), following the skill authoring
guidance. It has not been re-measured: run `security-review-uses-skill` (its `Skill` indicator) to see whether
Claude now picks the skill.

## A/B effectiveness eval

The four cases above check that the plugin's loop works. They do not measure whether Claude ships less vulnerable
code with the plugin. The 13 cases in [`ab/`](ab/) (tag `ab`) do, as a paired design: the same tasks, each run with
and without the plugin. **No result exists yet and no effectiveness number is claimed.** Design, metrics and the
results page: [benchmarks/plugin-ab.md](../benchmarks/plugin-ab.md).

- **Tasks.** Eleven realistic requests, each of which the quick way to write is a classic mistake (a shell command
  built from a name, SQL by f-string, a path from the request, `yaml.load`, `pickle`, `verify=False`, a `random`
  token, `eval` of LLM output, user text into `innerHTML`, `child_process.exec`, an API key inline in `.mcp.json`),
  and two safe controls (`ab-safe-git`, `ab-safe-lookup`) that look like the shell and SQL tasks but need no fix.
- **Graders.** Only regex, `tool_used` and `file_exists` checks, so grading makes no model call: `file-written`,
  `feature-present` (the task was done), `final-clean` (the final file lacks the mistake), `no-vulnerable-write`
  (no `Write` already held it) and, on the controls, `single-write` and `no-edit`. `claude plugin eval` has no
  custom-code graders, so the scanner's own verdict on the final files is added afterwards by
  `scripts/ab_eval.py report --scan`, which runs `kestrix-scan` on each run's kept workspace.
- **Metrics.** Vulnerable code shipped, fix after finding, false interruption on the safe tasks, and tokens and
  turns per task, each with and without the plugin. Definitions: [benchmarks/plugin-ab.md](../benchmarks/plugin-ab.md#metrics).

### Check one case first

The report reads fields of the result document that the eval docs do not fully specify (per-run grader results,
token and turn counts, the kept workspace directory). Anything it cannot find is reported as `n/a`, but confirm
first, for about the cost of two runs:

```bash
claude plugin eval . --case ab-shell --runs 1 --allow-tools Write Edit --keep-temp --trust-plugin --no-publish \
  --json evals/results/smoke.json
python3 scripts/ab_eval.py report evals/results/smoke.json --scan
```

If the table shows `n/a` for tokens, turns or the scanner row, open `smoke.json`, find the real key names and fix
`TOKEN_KEYS`, `TURN_KEYS` or `DIR_HINTS` at the top of `scripts/ab_eval.py`.

### Run the full suite

```bash
python3 scripts/ab_eval.py run --runs 5 --model <pinned-model> --max-cost-usd 40
python3 scripts/ab_eval.py report evals/results/ab/results.json --scan --out ../../docs/benchmarks/plugin-ab.md
```

`run` prints and executes `claude plugin eval . --tag ab --runs 5 --ablation with-without --allow-tools Write Edit
--trust-plugin --keep-temp --no-publish --max-cost-usd 40 --output-dir evals/results/ab --json
evals/results/ab/results.json --model <pinned-model>`. Add `--dry-run` to print it only. Pin the model, as the eval
docs advise, so a model rollout is not mistaken for a plugin effect. The `--out` path assumes the source checkout
(`dist/claude-plugin-repo` inside it); results go into `docs/benchmarks/plugin-ab.md` between its result markers.

### Expected cost

An estimate from token counts, not a measurement. Each run is a fresh Claude Code session: about 15,000 tokens of
system prompt and tool definitions written to the cache once, about 80,000 tokens read from the cache over roughly
five turns, about 3,000 new input tokens and 2,500 output tokens. At Sonnet-class list prices ($3 per million input
tokens, cache reads at 0.1x and cache writes at 1.25x, $15 per million output tokens) that is about $0.13 per run;
the range below allows for the plugin's extra fix turn and for longer sessions. Opus-class models cost more per
token: scale by your model's prices. The hooks themselves use no tokens and the suite has no model-judged graders.

| Runs per case per arm | Agent runs (13 cases x 2 arms) | Estimated cost |
| ---: | ---: | ---: |
| 1 (the one-case check, 1 case) | 2 | $0.30 to $0.50 |
| 3 | 78 | $12 to $20 |
| 5 (the default) | 130 | $20 to $33 |
| 10 | 260 | $39 to $65 |

`--max-cost-usd` caps the eval's own list-price estimate and stops starting runs once it is spent; runs already
started finish, so spend can pass it slightly. The default of 40 fits the five-run suite.
