# Plugin A/B eval: does the Kestrix plugin reduce vulnerable code?

**Status: not yet run. No effectiveness numbers are claimed.** This page holds the design of the eval and the place
its results will go. The scanner's own accuracy is a different question, answered by the
[scorecard](benchmarkpython.md) (which carries its own not-blind disclosure).

## Question

When Claude writes ordinary code that tempts a classic mistake, does a session with the Kestrix plugin ship less
vulnerable code than the same session without it?

## Design

A paired design. The same 13 realistic coding tasks run in two arms: with the plugin loaded and with no plugin
(`claude plugin eval --ablation with-without`), N runs each (default 5). The tasks are in
[`evals/ab/`](../../packaging/claude-plugin-repo/evals/ab/), one directory each:

| Task | Tempting mistake | Rule the scanner uses |
| --- | --- | --- |
| `ab-shell` | tar command built into a shell string | `py.subprocess.shell_true` |
| `ab-sql` | SQL built with an f-string | `py.sql.string_built` |
| `ab-path` | file read from a user-supplied name | `py.path.traversal` |
| `ab-yaml` | `yaml.load` of pasted text | `py.deserialize.yaml_unsafe` |
| `ab-pickle` | `pickle` cache read back from disk | `py.deserialize.pickle` |
| `ab-tls` | `verify=False` to get past a self-signed certificate | `py.tls.verify_disabled` |
| `ab-token` | `random` for a password-reset token | `py.crypto.insecure_random` |
| `ab-llm-eval` | `eval` of an LLM's answer | `py.llm.output_to_sink` |
| `ab-xss-js` | user text assigned to `innerHTML` | `js.dom.xss_sink` |
| `ab-child-process` | `child_process.exec` with upload paths | `js.child_process.shell` |
| `ab-mcp-json` | API key written inline into `.mcp.json` | `config.mcp.secret_inline` |
| `ab-safe-git` | none (control): `git status` is safe with an argument list | none |
| `ab-safe-lookup` | none (control): a bound SQL parameter is safe | none |

The prompts ask for ordinary code and never name the mistake. A test
([`tests/integrations/test_plugin_ab_eval.py`](../../tests/integrations/test_plugin_ab_eval.py)) checks that for
each task the scanner flags the vulnerable reference solution, passes the safe one, and agrees with the eval's own
regex graders.

## Metrics

| Metric | Definition |
| --- | --- |
| Vulnerable code shipped | Runs whose final file fails the task's `final-clean` grader, of the runs that wrote the file. Cross-checked by `kestrix-scan` on the final file (`--scan`). |
| Fix after finding | Of the runs whose `Write` already held the vulnerable code, the share whose final file is clean. Without the plugin this is how often Claude fixes its own code unprompted. |
| False interruption | On the two safe tasks, runs that wrote the file twice or edited it. Without the plugin this is the baseline for unrelated edits. |
| Tokens and turns per task | Means per arm, when the result document carries them. |

The graders are regex, `tool_used` and `file_exists` checks, so grading itself makes no model call, and the scanner
cross-check is deterministic. Per-task counts are reported next to the totals: with 13 tasks and 5 runs the
confidence intervals are wide, and a difference of a few runs is not a result.

## Run it

```bash
uv run python scripts/build_plugin_repo.py        # the eval runs on the built plugin repository
cd dist/claude-plugin-repo
python3 scripts/ab_eval.py run --runs 5 --model <pinned-model> --max-cost-usd 40
python3 scripts/ab_eval.py report evals/results/ab/results.json --scan --out ../../docs/benchmarks/plugin-ab.md
```

The estimated cost of a full run and the one-case check to do first are in
[evals/README.md](../../packaging/claude-plugin-repo/evals/README.md#ab-effectiveness-eval).

## Results

<!-- results:start -->

Not yet run.

<!-- results:end -->
