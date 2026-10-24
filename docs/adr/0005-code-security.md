# ADR 0005: Code security scanning, a Claude Code plugin, and a learned vulnerability model

- Status: accepted
- Date: 2026-10-19
- Decision owner: Ruthvik Bandari

## Context

People increasingly write code with AI assistants. Those assistants, and the people using them, ship the same
classic mistakes:
- hard-coded secrets;
- shell and SQL injection;
- unsafe deserialization;
- disabled TLS checks;
- weak randomness for tokens;
- unsafe DOM sinks.

Kestrix already explains security answers for emails, files, websites and detection rules. The owner wants three
things:

1. The pip package raises errors on insecure code.
2. A Claude Code plugin that lets Claude analyze code as it develops and fix issues automatically.
3. AI and ML models trained on the owner's HPC allocation (V100, A100 and H200 through Slurm).

## Decision

### 1. Module `kestrix.code`: an explainable, local, rule-based scanner

**Command:** `kestrix code scan [PATH ...] [--diff BASE] [--format text|json|sarif] [--fail-on low|medium|high|critical] [--baseline FILE]`.

**Languages:**
- **Python** is analyzed with the stdlib `ast`. It handles call resolution through imports and aliases, keyword
  arguments, and simple constant propagation within a function. Untrusted input is never executed or imported.
- **JavaScript and TypeScript** come next. They need a bounded tokenizer and a structural matcher that is exact
  enough for sinks such as `innerHTML =`, `eval(`, `child_process.exec(` with template strings, and
  `dangerouslySetInnerHTML`.
- **Any text file** gets the secrets rules: high-precision provider patterns (AWS, GitHub, Slack, Stripe, Google,
  private keys, JWTs), plus entropy-gated generic assignments.

**Every finding carries:**
- a stable rule id such as `py.subprocess.shell_true`;
- a CWE number;
- a severity and a confidence;
- the file, line and column;
- a one-line message;
- why it matters;
- a concrete fix, as text plus a patch hint when it is mechanical.

**Exit codes:**

| Code | Meaning |
| --- | --- |
| 0 | No findings at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` |
| 2 | Usage or input error |

**Ways to run it:**
- **Suppression:** an inline `# kestrix: ignore[rule-id] reason`. The reason is required. A baseline file lets
  existing code be adopted gradually.
- **Integrations:**
  - SARIF 2.1.0 for GitHub code scanning;
  - a pre-commit hook (`.pre-commit-hooks.yaml`);
  - a GitHub Action example;
  - a Python API `kestrix.code.scan(paths) -> ScanReport`.
- **Safety and limits:**
  - files are read as data, with size and count caps;
  - symlinks are not followed outside the scan root;
  - `.gitignore`d and vendored paths are skipped by default;
  - nothing leaves the machine.

**Honesty:** rules are pattern analysis and miss things. Every rule has positive and negative tests, and the docs
claim no detection rates until the evaluation in part 3 exists.

### 2. Claude Code plugin `kestrix`, shipped in the repo and installable by command

**The plugin directory `src/kestrix/integrations/claude_plugin/kestrix/` contains:**
- `.claude-plugin/plugin.json`;
- a `marketplace.json` at the repo root, so `/plugin marketplace add Ruthvik-Bandari/kestrix` works;
- `kestrix integrations install-claude-plugin`, which copies the plugin locally.

**Hooks:**
- **PostToolUse on Write, Edit and MultiEdit:** runs `kestrix code scan --hook` on the changed file and returns
  the findings as additional context. Claude then fixes them in the same turn.
- **Stop:** optionally blocks finishing while high or critical findings remain in files changed this session.
- **Timeouts:** both hooks are fast (under about 1 s per file) and fail open. A scanner error never blocks the user.

**Skills:** `secure-code-review` (how to review and fix by rule family) and the existing `kestrix-security` skill.

**Commands:** `/kestrix:scan`, `/kestrix:fix` and `/kestrix:review`.

**Untrusted content:** code content is data. The hook output never includes secret values, only their location
and type.

### 3. A learned vulnerability model, trained on the HPC and shipped only if it beats the rules

This is research in the style of the detection-repair track, under its rules:

**Data:**
- public function-level vulnerability datasets with recorded licenses (candidates: PrimeVul, DiverseVul,
  CVEfixes);
- every dataset is checked and recorded in `research/results/sources.md` before use.

**Method:**
- splits by project and by CVE, with no leakage, and a test split evaluated exactly once;
- baselines are the rule engine and an untrained code model;
- the learned model is a LoRA fine-tune of a small open code model, sized to the GPU by measurement.

**What it does if it ships:** an optional `kestrix[ml]` extra that ranks and explains *additional* suspicious
functions and suppresses likely false positives. It is never the only gate.

## Consequences

- **Delivery slices:**
  - C1: Python rules, secrets rules, the CLI, the output formats, exit codes, suppression and baseline;
  - C2: the Claude Code plugin with hooks, skills and commands;
  - C3: JavaScript and TypeScript rules;
  - C4: pre-commit, the GitHub Action and the SARIF upload example;
  - C5: ML data acquisition and checks on the HPC;
  - C6: training and evaluation;
  - C7: an optional `kestrix[ml]` integration, if it earns it.
- **Licenses.** The scanner's rules are written from scratch. Rule ideas follow public CWE guidance, and no rule
  text or code is copied from other scanners.
