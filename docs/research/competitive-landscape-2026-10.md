# Competitive landscape: code security inside AI coding agents (web check, 2026-10-19)

This is a summary of a sourced web review. Vendor figures are the vendors' own. Claims marked *unverified* could
not be confirmed from primary sources.

## Fix-while-writing is now table stakes

These products already scan files as Claude writes them:

| Product | What it does | Where code goes | Source |
| --- | --- | --- | --- |
| Anthropic `security-guidance` (official, free) | Regex checks on about 25 patterns on Edit/Write; an LLM review of the diff on Stop; an agentic review on commit that traces data flow | Diffs and files go to the model endpoint | [plugin](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/security-guidance) |
| Anthropic `/security-review` and its GitHub Action (MIT) | LLM review of the changed files plus a second false-positive pass. The action is not hardened against prompt injection | Model API | [action](https://github.com/anthropics/claude-code-security-review), [support](https://support.claude.com/en/articles/11932705-automated-security-reviews-in-claude-code) |
| Anthropic Claude Code Security (research preview, Feb 2026) | Data-flow reasoning, findings re-verified, severity and confidence ratings | Anthropic | [announcement](https://www.anthropic.com/news/claude-code-security) |
| Semgrep Guardian plugin | A hook on every file write that loops until the result is clean. Needs a login | Uploads files to `scanner.semgrep.ai` | [docs](https://app.semgrep.dev/docs/mcp), [repo](https://github.com/semgrep/mcp-marketplace) |
| Snyk Studio hooks and MCP | PostToolUse scanning of changed lines plus a blocking Stop gate. Needs an account | Snyk cloud by default | [docs](https://docs.snyk.io/agent-security/agentic-security-with-snyk-studio/getting-started-with-snyk-studio), [write-up](https://dev.classmethod.jp/articles/snyk-studio-claude-code-mcp/) |
| Aikido plugin (official marketplace) | SAST, secrets, IaC. Needs a login | Aikido | [docs](https://help.aikido.dev/ai-and-dev-tools/aikido-mcp/anthropic-claude-code-mcp.md) |
| GitHub (since 2026-06-09) | CodeQL, dependency and secret checks on Claude and Codex agent PRs, with no GHAS license needed | GitHub | [changelog](https://github.blog/changelog/2026-06-09-security-validation-for-third-party-coding-agents) |

## Kestrix's position

**Kestrix is the offline, deterministic, auditable layer that runs alongside Claude's own review.** It is not
the only real-time option.

### Strengths

- **Fully local:** no account, no upload, and no network.
- **Deterministic:** results come from AST analysis, so they are the same on every run. The official plugin's
  edit-time layer is regex.
- **Redistributable:** the rules are Apache-2.0. Semgrep's rules are internal-use only and cannot be
  redistributed ([licensing](https://docs.semgrep.dev/licensing)).
- **Auditable:** SARIF output, baselines, and suppressions that require a reason.

### Weaknesses

- **Narrow coverage:** 28 rules, Python only.
- **Shallow analysis:** no taint tracking, cross-file analysis, reachability or dependency scanning.
- **No benchmark yet,** and no brand.

## Licensing rules for us

- Do not copy, port or closely paraphrase any of these:

  | Source | Why not |
  | --- | --- |
  | Semgrep rules | Internal-use license |
  | Trail of Bits Semgrep rules | AGPL-3.0 |
  | Trail of Bits skills | CC-BY-SA-4.0 |
  | Snyk data or descriptions | Terms of service |
  | CodeQL queries | Treat as off-limits; terms *unverified* |

- Every rule has a clean-room note: it was written from the CWE entry and the language documentation.
- OWASP BenchmarkPython is GPL-3.0. Download it in CI as an external target; never vendor it.

## What builds trust and adoption

- **Listing:** follow the official directory's pre-submission checklist
  ([checklist](https://claude.com/docs/plugins/pre-submission-checklist)):
  - README and LICENSE;
  - no unpinned launchers and no package installs inside hooks;
  - every network behavior disclosed;
  - the plugin at the root of its own repo.

  Also offer it to the community marketplace `trailofbits/skills-curated`.
- **Proof of privacy:** a privacy statement backed by a test that no socket opens during a scan.
- **Security process:** a `SECURITY.md`.
- **Release integrity:** signed or attested releases.
- **Evidence:**
  - per-rule good and bad examples;
  - `claude plugin eval` results;
  - a published benchmark scorecard against Bandit and Semgrep CE on OWASP BenchmarkPython, scored with
    BenchmarkUtils (true-positive rate, false-positive rate, Youden index per CWE).
- **Configuration risk:** project hooks and MCP configuration were used for remote code execution (CVE-2025-59536
  and CVE-2026-21852, since patched;
  [Check Point](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files/)).
  A scanner for risky `.claude/settings.json` and `.mcp.json` entries is a fitting Kestrix rule family.

## Prioritized roadmap

1. **Hook quality:**
   - report only findings the edit introduced (compared with the file before the edit);
   - a capped, structured `additionalContext`;
   - published latency.
2. **Stop gate hardening:** loop guard, retry cap, fail-open behavior, and a documented opt-in.
3. **Benchmark:** OWASP BenchmarkPython against Kestrix, Bandit, Semgrep CE and the security-guidance regex layer,
   with the scorecard and method published.
4. **Provenance:** clean-room provenance notes for every rule, plus a dataset license manifest for the ML work.
5. **Offline dependency scanning:** an OSV-based check of lockfiles, plus a PreToolUse check that blocks
   installing known-malicious packages (OpenSSF data through OSV).
6. **Taint analysis:** intraprocedural taint tracking for the Python injection rules.
7. **Agent- and ML-era rules:**
   - LLM output flowing into `eval`, a shell or SQL;
   - unsafe model loading (`torch.load`, `joblib`);
   - risky `.claude/settings.json` and `.mcp.json` entries.
8. **Publishing:**
   - a standalone plugin repo with README, LICENSE, PRIVACY, SECURITY.md and eval results;
   - submission to the official directory and to `skills-curated`.
9. **JavaScript and TypeScript rules,** then pre-commit, a GitHub Action and SARIF upload.
10. **`/kestrix:review`:** deterministic findings first, then Claude tries to disprove each one. Each finding is
    labeled as engine-confirmed or model-suggested.
