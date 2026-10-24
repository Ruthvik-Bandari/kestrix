// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { toolFor } from "../../../app/tools";
import { code, guide, list, note, p, pages, section, see, table } from "../blocks";
import type { DocPage } from "../model";
import { ref } from "./helpers";
import { RULE_ROWS } from "./rules-data";

/*
 * kestrix-scan: the code scanner, its rules and its accuracy. Follows docs/modules/code.md,
 * packages/kestrix-scan/README.md, docs/modules/code-rules-provenance.md and docs/benchmarks/cvefixes.md.
 */

const BASE = "code-security/kestrix-scan";

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

const FAMILIES: { heading: string; prefixes: string[]; intro: string }[] = [
  { heading: "Python (py.*)", prefixes: ["py."], intro: "Run on `.py` and `.pyw` files. Python is parsed with the standard-library `ast`; nothing is imported or executed." },
  {
    heading: "JavaScript and TypeScript (js.*)",
    prefixes: ["js."],
    intro: "Run on `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.mts` and `.cts` files with a bounded tokenizer, not a full parser. Includes Angular's bypassSecurityTrust* and the Next.js, Fastify, Koa and NestJS request sources. Script blocks of `.html`, `.vue` and `.svelte` files get these rules too.",
  },
  {
    heading: "Web files (vue.*, svelte.*, web.*, html.*, css.*, next.*)",
    prefixes: ["vue.", "svelte.", "web.", "html.", "css.", "next."],
    intro: "Run on `.vue`, `.svelte`, `.html`, `.htm`, `.css` and `.scss` files with a bounded tag scanner, and on `next.config.*`. Mostly low severity; a missing Content-Security-Policy is not reported.",
  },
  {
    heading: "CI and infrastructure (gha.*, docker.*, sh.*, tf.*, k8s.*)",
    prefixes: ["gha.", "docker.", "sh.", "tf.", "k8s."],
    intro: "Run on GitHub Actions workflows and `action.yml`, Dockerfiles and Containerfiles, `.sh` and `.bash` scripts (and `run:` blocks and `RUN` lines), `.tf` files and Kubernetes manifests, read with a bounded YAML subset reader and line scanners. Nothing is run or planned; only literal values are judged. Suppress with `# kestrix: ignore[id] reason`.",
  },
  { heading: "Secrets (secret.*)", prefixes: ["secret."], intro: "Run on every text file. Findings show only the kind of secret and its first four characters, never the value." },
  {
    heading: "Claude Code and MCP configuration (config.*)",
    prefixes: ["config."],
    intro: "Run on `.claude/settings.json`, `.claude/settings.local.json`, `hooks/hooks.json` and `.mcp.json`.",
  },
  {
    heading: "Dependencies (dep.*)",
    prefixes: ["dep."],
    intro: "Run on lockfiles after `kestrix-scan db update`, against a local copy of the OSV vulnerability data.",
  },
];

function rulesFor(prefixes: string[]): string[][] {
  return RULE_ROWS.filter(([id]) => prefixes.some((prefix) => id.startsWith(prefix)))
    .sort((a, b) => SEVERITY_ORDER.indexOf(a[1]) - SEVERITY_ORDER.indexOf(b[1]))
    .map(([id, severity, cwe, finds]) => [`\`${id}\``, severity, cwe, finds]);
}

export const scannerPages: DocPage[] = [
  {
    path: BASE,
    title: toolFor("code").name,
    nav: "kestrix-scan",
    summary: toolFor("code").summary,
    sections: [
      ref("code", "What it is"),
      ref("code", "How it works"),
      ref("code", "How it helps"),
      ref("code", "Typical uses"),
      section("In this section", pages(`${BASE}/install-and-cli`, `${BASE}/configuration`, `${BASE}/ci-and-pre-commit`, "code-security/rules", "code-security/accuracy")),
    ],
  },
  {
    path: `${BASE}/install-and-cli`,
    title: "kestrix-scan: install and command line",
    nav: "Install and CLI",
    summary: "Install the scanner, scan a directory, download the vulnerability data and read the output and exit codes.",
    sections: [
      section(
        "Install and first scan",
        p("`kestrix-scan` is its own package with no dependencies on Python 3.11 and newer. The full `kestrix` workbench includes it, and `kestrix code scan` runs the same scanner with the same options."),
        guide("code"),
      ),
      section(
        "Commands",
        table(
          ["Command", "Options", "Exit codes"],
          [
            [
              "`kestrix-scan [scan] [PATH ...]`",
              "`--format text|json|sarif`, `--output FILE`, `--fail-on low|medium|high|critical|none` (default `high`), `--baseline FILE`, `--write-baseline FILE`, `--diff BASE`, `--hook`, `--config FILE`, `--no-config`",
              "0 no findings at or above `--fail-on`; 1 findings at or above it; 2 usage or input error",
            ],
            ["`kestrix-scan init`", "`--ci github`, `--pre-commit`, `--claude-plugin`, `--force`, `--dir DIR`", "0 done; 2 refused"],
            ["`kestrix-scan rules`", "", "0"],
            ["`kestrix-scan db update` (network)", "`--ecosystem PyPI npm` (default: both)", "0 done; 2 download or index error"],
            ["`kestrix-scan db status`", "", "0 index present; 1 no index"],
          ],
        ),
        p("`PATH` defaults to `.`, and `scan` is the default command, so `kestrix-scan src` is `kestrix-scan scan src`. Errors print `Rejected (<reason>): <detail>` to stderr and exit 2."),
        list(
          "`--format json` prints the full report. `--format sarif` prints SARIF 2.1.0 for GitHub code scanning.",
          "`--output FILE` writes the report to a file instead of stdout; the exit code is the same.",
          "`--fail-on` sets the lowest severity that makes the command exit 1. `none` always exits 0 after a successful scan.",
          "`--diff REF` keeps only findings on lines added or changed since a git ref.",
          "`--config FILE` reads settings from that file instead of searching for one; `--no-config` ignores settings files.",
        ),
      ),
      section(
        "What is scanned",
        list(
          "Directories are walked without following symbolic links. `.git`, `node_modules`, `.venv`, `dist`, `build`, `vendor`, `site-packages` and similar directories are always skipped, and `.gitignore` is honored.",
          "A file named on the command line is scanned even if it is ignored, so a hook can check a file such as `.env`.",
          "Files over 1 MiB are skipped as `too_large`; files with a NUL byte near the start as `binary`; at most 20,000 files per scan.",
          "A Python file that does not parse is listed as `syntax_error`; the secret rules still run on it.",
        ),
      ),
      section(
        "Dependency checks",
        p("Pinned versions in lockfiles are checked against a local copy of OSV. The check is offline: build the index once, refresh it now and then, and every scan reads it."),
        code("kestrix-scan db update"),
        p("`db update` is the only command that uses the network. It downloads the public OSV exports over HTTPS, only for the ecosystems your lockfiles use, and an unchanged export is not downloaded again. Scans then check `requirements*.txt` pins and `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `composer.lock`, `go.mod`, `go.sum`, `Cargo.lock`, `pom.xml`, `gradle.lockfile`, `Gemfile.lock`, `packages.lock.json` and `pubspec.lock`. `kestrix-scan db status` shows the index and its age."),
        table(
          ["Finding", "Severity", "When"],
          [
            ["`dep.malicious`", "critical", "Any advisory for the pinned version is an OpenSSF malicious-package report. Remove the package and rotate every credential on machines where it was installed."],
            ["`dep.vulnerable`", "highest of the advisories'", "An advisory affects the pinned version. The fix is the lowest version that fixes every vulnerability."],
            ["`dep.db_stale`", "note, not a finding", "There is no index, or it is older than `db-max-age-days` (default 7). It never changes the exit code."],
          ],
        ),
        note("Reachability is not analyzed: a finding means the version is affected, not that your code calls the vulnerable function. Language runtimes such as the PHP interpreter are not lockfile dependencies and are not checked here.", "caution"),
      ),
      section(
        "The report",
        p("Each finding has `rule_id`, `cwe`, `severity`, `confidence`, `path`, `line`, `column`, `message`, `why`, `fix`, a snippet of at most 200 characters (redacted for secrets) and a `fingerprint`. A taint finding also has a `trace` of steps from source to sink. The JSON keys and their order are stable."),
        see("Every rule", "code-security/rules"),
      ),
    ],
  },
  {
    path: `${BASE}/configuration`,
    title: "kestrix-scan: configuration, suppression and baselines",
    nav: "Configuration and baselines",
    summary: "Settings files, inline suppression with a reason, baselines for existing code and scanning only changed lines.",
    sections: [
      section(
        "Settings",
        p("Settings come from `[tool.kestrix]` in `pyproject.toml`, or the same keys at the top level of `.kestrix.toml`. The scanner searches from the scan root upwards, the first file found wins, and command-line flags override it."),
        code(
          `[tool.kestrix]
fail-on = "medium"                              # low, medium, high, critical or none
exclude = ["tests/fixtures/", "*.min.js"]       # globs, as in .gitignore
baseline = ".kestrix-baseline.json"             # relative to this file
rules.enable = ["py.", "secret."]               # rule ids or prefixes; default: every rule
rules.disable = ["py.crypto.weak_hash"]`,
          "pyproject.toml",
        ),
        table(
          ["Key", "Meaning"],
          [
            ["`fail-on`", "The default for `--fail-on`."],
            ["`exclude`", "Globs of files and directories to leave out, with `.gitignore` semantics."],
            ["`baseline`", "The default for `--baseline`, relative to the settings file."],
            ["`rules.enable`", "Rule ids or prefixes (`py.`, `secret.`, `py.crypto`) to report; default: every rule."],
            ["`rules.disable`", "Rule ids or prefixes to leave out, applied after `enable`."],
            ["`ignore-advisories`", "A table of advisory id (or alias, such as a CVE) to the reason it does not apply; the reason is required."],
            ["`claude.install-guard`", "`false` turns off the Claude Code install guard for this project."],
          ],
        ),
        p("An unknown key prints a warning and is ignored; an unknown rule id, a bad value or invalid TOML is an error (exit 2), and a misspelled rule id gets a suggestion. `kestrix-scan init` appends a minimal `[tool.kestrix]` without rewriting the file."),
        code("kestrix-scan init --ci github --pre-commit"),
      ),
      section(
        "Suppress a false positive",
        p("Add a comment on the finding's line or the line above, with the rule id and a reason. The reason is required: a suppression without one suppresses nothing and adds a note to the report."),
        code("subprocess.run(deploy.command, shell=True)  # kestrix: ignore[py.subprocess.shell_true] command from the reviewed deploy config"),
        p("`// kestrix: ignore[...] reason` works the same way in files with `//` comments, and `/* kestrix: ignore[...] reason */` is the form JSX accepts. For lockfiles, which have no comments, use `ignore-advisories` with a reason per advisory."),
      ),
      section(
        "Adopt it on existing code with a baseline",
        p("A fingerprint is the SHA-256 of the rule id, the path and the snippet with all whitespace removed. It leaves out the line number, so a finding keeps its fingerprint when code above it moves. Record today's findings, commit the file, and from then on only new findings count:"),
        code("kestrix-scan --write-baseline .kestrix-baseline.json"),
        code("kestrix-scan --baseline .kestrix-baseline.json"),
        p("The report's `baseline_filtered` says how many findings the baseline left out. A baselined dependency finding comes back when a new advisory affects the same version."),
      ),
      section(
        "Scan only what changed",
        code("kestrix-scan . --diff main"),
        p("`--diff BASE` keeps only findings on lines added or changed since the git ref, comparing the working tree (staged or not) with `git diff --unified=0`. Untracked files that are not ignored count as wholly new. Refs that start with `-` are refused."),
      ),
    ],
  },
  {
    path: `${BASE}/ci-and-pre-commit`,
    title: "kestrix-scan: SARIF, CI, pre-commit and pytest",
    nav: "CI, pre-commit and pytest",
    summary: "Upload SARIF to GitHub code scanning, run the scanner as a pre-commit hook, and fail a pytest run on findings.",
    sections: [
      section(
        "SARIF and GitHub code scanning",
        p("`--format sarif` writes SARIF 2.1.0. Each result carries a level (`error` for critical and high, `warning` for medium, `note` for low), its location, the redacted snippet and the fingerprint, and the driver lists every rule with its CWE and fix. A taint finding also has a code flow from source to sink."),
        code("kestrix-scan --format sarif --output kestrix.sarif"),
      ),
      section(
        "GitHub Action",
        p("`kestrix-scan init --ci github` writes `.github/workflows/kestrix.yml`. Its actions are pinned to commit SHAs and its job has only `contents: read` and `security-events: write`. The key steps:"),
        code(
          `- run: pip install kestrix-scan==0.1.0
- run: kestrix-scan db update        # downloads the OSV data, so this job needs network access
- run: kestrix-scan --format sarif --output kestrix.sarif || true
- uses: github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee # v4.39.0
  with:
    sarif_file: kestrix.sarif`,
          ".github/workflows/kestrix.yml (excerpt)",
        ),
        p("Findings appear under Security → Code scanning. To fail the build instead, drop `|| true`."),
        note("The generated workflow installs `kestrix-scan` from PyPI, so it only works after the PyPI release. Until then, replace that step with the repository install, which needs uv on the runner.", "caution"),
      ),
      section(
        "pre-commit",
        code(
          `repos:
  - repo: https://github.com/Ruthvik-Bandari/kestrix
    rev: v0.1.0
    hooks:
      - id: kestrix-scan`,
          ".pre-commit-config.yaml",
        ),
        p("The hook scans the staged Python and text files and honours `[tool.kestrix]`."),
      ),
      section(
        "pytest",
        code("pytest --kestrix"),
        code("pytest --kestrix --kestrix-fail-on=medium"),
        p("Adds one `kestrix-scan` item that scans the rootdir and fails when findings meet the threshold. Without `--kestrix` the scanner is not even imported."),
      ),
      section(
        "From Python",
        code(
          `import kestrix_scan

report = kestrix_scan.scan(["src"], config=kestrix_scan.load_config("."), fail_on="high")
for finding in report.findings:
    print(finding.path, finding.line, finding.rule_id, finding.fix)
raise SystemExit(kestrix_scan.exit_code(report))`,
        ),
      ),
    ],
  },
  {
    path: "code-security/rules",
    title: "Rules reference",
    nav: "Rules reference",
    summary: `All ${RULE_ROWS.length} scanner rules, by family, with severity and CWE.`,
    sections: [
      section(
        "How to read these tables",
        p(
          `There are ${RULE_ROWS.length} rules. Each finding names its rule id, a CWE, why it matters and a concrete fix. Every rule was written for Kestrix from its CWE entry and the language, library or standard documentation cited for it; no rule text, pattern or code from another scanner was used. List them on your own machine with \`kestrix-scan rules\`.`,
        ),
        p("Taint is followed within one function from request, LLM-client and similar sources to the sink, never across functions or files."),
        see("Suppress a finding", `${BASE}/configuration`),
      ),
      ...FAMILIES.map((family) =>
        section(family.heading, p(family.intro), table(["Rule", "Severity", "CWE", "Finds"], rulesFor(family.prefixes))),
      ),
      section(
        "Limits of the rules",
        list(
          "Rules are pattern analysis: they miss things and can be wrong in context. No real-world detection rate is claimed.",
          "JavaScript and TypeScript rules use a tokenizer, not a parser: they match fixed shapes and follow names only through simple bindings.",
          "The secret rules are high-precision on purpose and miss credentials with no recognizable shape or name.",
          "Dependency checks cover the lockfiles of nine ecosystems (PyPI, npm, Packagist, Go, crates.io, Maven, RubyGems, NuGet, Pub), not language runtimes, and need `kestrix-scan db update` first.",
        ),
        see("Measured accuracy", "code-security/accuracy"),
      ),
    ],
  },
  {
    path: "code-security/accuracy",
    title: "Accuracy: CVE-fix commits",
    nav: "Accuracy",
    summary: "How kestrix-scan, Bandit and ESLint's security plugin compare on files from real CVE fix commits, and the honest reading.",
    sections: [
      section(
        "What was measured",
        p("The benchmark scans the vulnerable and the fixed version of files from real CVE fix commits, and counts a detection when a finding of the right weakness family lands within 3 lines of a changed line. It uses CVEfixes v1.0.8 and the GitHub Advisory Database's fix commits. Projects, CVEs and files never straddle the development and test halves."),
        table(
          ["Split", "Projects", "CVEs", "File pairs (Python / JavaScript / TypeScript)", "Pairs in scope"],
          [
            ["Development", "1588", "4311", "13107 (5723 / 2331 / 5053)", "6634"],
            ["Locked test", "619", "1679", "4367 (1714 / 1430 / 1223)", "2172"],
          ],
        ),
        p("The tools were Bandit 1.9.4, ESLint 9.39.5 with eslint-plugin-security 4.2.0 (also without `detect-object-injection`, the rule projects usually switch off), and kestrix-scan 0.1.0. Each tool scanned only the languages it supports. Semgrep was not run, because its registry rules are not licensed for this use."),
      ),
      section(
        "Locked test result",
        p("Run once, on the test half, after the scanner was frozen. Intervals are 95% repository-bootstrap intervals."),
        table(
          ["Tool", "Language", "Detection", "Fix-aware", "False alarms per KLOC (fixed files)"],
          [
            ["kestrix-scan", "Python", "4.4% [2.4, 6.6]", "3.2% [1.5, 5.2]", "0.29 [0.17, 0.44]"],
            ["Bandit 1.9.4", "Python", "6.2% [4.3, 8.3]", "3.9% [2.2, 6.0]", "1.42 [0.99, 1.92]"],
            ["kestrix-scan", "JS/TS", "5.6% [3.9, 7.7]", "3.6% [2.1, 5.4]", "0.91 [0.52, 1.45]"],
            ["eslint-plugin-security 4.2.0", "JS/TS", "10.4% [7.6, 13.4]", "1.6% [0.8, 2.5]", "15.62 [13.25, 18.26]"],
            ["eslint-plugin-security without `detect-object-injection`", "JS/TS", "5.6% [3.2, 7.9]", "1.2% [0.6, 2.0]", "1.45 [1.04, 2.05]"],
          ],
        ),
      ),
      section(
        "The honest reading",
        list(
          "Kestrix detects less than Bandit on Python (−1.8 points, paired interval −3.6 to −0.3) at about a fifth of Bandit's false-alarm rate, and less than full ESLint security on JS/TS (−4.9 points, −8.4 to −1.3), whose lead comes with 17x the false alarms.",
          "Against ESLint without its noisiest rule, detection is equal, Kestrix raises fewer false alarms, and it is more often right that the fix removed the problem (fix-aware 3.6% against 1.2%).",
          "The tools find different bugs. Kestrix with Bandit detects 7.1% of Python pairs, and Kestrix with ESLint 15.1% of JS/TS pairs. Running them together beats either alone.",
          "Absolute detection is low for every tool, partly because the ground truth is coarse (a changed file of a fix commit, often without the weakness) and partly because many CVEs are design flaws (authorization, CSRF, logic) that pattern rules do not see. These numbers are not a claim that a scan finds most vulnerabilities.",
        ),
        note("The locked test is spent. Later rule changes need new held-out data, and the development numbers after the first round of rule changes are tuned numbers, not blind ones.", "caution"),
      ),
      section(
        "Round 2 on a fresh held-out set",
        p("A second round of rule changes was measured once on test2: 1,024 in-scope files from 522 projects, with no advisory, CVE, fix commit or file content shared with any tuning data."),
        table(
          ["Tool", "Language", "Detection", "False alarms per KLOC (fixed files)"],
          [
            ["kestrix-scan round 2", "Python", "7.7% [4.2, 12.0]", "0.23 [0.16, 0.29]"],
            ["kestrix-scan round 1", "Python", "7.5% [4.0, 11.6]", "0.22 [0.15, 0.29]"],
            ["Bandit 1.9.4", "Python", "10.2% [6.3, 14.2]", "0.99 [0.77, 1.21]"],
            ["kestrix-scan round 2", "JS/TS", "10.3% [7.2, 13.9]", "0.43 [0.24, 0.70]"],
            ["kestrix-scan round 1", "JS/TS", "9.0% [5.8, 12.9]", "0.40 [0.22, 0.66]"],
            ["eslint-plugin-security", "JS/TS", "12.4% [8.8, 16.1]", "16.93 [14.09, 19.90]"],
          ],
        ),
        list(
          "Round 2 helped a little on unseen code: detection 8.3% to 9.1% overall (+0.8 points, paired interval +0.1 to +1.6), mostly in JavaScript and TypeScript, for 3% more alerts.",
          "Bandit still detects more Python (−2.5 points, interval −4.7 to −0.2) at about four times the false alarms. On JS/TS, full ESLint security's lead (−2.0 points, interval −6.3 to +2.8) is not established, at about forty times the false alarms.",
          "Kestrix with Bandit detects 11.8% of Python pairs. test2 is now spent too.",
        ),
      ),
      section(
        "What is not claimed",
        list(
          "Not a detection rate for real-world code: a pair is a changed file of a fix commit, many of which hold no instance of the CVE's weakness, and a vulnerability can sit in a file the fix did not change. A \"miss\" is often not a miss.",
          "CWE labels are the CVE's, not the file's, and only CWEs that map to a weakness family are scored. About half the pairs are out of scope.",
          "False alarms are approximate: alerts on fixed and unchanged files can be real weaknesses.",
          "Tool defaults only: Bandit and ESLint were not tuned, and a project that configures them would see fewer alerts.",
          "Near-duplicates (backports with edits) remain, and Python 2 and unparsable files count as no finding.",
        ),
        p("Only counts, rates and rule ids are published; the mined files stay on the cluster and keep their projects' licenses."),
        see("Dataset attributions", "reference/licenses"),
      ),
    ],
  },
];
