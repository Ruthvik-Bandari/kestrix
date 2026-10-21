// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { toolFor, type ToolPage } from "../../app/tools";
import type { IconName } from "../../components/Icon";
import { INSTALL_AI, INSTALL_DASHBOARD, INSTALL_EXIF, INSTALL_KESTRIX, INSTALL_SCAN, toolContent } from "../tools/content";
import { code, list, p, steps, type DocSection } from "./blocks";

/*
 * The in-app documentation. It summarizes README.md, docs/modules/*.md,
 * packages/kestrix-scan/README.md, docs/claude-plugin.md and ADR 0006, and must never contradict
 * them: when those change, change this file in the same commit. Each tool's page is built from
 * app/tools.ts and features/tools/content.ts, so nothing about a tool is written twice.
 */

export type DocGroup = "Start" | "Tools" | "Packages and integrations";

export interface DocPage {
  /** "" for the overview, at /docs. */
  slug: string;
  title: string;
  nav: string;
  group: DocGroup;
  icon: IconName;
  lede: string;
  sections: DocSection[];
  /** A tool's page ends with its install-and-use guide (features/tools/ToolGuide). */
  tool?: ToolPage;
}

function toolPage(page: ToolPage, group: DocGroup = "Tools"): DocPage {
  const tool = toolFor(page);
  return {
    slug: page,
    title: tool.name,
    nav: tool.name,
    group,
    icon: tool.icon,
    lede: tool.summary,
    sections: toolContent[page].reference,
    tool: page,
  };
}

const overview: DocPage = {
  slug: "",
  title: "Kestrix documentation",
  nav: "Overview",
  group: "Start",
  icon: "bookOpen",
  lede: "Security checks for your code, and a local-first security workbench. Everything runs on your own machine.",
  sections: [
    {
      heading: "What Kestrix is",
      blocks: [
        p(
          "Kestrix is an open-source security toolkit by Ruthvik Bandari. It fixes broken threat detections, inspects suspicious files and links, checks your website's defences, reads suspicious emails, tells you whether your Bitcoin addresses are exposed to future quantum attacks, and finds security mistakes in code, including the code an AI assistant writes.",
        ),
        p(
          "Every result starts with a plain answer and keeps the evidence that produced it. Heuristic scores are labeled as heuristics, never as probabilities, and a clean result always means that no check fired, not that something is safe.",
        ),
        { kind: "landing", text: "See a real example report on the home page" },
      ],
    },
    {
      heading: "Two packages",
      blocks: [
        list(
          "`kestrix-scan` is the code scanner and the Claude Code plugin. It has no dependencies on Python 3.11 and newer (only `tomli` on 3.10) and works in the terminal, CI, pre-commit, pytest and Claude Code.",
          "`kestrix` is the full workbench: every module, the `kestrix` CLI and the dashboard. It depends on `kestrix-scan`, so one install gives you both; `kestrix code scan` runs the same scanner.",
        ),
        p("Both need Python 3.10 or newer. Install commands and options are on the pip packages page."),
      ],
    },
    { heading: "Seven tools", blocks: [{ kind: "tools" }] },
    {
      heading: "How it fits together",
      blocks: [
        steps(
          "One core: each module is a set of Python functions. The `kestrix` CLI and the dashboard's API call the same functions, so a result is the same wherever you run it.",
          "`kestrix dashboard` starts a FastAPI server on `127.0.0.1:8765` that serves the API and the bundled dashboard. It answers only local requests.",
          "Outbound requests are opt-in and say so first: the website check, the Bitcoin chain lookup and the AI guardian. Everything else works offline.",
          "Detection repair replays rules on a pinned Elasticsearch 8.19.3 that you start with Docker; it is the only matching oracle.",
          "`kestrix-scan` stands alone, and the workbench and the Claude Code plugin both call it.",
        ),
      ],
    },
    {
      heading: "On your computer, or on the hosted service",
      blocks: [
        p(
          "By default Kestrix runs on your own machine, with no accounts. The hosted service adds Google or GitHub sign-in and runs the email check, the web check and forensics on Kestrix's server; uploaded files and emails are never stored. The reports of those checks are kept for 30 days in Recent results (encrypted on the hosted service, in your Kestrix folder locally) so you can open them again; you can delete them or turn history off in Settings.",
        ),
        p(
          "Detection repair, the Bitcoin check, the code scanner and the Claude Code plugin run on your computer only. Their pages on the hosted service are guides to installing and using them.",
        ),
        p("Use Kestrix only on systems, files and websites you own or are authorized to assess."),
      ],
    },
  ],
};

const packages: DocPage = {
  slug: "packages",
  title: "The pip packages",
  nav: "pip packages",
  group: "Packages and integrations",
  icon: "package",
  lede: "Install, run and configure kestrix-scan and kestrix, in the terminal, pre-commit, GitHub and pytest.",
  sections: [
    {
      heading: "Install",
      blocks: [
        p(
          "PyPI release pending: neither package is published to PyPI yet, so install them from the repository with uv.",
        ),
        code(INSTALL_KESTRIX),
        p("Every workbench command, including `kestrix-scan`. Two optional extras, `exif` for photo metadata and `ai` for the Bitcoin guardian, install the same way:"),
        code(INSTALL_EXIF),
        code(INSTALL_AI),
        code(INSTALL_SCAN),
        p("Only the code scanner and the Claude Code plugin."),
        p("The web dashboard is not built into a repository install yet. To run it, build it from a clone (needs Node.js 20 or newer):"),
        code(INSTALL_DASHBOARD),
        p(
          "After the PyPI release you will also be able to run `pip install kestrix-scan` or `pip install kestrix` (or use `uv tool install` or `pipx install` with the package name).",
        ),
      ],
    },
    {
      heading: "The kestrix-scan command",
      blocks: [
        code("kestrix-scan src"),
        list(
          "`--format text|json|sarif`: the output format. SARIF 2.1.0 is for GitHub code scanning.",
          "`--output FILE`: write the report to a file instead of stdout.",
          "`--fail-on low|medium|high|critical|none`: the lowest severity that makes the command exit 1 (default `high`).",
          "`--diff REF`: only report findings on lines changed since a git ref.",
          "`--baseline FILE` and `--write-baseline FILE`: leave out known findings, or record the current ones.",
          "`--config FILE` and `--no-config`: use one settings file, or ignore settings files.",
        ),
        p("Exit codes: 0 nothing at or above `--fail-on`, 1 findings at or above it, 2 usage or input error. `kestrix-scan rules` lists every rule."),
        p("Silence a confirmed false positive on its line, or the line above, with a required reason: `# kestrix: ignore[py.subprocess.shell_true] command from the reviewed deploy config`."),
      ],
    },
    {
      heading: "Dependencies",
      blocks: [
        code("kestrix-scan db update"),
        p(
          "Downloads the public OSV data for PyPI and npm: the only command that uses the network. Scans then check `requirements*.txt` pins and `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, `package-lock.json`, `yarn.lock` and `pnpm-lock.yaml` offline. `kestrix-scan db status` shows the index.",
        ),
      ],
    },
    {
      heading: "Configuration",
      blocks: [
        p("`[tool.kestrix]` in `pyproject.toml`, or the same keys at the top level of `.kestrix.toml`. The nearest file wins, and command-line flags override it."),
        code(
          `[tool.kestrix]
fail-on = "medium"                              # low, medium, high, critical or none
exclude = ["tests/fixtures/", "*.min.js"]       # globs, as in .gitignore
baseline = ".kestrix-baseline.json"             # relative to this file
rules.enable = ["py.", "secret."]               # rule ids or prefixes; default: every rule
rules.disable = ["py.crypto.weak_hash"]`,
          "pyproject.toml",
        ),
        p("`kestrix-scan init` appends a minimal `[tool.kestrix]` without rewriting the file; `--pre-commit`, `--ci github` and `--claude-plugin` set up the rest."),
        code("kestrix-scan init --ci github --pre-commit"),
      ],
    },
    {
      heading: "pre-commit",
      blocks: [
        code(
          `repos:
  - repo: https://github.com/Ruthvik-Bandari/kestrix
    rev: v0.1.0
    hooks:
      - id: kestrix-scan`,
          ".pre-commit-config.yaml",
        ),
        p("The hook scans the staged Python and text files and honours `[tool.kestrix]`."),
      ],
    },
    {
      heading: "GitHub Action",
      blocks: [
        p(
          "`kestrix-scan init --ci github` writes `.github/workflows/kestrix.yml`. Its actions are pinned to commit SHAs and its job has only `contents: read` and `security-events: write`. The key steps:",
        ),
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
        p(
          "The generated workflow installs `kestrix-scan` from PyPI, so it only works after the PyPI release. Until then, replace that step with the repository install shown under Install, which needs uv on the runner.",
        ),
      ],
    },
    {
      heading: "pytest",
      blocks: [
        code("pytest --kestrix"),
        code("pytest --kestrix --kestrix-fail-on=medium"),
        p("Adds one `kestrix-scan` item that scans the rootdir and fails when findings meet the threshold. Without `--kestrix` the scanner is not even imported."),
      ],
    },
    {
      heading: "The kestrix workbench CLI",
      blocks: [
        code("kestrix dashboard"),
        p("Opens the dashboard at `http://localhost:8765` (until the PyPI release, only after the from-source build in Install). Every module also has commands; each tool's page lists them."),
        p("Add `--json` to any command for machine-readable output. Exit codes are stable, so the commands work in scripts and CI."),
      ],
    },
  ],
};

const TOOL_DOCS: ToolPage[] = ["mail", "webcheck", "forensics", "detect", "code", "bitcoin"];

export const docPages: DocPage[] = [
  overview,
  ...TOOL_DOCS.map((page) => toolPage(page)),
  packages,
  toolPage("claude-plugin", "Packages and integrations"),
];

export const DOC_GROUPS: DocGroup[] = ["Start", "Tools", "Packages and integrations"];

export function findDoc(slug: string | undefined): DocPage | undefined {
  const key = slug === undefined || slug === "overview" ? "" : slug;
  return docPages.find((page) => page.slug === key);
}
