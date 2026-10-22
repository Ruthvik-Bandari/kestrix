// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { PRIVACY_PATH, TERMS_PATH } from "../../../app/paths";
import { INSTALL_AI, INSTALL_DASHBOARD, INSTALL_EXIF, INSTALL_KESTRIX, INSTALL_SCAN, PYPI_PENDING } from "../../tools/content";
import { code, list, note, p, section, see, steps, table, type Block } from "../blocks";
import type { DocPage } from "../model";
import { HOSTED_DOC_PATH } from "../model";

/*
 * Getting started: what Kestrix is, how to install and run it, the hosted service and privacy.
 * Follows README.md, docs/hosted.md, docs/security-model.md and docs/release.md; when those change,
 * change this file in the same commit.
 */

const landing: Block = { kind: "landing", text: "See a real example report on the home page" };

export const gettingStartedPages: DocPage[] = [
  {
    path: "getting-started/what-is-kestrix",
    title: "What Kestrix is",
    nav: "What Kestrix is",
    summary: "An open-source security toolkit by Ruthvik Bandari: seven tools that run on your own computer.",
    sections: [
      section(
        "What it does",
        p(
          "Kestrix is an open-source security toolkit by Ruthvik Bandari. It fixes broken threat detections, inspects suspicious files and links, checks your website's defences, reads suspicious emails, tells you whether your Bitcoin addresses are exposed to future quantum attacks, and finds security mistakes in code, including the code an AI assistant writes.",
        ),
        p(
          "Every result starts with a plain answer and keeps the evidence that produced it. Heuristic scores are labeled as heuristics, never as probabilities, and a clean result always means that no check fired, not that something is safe.",
        ),
        landing,
      ),
      section(
        "Seven tools",
        { kind: "tools" },
        p("Each tool has its own section in these docs: what it is, how it works, how to use it, every finding it can report, and where its limits are."),
      ),
      section(
        "Two packages",
        list(
          "`kestrix-scan` is the code scanner and the Claude Code plugin. It has no dependencies on Python 3.11 and newer (only `tomli` on 3.10) and works in the terminal, CI, pre-commit, pytest and Claude Code.",
          "`kestrix` is the full workbench: every module, the `kestrix` CLI and the dashboard. It depends on `kestrix-scan`, so one install gives you both; `kestrix code scan` runs the same scanner.",
        ),
        p("Both need Python 3.10 or newer."),
        see("Install them", "getting-started/installation"),
      ),
      section(
        "How it fits together",
        steps(
          "One core: each module is a set of Python functions. The `kestrix` CLI and the dashboard's API call the same functions, so a result is the same wherever you run it.",
          "`kestrix dashboard` starts a FastAPI server on `127.0.0.1:8765` that serves the API and the bundled dashboard. It answers only local requests.",
          "Outbound requests are opt-in and say so first: the website check, the Bitcoin chain lookup and the AI guardian. Everything else works offline.",
          "Detection repair replays rules on a pinned Elasticsearch 8.19.3 that you start with Docker; it is the only matching oracle.",
          "`kestrix-scan` stands alone, and the workbench and the Claude Code plugin both call it.",
        ),
      ),
      section(
        "On your computer, or on the hosted service",
        p(
          "By default Kestrix runs on your own machine, with no accounts. The hosted service adds Google or GitHub sign-in and runs the email check, the web check and forensics on Kestrix's server. Detection repair, the Bitcoin check, the code scanner and the Claude Code plugin run on your computer only.",
        ),
        see("What the hosted service does and does not do", HOSTED_DOC_PATH),
        note("Use Kestrix only on systems, files and websites you own or are authorized to assess.", "caution"),
      ),
    ],
  },
  {
    path: "getting-started/installation",
    title: "Installation",
    nav: "Installation",
    summary: "Install the packages from the repository with uv, add the optional extras, and build the dashboard from source.",
    sections: [
      section(
        "Requirements",
        list(
          "Python 3.10 or newer, and `uv` to install the command-line tools.",
          "Node.js 20 or newer, only to build the web dashboard from a clone.",
          "Docker, only for detection repair, which replays rules on a pinned Elasticsearch.",
        ),
      ),
      section(
        "Install from the repository",
        note(PYPI_PENDING, "caution"),
        p("Neither package is published to PyPI yet, so install them from the repository with uv. The full workbench, with every command including `kestrix-scan`:"),
        code(INSTALL_KESTRIX),
        p("Only the code scanner and the Claude Code plugin:"),
        code(INSTALL_SCAN),
        p("Two optional extras install the same way: `exif` for photo metadata and `ai` for the Bitcoin guardian."),
        code(INSTALL_EXIF),
        code(INSTALL_AI),
        p("After the PyPI release you will also be able to run `pip install kestrix-scan` or `pip install kestrix` (or use `uv tool install` or `pipx install` with the package name)."),
      ),
      section(
        "Build the dashboard from source",
        p("The repository does not commit the built dashboard, so a repository install gives every CLI command but an empty dashboard. To run the dashboard, build it from a clone (needs Node.js 20 or newer):"),
        code(INSTALL_DASHBOARD),
        p("Until the PyPI release ships the dashboard bundle, this is the way to get it."),
      ),
      section(
        "Check it works",
        code("kestrix version"),
        p("Prints the installed version and the author. For the scanner on its own, `kestrix-scan version` does the same."),
        see("Run the dashboard", "getting-started/run-locally"),
      ),
    ],
  },
  {
    path: "getting-started/run-locally",
    title: "Run locally",
    nav: "Run locally",
    summary: "Start the dashboard on your own computer, use the CLI, and start the replay engine for detection repair.",
    sections: [
      section(
        "The dashboard",
        code("kestrix dashboard"),
        p("Opens the dashboard at `http://localhost:8765` (until the PyPI release, only after the from-source build under Installation). The server binds to `127.0.0.1`, answers only requests whose `Host` is a loopback name, refuses cross-site writes and has no accounts."),
        note("Do not run the dashboard on a machine you share with people you do not trust, and keep the default host unless something else controls access in front of it. See the security model.", "caution"),
        see("Read the security model", "security/threat-model"),
      ),
      section(
        "The command line",
        p("Every module also has commands, listed on each tool's page and in the CLI reference. Add `--json` to any command for machine-readable output. Exit codes are stable, so the commands work in scripts and CI."),
        code("kestrix mail analyze message.eml --json"),
        see("CLI commands", "reference/cli"),
      ),
      section(
        "Detection repair needs a replay engine",
        p("Detection repair is the only module that needs Docker. It runs a pinned Elasticsearch on `127.0.0.1:9200`; every other module works without it."),
        code("kestrix detect engine-up"),
        code("kestrix detect engine-status"),
        see("Detection repair", "tools/detection-repair/using-it"),
      ),
      section(
        "What leaves your computer",
        p("Nothing, unless you ask: the website check, the Bitcoin chain lookup, the AI guardian and `kestrix-scan db update` are the only features that open a connection, and each says so first."),
        see("Privacy and data handling", "security/data-handling"),
      ),
    ],
  },
  {
    path: HOSTED_DOC_PATH,
    title: "The hosted service",
    nav: "The hosted service",
    summary: "What is different when you use Kestrix on its website instead of on your own computer.",
    sections: [
      section(
        "What runs where",
        list(
          "You sign in with Google or GitHub. There are no passwords.",
          "Only the email check, the website check and file and link forensics run on the hosted service.",
          "Detection repair and Bitcoin are not available there. Run them on your own computer; their guide pages show how.",
          "The code scanner and the Claude Code plugin always run on your own computer.",
        ),
      ),
      section(
        "Local and hosted compared",
        table(
          ["Area", "On your computer", "Hosted service"],
          [
            ["Accounts", "None", "Sign-in with Google or GitHub; no passwords"],
            ["Modules", "All five, plus the code scanner", "Website check, forensics, email check"],
            ["Result history", "Kept 30 days, plaintext, in your Kestrix folder", "Kept 30 days per user, encrypted"],
            ["Website check", "Any port; private addresses allowed with a flag", "Public targets on ports 80 and 443 only; each scan needs your confirmation that you own the site or are authorized to test it"],
            ["Uploads", "Files up to 50 MiB, messages up to 25 MiB", "Both up to 10 MiB"],
            ["Analyses", "In the server process", "In a separate worker process with CPU, memory and time limits"],
            ["Concurrency", "No limit", "One request at a time per user; at most 2 analyses and 8 website checks at once"],
            ["Rate limits", "None", "Per user and per IP"],
          ],
        ),
      ),
      section(
        "What happens to your input",
        list(
          "Files and emails are analyzed on Kestrix's server and are never stored. An upload over 1 MiB waits in a temporary file while it is processed, and that file is deleted when the request ends.",
          "Each analysis runs in a separate worker process with CPU, memory and time limits.",
          "Files and messages are limited to 10 MiB each. On your own computer the limits are 50 MiB for files and 25 MiB for messages.",
          "A website check is sent from Kestrix's server, not from your computer. It reaches public addresses only, on ports 80 and 443, and every scan needs your confirmation that you own the site or are authorized to test it.",
          "A link is analyzed as text and never opened.",
        ),
      ),
      section(
        "Saved reports",
        list(
          "After a check, its report is saved for you for 30 days, encrypted. The file or message you uploaded is not saved.",
          "A saved email report holds the subject, the sender and short evidence, not the message body.",
          "You can delete one report or all of them, or turn history off in Settings. Turning it off deletes your saved reports and stops saving new ones. Deleting your account deletes them too.",
        ),
      ),
      section(
        "Limits",
        list(
          "Website checks: 20 per hour per account, and at most 5 of those can be whole-site scans.",
          "Email, file and link checks share one allowance of 120 per hour per account.",
          "One check runs at a time per account. A second one is refused until the first finishes.",
        ),
      ),
      section(
        "Privacy and terms",
        p("The full notices are separate pages."),
        { kind: "route", text: "Read the privacy notice", to: PRIVACY_PATH },
        { kind: "route", text: "Read the terms", to: TERMS_PATH },
      ),
    ],
  },
];
