// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { INSTALL_KESTRIX, INSTALL_SCAN } from "../../tools/content";
import { code, list, note, p, section, see, steps, table } from "../blocks";
import type { DocPage } from "../model";
import { HOSTED_DOC_PATH } from "../model";

/*
 * Quickstart, troubleshooting, what's new and the configuration reference. The quickstart commands were run on
 * a clean directory and print what is described. Follows README.md, CHANGELOG.md, docs/modules/*.md and
 * docs/claude-plugin.md.
 */

const SAMPLE_EML = `cat > sample.eml <<'EOF'
From: "Example Bank" <alerts@notice.example>
To: you@mail.example
Subject: Verify your account
Date: Thu, 22 Oct 2026 09:00:00 +0000
Message-ID: <1@notice.example>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Please <a href="https://login.notice.example/verify">www.example-bank.com</a> to verify your account.</p>
EOF`;

const SAMPLE_PY = `mkdir -p app
cat > app/deploy.py <<'EOF'
import subprocess


def run(cmd):
    subprocess.run(cmd, shell=True)
EOF`;

export const guidePages: DocPage[] = [
  {
    path: "getting-started/quickstart",
    title: "Quickstart: two checks in five minutes",
    nav: "Quickstart",
    summary: "Install Kestrix, check a made-up phishing email, and scan a small Python file, using only files you create here.",
    sections: [
      section(
        "Before you start",
        list("You have Python 3.10 or newer with `pip`.", "You work in an empty scratch directory. Nothing here uses real data, and nothing leaves your computer."),
      ),
      section("Install", code(INSTALL_KESTRIX), code("kestrix version")),
      section(
        "Check an email",
        steps(
          "Create a made-up message. It uses `.example` domains, which cannot be real.",
          "Check it.",
          "Read the result.",
        ),
        code(SAMPLE_EML, "sample.eml"),
        code("kestrix mail analyze sample.eml"),
        p("The verdict is `malicious`, with a heuristic score of 50 out of 100. Three findings explain it: the link text shows one site but the link goes to another (high), the subject asks you to verify an account (medium), and no authentication results are present, which makes the verdict less certain without making it worse (info). The score is a heuristic, not a probability."),
        see("Every email finding", "tools/email/findings"),
      ),
      section(
        "Scan some code",
        p("Install the scanner on its own (it is also part of the package above), create a small file with a known mistake, and scan it."),
        code(INSTALL_SCAN),
        code(SAMPLE_PY, "app/deploy.py"),
        code("kestrix-scan app"),
        p("The scan reports one finding, `py.subprocess.shell_true` (high, CWE-78), with the fix: pass the command as a list of arguments without `shell=True`. The command exits 1 because a finding is at or above the default `--fail-on high`."),
        see("Every rule", "code-security/rules"),
      ),
      section(
        "Where to go next",
        list(
          "Open the dashboard to use every tool in the browser.",
          "Wire the scanner into your project: configuration, a baseline, pre-commit and CI.",
          "Read how far to trust a result: every tool has a limits and accuracy page.",
        ),
        see("Run the dashboard", "getting-started/run-locally"),
        see("Set up the scanner in a project", "code-security/kestrix-scan/configuration"),
      ),
    ],
  },
  {
    path: "getting-started/troubleshooting",
    title: "Troubleshooting and FAQ",
    nav: "Troubleshooting and FAQ",
    summary: "Answers to the questions people ask first, and fixes for the errors people hit first.",
    sections: [
      section(
        "Questions",
        table(
          ["Question", "Answer"],
          [
            ["Does a clean result mean it is safe?", "No. A clean result means none of the checks fired. Heuristic scores are labeled heuristics and are never probabilities."],
            ["Does Kestrix send my file or email anywhere?", "No, unless you use the hosted service, where it is analyzed on the server and never stored. The only features that open a connection on your computer are the website check, the Bitcoin lookup and guardian, and `kestrix-scan db update`."],
            ["Which tools work on the hosted service?", "The email check, the website check and file and link forensics. Detection repair, Bitcoin and the code tools run on your computer."],
            ["Can I scan any website?", "Only sites you own or are authorized to assess."],
            ["Is there a pip package?", "Yes. `pip install kestrix-scan` for the code scanner and Claude Code plugin, `pip install kestrix` for everything."],
            ["How accurate is it?", "Each tool's limits and accuracy page gives the measured numbers, with their caveats, and says where nothing has been measured."],
          ],
        ),
        see("Data handling", "security/data-handling"),
        see("The hosted service", HOSTED_DOC_PATH),
      ),
      section(
        "Problems",
        table(
          ["Symptom", "Cause and fix"],
          [
            ["The dashboard page is empty or answers `dashboard_not_built`", "A repository install has every CLI command but no built dashboard. Build it from a clone: `npm --prefix frontend ci && npm --prefix frontend run build`, then reinstall."],
            ["`Rejected (invalid_input)` on an email", "The file has none of the usual message headers. Save the message itself as `.eml` rather than copying its text."],
            ["The email verdict is `insufficient_evidence`", "No trusted `Authentication-Results` header was found. Pass `--trusted-authserv-id` with your provider's `authserv-id`."],
            ["Web check exits 2 with `target_not_allowed`", "The address resolves to a private or loopback range. Use `--allow-private` only for hosts you control."],
            ["Web check exits 3", "The site did not answer within 10 seconds, or redirected more than 5 times."],
            ["A web check grade of F with few findings", "The grade is forced to F when the final URL is not HTTPS or TLS is not ok."],
            ["Detection repair reports `engine_unavailable` (exit 3)", "Start the engine with `kestrix detect engine-up` (it needs Docker), then check `kestrix detect engine-status`."],
            ["Detection repair reports `unsupported` (exit 11)", "The rule uses semantics outside the supported Sigma subset: single-event Windows `process_creation` rules."],
            ["`exif_status` is `pillow_not_installed`", "Install Kestrix with the `exif` extra."],
            ["`kestrix-scan` exits 1", "A finding is at or above `--fail-on`. Fix it, suppress a confirmed false positive with a reason, or baseline existing findings."],
            ["`kestrix-scan` exits 2", "A usage or input error: a missing path, a bad baseline, an unknown git ref or an unknown rule id in the settings."],
            ["A `dep.db_stale` note", "The vulnerability index is missing or more than 7 days old. Run `kestrix-scan db update`."],
            ["The Claude Code plugin shows nothing", "The hooks fail open. Check that `kestrix-scan` and `python3` are on PATH, and run `/kestrix:status` to see which files were not checked and why."],
            ["`ai_key_missing` from the Bitcoin guardian", "Install the `ai` extra, then set `ANTHROPIC_API_KEY` or run `kestrix config set-anthropic-key`."],
          ],
        ),
        p("Each tool's Using it page has a troubleshooting list for that tool."),
      ),
    ],
  },
  {
    path: "reference/configuration",
    title: "Configuration reference",
    nav: "Configuration",
    summary: "Every setting you can change: environment variables, the scanner's settings file, and where Kestrix keeps its files.",
    sections: [
      section(
        "Environment variables",
        table(
          ["Variable", "Used by", "Effect"],
          [
            ["`KESTRIX_HOME`", "All", "The config folder (`secrets.json`, local result history). Default: `$XDG_CONFIG_HOME/kestrix`, which defaults to `~/.config/kestrix` (`%APPDATA%\\kestrix` on Windows)."],
            ["`ANTHROPIC_API_KEY`", "Bitcoin guardian", "Your own key; used before the stored one."],
            ["`KESTRIX_AI_MODEL`", "Bitcoin guardian", "A model id to use instead of the default."],
            ["`KESTRIX_ES_URL`", "Detection repair", "The replay engine's URL. Default `http://127.0.0.1:9200`."],
            ["`KESTRIX_SCAN_DB`", "kestrix-scan", "Where the vulnerability index is kept. Default: the user cache folder."],
            ["`KESTRIX_BLOCK_ON_STOP`", "Claude Code plugin", "`1` turns the Stop gate on; `0` turns it off even when `.kestrix.json` turns it on."],
            ["`KESTRIX_INSTALL_GUARD`", "Claude Code plugin", "`0` turns the install guard off."],
            ["`KESTRIX_MODE`", "Server", "`local` (default) or `hosted`. The hosted service has further variables for its operator, which are documented in the repository."],
          ],
        ),
      ),
      section(
        "The scanner's settings file",
        p("`[tool.kestrix]` in `pyproject.toml`, or the same keys in `.kestrix.toml`: `fail-on`, `exclude`, `baseline`, `rules.enable`, `rules.disable`, `ignore-advisories` and `claude.install-guard`."),
        see("Every setting", "code-security/kestrix-scan/configuration"),
      ),
      section(
        "Command-line options",
        see("CLI commands", "reference/cli"),
      ),
      section(
        "Hosted service variables (operators)",
        p("The hosted service reads these from its host's secret store, and refuses to start with a message naming any required one that is missing or malformed."),
        table(
          ["Variable", "Required", "Meaning"],
          [
            ["`KESTRIX_PUBLIC_ORIGIN`", "Yes", "The public `https://` origin, with no path, query or credentials."],
            ["`KESTRIX_SESSION_PEPPER`", "Yes", "A secret of at least 32 bytes that keys refresh-token, CSRF and state hashes. Changing it signs everyone out."],
            ["`KESTRIX_JWT_SECRET`", "Yes", "A different secret of at least 32 bytes that signs access tokens."],
            ["`KESTRIX_JWT_SECRET_PREVIOUS`", "No", "The previous JWT secret during a rotation; accepted only to verify."],
            ["`KESTRIX_HISTORY_KEY`", "Yes", "Exactly 32 random bytes, base64-encoded: the AES-256-GCM key for saved reports."],
            ["`KESTRIX_HISTORY_KEY_PREVIOUS`", "No", "The previous history key during a rotation; used only to decrypt."],
            ["`KESTRIX_GOOGLE_CLIENT_ID`, `KESTRIX_GOOGLE_CLIENT_SECRET`, `KESTRIX_GITHUB_CLIENT_ID`, `KESTRIX_GITHUB_CLIENT_SECRET`", "One provider", "Sign-in providers. A provider is on only when both of its values are set."],
            ["`KESTRIX_DB`", "No", "The SQLite file, which belongs on a persistent volume."],
            ["`KESTRIX_LOG_SALT`", "No", "At least 16 bytes; salts the user-id hash in logs."],
            ["`KESTRIX_ABUSE_CONTACT`", "No", "A contact address added to the website check's `User-Agent`."],
            ["`KESTRIX_CLIENT_IP_HEADER`, `KESTRIX_TRUST_PROXY_HEADERS`", "No", "How the client IP for per-IP limits is read behind a proxy; they cannot be combined."],
            ["`KESTRIX_HSTS_PRELOAD`", "No", "`1` adds `preload` to the HSTS header. Off by default."],
            ["`PORT`", "No", "The listening port for `kestrix serve-hosted` (default 8000)."],
          ],
        ),
      ),
    ],
  },
  {
    path: "reference/whats-new",
    title: "What's new",
    nav: "What's new",
    summary: "The notable changes since the project began. Kestrix has no tagged release yet, so everything is listed as unreleased.",
    sections: [
      section(
        "Status",
        note("Kestrix has not had a release. The changelog's `Unreleased` section is the current state of the main branch, and before 1.0 a minor version may change commands, report fields or API routes.", "caution"),
      ),
      section(
        "Unreleased",
        list(
          "Link and file checker: five new file findings (`macro_office_file`, `encrypted_archive`, `embedded_executable`, `active_content_svg`, `runnable_script_file`) and two new link findings (`hosting_platform_subdomain`, `digits_in_subdomain`). Legacy Office and Flash files no longer raise high-entropy findings. Development-split measurements are on the limits page.",
          "Recent results: after a check, the report (never the upload) is kept for 30 days, with routes to list and delete it and a setting to turn it off. On the hosted service it is encrypted per user.",
          "Hosted sign-in uses 15-minute access tokens and rotating refresh tokens, and the landing page has Log in and Sign up tabs.",
          "Code scanner: five new Python rules (reflected XSS, LDAP and XPath injection, insecure cookies, session trust boundary), better taint handling, and a measurement on CVE-fix commits whose locked test has been run once.",
          "Email check: round-1 rule changes measured on a locked test.",
        ),
        see("Email check accuracy", "tools/email/limits"),
        see("Scanner accuracy", "code-security/accuracy"),
      ),
    ],
  },
];
