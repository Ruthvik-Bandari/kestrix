// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { PRIVACY_PATH, TERMS_PATH } from "../../../app/paths";
import { code, list, note, p, section, see, steps, table } from "../blocks";
import type { DocPage } from "../model";
import { HOSTED_DOC_PATH } from "../model";

/*
 * Security and trust. Follows SECURITY.md, docs/security-model.md (the threat model page lives in
 * ./reference.ts), docs/hosted.md, docs/release.md, NOTICE and .github/workflows/release.yml.
 * Anything not yet true is marked pending.
 */

export const securityPages: DocPage[] = [
  {
    path: "security/reporting",
    title: "Report a vulnerability",
    nav: "Report a vulnerability",
    summary: "How to report a security problem in Kestrix privately, which versions get fixes, what is in scope and how good-faith research is treated.",
    sections: [
      section(
        "Report it privately",
        steps(
          "Email ruthvik299@gmail.com with a subject that starts with \"Kestrix security\". If you can see the Kestrix repository, you can use its private vulnerability reporting (a private security advisory) instead.",
          "Describe the issue, the affected version or commit, and the steps to reproduce it. A minimal proof of concept helps.",
          "Say whether you want to be credited, and under what name.",
        ),
        note("Security contact: ruthvik299@gmail.com. Use it for vulnerability reports only; it is read by the single maintainer.", "info"),
        note("Do not open a public issue, pull request or discussion for a vulnerability. Kestrix has a single maintainer, so response times vary. You get a reply by email (or in the advisory thread), and the fix, the advisory and the credit are coordinated with you there.", "caution"),
      ),
      section(
        "Supported versions",
        table(
          ["Version", "Security fixes"],
          [
            ["0.1.x", "Yes"],
            ["Earlier code in the repository (the retired CTPPO prototype)", "No"],
          ],
        ),
        p("Fixes go into the latest 0.1 release. Kestrix is not yet published to PyPI, so until then the latest commit on the main branch is what is supported."),
      ),
      section(
        "What is in scope",
        list(
          "The `kestrix` package and CLI, the local server and its loopback-only, cross-site and body-size protections, and the bundled dashboard.",
          "Parsing of untrusted rules, mappings, fixtures, files, URLs and addresses.",
          "Outbound request guards (the website check and mempool.space lookups), and storage of the Anthropic API key.",
          "The CI workflow and the release artifacts built from the repository.",
          "The hosted service, once its owner has launched it: sign-in, sessions and CSRF, rate limits, upload handling, the website check's target restrictions, the encrypted result history and the response headers.",
        ),
        p("Out of scope: vulnerabilities in third-party services or in dependencies (report those to their maintainers), the replay engine's own security settings (which `detect engine-up` disables by design for a loopback-only engine), findings that need an attacker who already runs code as your user, limitations the threat model already lists, and the results of the heuristic checks, which are accuracy issues to raise as normal issues."),
        see("The threat model and its known limitations", "security/threat-model"),
      ),
      section(
        "Safe harbor",
        p("Research done in good faith under this policy is authorized, and no legal action will be taken or supported against you for it. Good faith means:"),
        list(
          "you test only against your own installation and systems you own or are permitted to test;",
          "you do not access, change or delete other people's data;",
          "you do not degrade services, including mempool.space and the Anthropic API;",
          "you report promptly and keep the details private until a fix is released or a disclosure date is agreed.",
        ),
        p("On the hosted service, test only with accounts you created, stay within the published rate limits (no load or denial-of-service testing), and never run a website check against a site you do not own or have permission to test. This policy cannot authorize testing of third-party systems."),
      ),
    ],
  },
  {
    path: "security/data-handling",
    title: "Privacy and data handling",
    nav: "Data handling",
    summary: "What each mode reads, what leaves your computer and only when you ask, what is stored where, and for how long.",
    sections: [
      section(
        "Local and hosted compared",
        table(
          ["", "On your computer", "On the hosted service"],
          [
            ["Uploads (files, messages)", "Read on your machine; never sent anywhere", "Analyzed on Kestrix's server and never stored; an upload over 1 MiB waits in a temporary file that is deleted when the request ends"],
            ["Saved reports", "30 days, plaintext, in `history.sqlite3` in your Kestrix folder (mode 0600); you can delete them or turn history off", "30 days per user, encrypted with AES-256-GCM; you can delete them, turn history off, or delete your account"],
            ["What a saved report holds", "Reason codes, hosts, hashes and short evidence; never the message body, link text or attachment bytes", "The same; an email report holds the subject, the sender and short evidence"],
            ["Accounts", "None", "Sign-in with Google or GitHub; no passwords"],
            ["Logs", "Standard server log", "Method, route, status, duration and a salted user hash; never bodies, file names, emails, query strings, cookies or tokens"],
            ["API key", "Optional Anthropic key in `secrets.json` (mode 0600), plain JSON, not in the OS keychain", "Not used; the Bitcoin guardian is not available"],
          ],
        ),
      ),
      section(
        "What leaves your computer, only when you ask",
        table(
          ["Feature", "What is sent", "To whom"],
          [
            ["Website check", "Read-only GET requests to the site you name, plus one TLS handshake", "That site (from your computer, or from Kestrix's server on the hosted service)"],
            ["Bitcoin chain lookup (`--lookup-chain`)", "Each looked-up hash-based address, with your IP address", "mempool.space"],
            ["Bitcoin guardian (`kestrix bitcoin ask`)", "Your message", "The Anthropic API, with your own key"],
            ["`kestrix-scan db update`", "A plain GET for each ecosystem's public vulnerability export; nothing about your project", "OSV"],
            ["Claude Code plugin", "Hook output is part of your conversation: rule ids, paths, line numbers, messages and fixes, never secret values", "Anthropic, like any other conversation content"],
          ],
        ),
        p("Everything else works offline. Scans, the scanner's hooks and the install guard read the local copy of the vulnerability data and open no connection; a test proves it by refusing every socket call."),
      ),
      section(
        "What is never done with your input",
        list(
          "Links are never visited, HTML is never rendered, attachments are never opened and files are never executed.",
          "A secret found in code is never written to any output: findings show only its kind, its location and its first four characters.",
          "Your uploads are not used for anything but the analysis you asked for.",
        ),
      ),
      section(
        "Notices",
        p("The hosted service has a privacy notice and terms of its own."),
        { kind: "route", text: "Read the privacy notice", to: PRIVACY_PATH },
        { kind: "route", text: "Read the terms", to: TERMS_PATH },
        see("The hosted service", HOSTED_DOC_PATH),
      ),
    ],
  },
  {
    path: "security/authorized-use",
    title: "Authorized use",
    nav: "Authorized use",
    summary: "Use Kestrix only on systems, files and websites you own or are authorized to assess, and how the tools enforce and respect that.",
    sections: [
      section(
        "The rule",
        note("Use Kestrix only on systems, files and websites you own or are authorized to assess.", "caution"),
        p("Kestrix is a defensive tool. Its checks are read-only, and it has no feature that exploits a weakness or that sends anything beyond what a check needs."),
      ),
      section(
        "How each tool keeps to it",
        table(
          ["Tool", "What it does and does not do"],
          [
            ["Web check", "Shows an authorization notice before it sends anything. It sends read-only GET requests only, never submits a form, logs in, follows a link to another site, fuzzes or scans ports. On the hosted service every scan needs your confirmation that you own the site or are authorized to test it, and only public targets on ports 80 and 443 are reachable."],
            ["File & link forensics, Email check", "Read what you give them. Files are never executed and links are never opened."],
            ["Bitcoin quantum risk", "Takes public addresses and public keys only. It never asks for private keys or seed phrases and cannot sign, send or move coins."],
            ["Code scanner and plugin", "Read files as data and never import, execute or upload them."],
            ["Detection repair", "Replays labeled events on a local engine bound to `127.0.0.1`."],
          ],
        ),
        p("`--allow-private` lifts the public-address rule for one website check. Use it only for hosts you control."),
      ),
      section(
        "If you find a problem in Kestrix itself",
        see("Report a vulnerability", "security/reporting"),
      ),
    ],
  },
  {
    path: "security/supply-chain",
    title: "Supply chain and releases",
    nav: "Supply chain",
    summary: "How Kestrix's source, dependencies and releases can be checked, and which parts are still pending the first release.",
    sections: [
      section(
        "Source",
        list(
          "Commits on the main branch carry verified signatures. Check them yourself with `git log --show-signature` after adding the author's key.",
          "Source files carry SPDX license headers, and the repository's `NOTICE` file records every third-party notice with its source, copyright holder and license.",
          "Third-party code, rules or data are added only under a license that permits redistribution with Apache-2.0, and each addition is recorded in `NOTICE` in the same change.",
          "The code scanner's rules were written for Kestrix from their CWE entries and documentation; no rule text from other scanners was used.",
        ),
        code("git log --show-signature -3"),
      ),
      section(
        "Dependencies",
        list(
          "The Python environment is locked in `uv.lock` and the dashboard's in `package-lock.json`; installs in CI and in the container use the locks.",
          "The code scanner has no runtime dependencies on Python 3.11 and newer (only `tomli` on 3.10).",
          "No advisory data ships with Kestrix. `kestrix-scan db update` downloads it, with each source's license recorded in `NOTICE`.",
        ),
        see("Licenses and attribution", "reference/licenses"),
      ),
      section(
        "Releases",
        note("Pending. Neither package has been published to PyPI, so no release exists to verify yet. Install from the repository until then.", "caution"),
        p("The release workflow is written and runs on a `v*` tag. When a release exists it works like this:"),
        steps(
          "The workflow checks that the tag equals the version in both packages' `pyproject.toml`.",
          "It builds the dashboard and both packages.",
          "It records a build provenance attestation for every file it builds, using GitHub's attest-build-provenance action.",
          "It publishes `kestrix-scan`, then `kestrix`, to PyPI with trusted publishing, so no PyPI API token exists anywhere. The publish waits for the owner's approval.",
        ),
        p("Once a release is published, anyone can check that a wheel was built by this repository's release workflow:"),
        code(
          `pip download --no-deps kestrix-scan==0.1.0 -d /tmp/k
gh attestation verify /tmp/k/kestrix_scan-0.1.0-py3-none-any.whl --repo Ruthvik-Bandari/kestrix`,
          "Works only after the first release",
        ),
        p("The workflow's third-party actions are pinned to commit SHAs."),
      ),
    ],
  },
];
