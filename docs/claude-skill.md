# Claude skill

> **In Claude Code, install the [Kestrix plugin](claude-plugin.md) instead.** It includes this skill, and it adds hooks that scan the code Claude writes, a secure-review skill and the `/kestrix:scan`, `/kestrix:fix` and `/kestrix:review` commands. The standalone install below still works, and it is the way to use the skill in Claude.ai or Claude Desktop.

Kestrix ships a Claude skill (an Agent Skill) named `kestrix-security`. With it installed, you can ask Claude everyday security questions in plain language,
and Claude runs the matching `kestrix` command on your machine, reads the JSON report and explains it:
the verdict first, the two or three most important reasons, then what to do next.

It covers:

- **Email triage:** "Is this email a phish?" on a saved `.eml` file (`kestrix mail analyze`).
- **Link checks:** "Is this link safe?" (`kestrix forensics url`). The link is read as text, never opened.
- **File checks:** "What is this attachment?" (`kestrix forensics file`). The file is never executed.
- **Website checks:** headers, TLS and cookies of a site you own (`kestrix webcheck scan`). Claude asks
  you to confirm you own or are authorized to test the site first.
- **Detection repair:** "Why didn't my Sigma rule fire?" on the bundled cases or your own rule, mapping and
  labeled events (`kestrix detect`). Needs Docker for the pinned Elasticsearch.
- **Bitcoin:** quantum exposure of public addresses and a migration plan (`kestrix bitcoin`).

The skill is Markdown only: `SKILL.md` with the workflows and safety rules, plus `reference/` files that
Claude loads when it needs them (every finding id with its severity, and a guide to the JSON fields). The
source is [`src/kestrix/integrations/claude_plugin/kestrix/skills/kestrix-security/`](../src/kestrix/integrations/claude_plugin/kestrix/skills/kestrix-security/),
inside the Claude Code plugin, and it ships inside the `kestrix` wheel. The plugin and the standalone
install below use the same files.

## Install for Claude Code

Install Kestrix first. The PyPI release is pending, so install from the repository:

```bash
uv tool install "git+https://github.com/Ruthvik-Bandari/kestrix"   # or: pipx install "git+https://..."
kestrix integrations install-claude-skill
```

The skill goes to `~/.claude/skills/kestrix-security`. Start a new Claude Code session to load it.

| Command | Options | What it does |
| --- | --- | --- |
| `kestrix integrations install-claude-skill` | `--dest PATH`, `--force` | Copies the skill to `PATH` (default `~/.claude/skills/kestrix-security`). |
| `kestrix integrations uninstall-claude-skill` | `--dest PATH` | Removes the installed skill. |
| `kestrix integrations package-claude-skill` | `--out FILE.zip` (required), `--force` | Writes the skill as a zip for Claude.ai or Claude Desktop. |

Exit codes: 0 done, 2 refused (the reason is printed to stderr).

**Safety of the installer.**

- An existing destination is replaced only with `--force`, and only when it is empty or already holds this
  skill (its `SKILL.md` names `kestrix-security`). An unrelated directory is never replaced or removed,
  even with `--force`.
- A destination that is a symbolic link is refused, so the installer never writes through a link to
  somewhere else. When an old copy is replaced, symbolic links inside it are removed, not followed.
- Files are written to a temporary sibling directory first and then renamed into place.

To install into a project instead of your home directory, pass
`--dest .claude/skills/kestrix-security` from the project root.

## Upload to Claude.ai or Claude Desktop

```bash
kestrix integrations package-claude-skill --out kestrix-security.zip
```

Upload the zip as a custom skill in Claude.ai or Claude Desktop (code execution must be enabled). The zip
holds the `kestrix-security/` folder with `SKILL.md` at its top. It is deterministic: the same Kestrix
version always produces the same bytes.

The skill still needs the `kestrix` command. In Claude.ai the code environment may not allow installing
packages from the internet; when it cannot install Kestrix, Claude says so and suggests running the same
commands locally or in Claude Code. The website check also needs outbound network access.

## Example prompts

- "Is this email a phish? ~/Downloads/invoice.eml"
- "My bank is example-bank.com. Check ~/Downloads/security-alert.eml for impersonation."
- "Is this link safe? http://paypa1-login.example.top/verify"
- "What is ~/Downloads/statement.pdf.exe? Don't open it."
- "Does this photo reveal where I live? ~/Pictures/IMG_0412.jpg"
- "Check the security headers on my site https://my-site.example — I own it."
- "Why didn't my Sigma rule fire? rule.yml, mapping.yml and dev.jsonl are in ./detections"
- "Show me how Kestrix repairs a noisy rule."
- "Is bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0 exposed to quantum attacks? How do I migrate?"

## Privacy

- Everything runs locally through the `kestrix` CLI. The skill tells Claude never to upload your emails,
  files, rules, events or addresses to other services, and never to fetch links found in emails or files.
- The only outbound requests are the ones Kestrix itself makes on request: the website check (one GET and
  one TLS handshake to your site) and, only if you agree, `kestrix bitcoin scan --lookup-chain`, which
  sends hash-based addresses to mempool.space.
- Email, file, URL, rule and event content is treated as untrusted data. The skill tells Claude to ignore
  instructions inside them (prompt injection) and to point them out as a warning sign.
- Claude quotes only what it needs: reason codes, hosts, titles and short evidence, not message bodies,
  attachment contents, cookies or secrets. Kestrix's own reports already leave out message bodies and
  attachment bytes ([mail privacy](modules/mail.md#privacy)).
- Using the skill sends Kestrix's report output to Claude as part of your conversation, under the terms of
  your Claude plan. If a message is too sensitive for that, run `kestrix` yourself in a terminal instead.

The skill never asks for Bitcoin private keys or seed phrases, and it only checks websites you own or are
authorized to assess.
