# Security policy

If you find a vulnerability in the Kestrix plugin for Claude Code or in the `kestrix-scan` scanner it calls,
report it privately so it can be fixed before details are public. This policy follows the main Kestrix
security policy; the scope below is the part that applies to this repository.

## Report a vulnerability

Use GitHub private vulnerability reporting:

1. Open the [new security advisory form](https://github.com/Ruthvik-Bandari/kestrix-claude-plugin/security/advisories/new) for this repository.
2. Describe the issue, the affected version or commit, and the steps to reproduce it. A minimal proof of concept helps.
3. Say whether you want to be credited, and under what name.

Do not open a public issue, pull request or discussion for a vulnerability. Kestrix has a single maintainer, so
response times vary. You will get a reply in the advisory thread, and the fix, the advisory and the credit are
coordinated with you there.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.1.x | Yes |

Fixes go into the latest 0.1 release. Update the plugin with `/plugin` (or `claude plugin update kestrix@kestrix`)
and the scanner with `pip install --upgrade kestrix-scan`.

## Scope

In scope:

- the hook script (`hooks/kestrix_hook.py`) and the hook configuration (`hooks/hooks.json`), including its handling
  of the session directory, the file snapshots and the hook JSON from Claude Code;
- anything that makes a hook block a tool, install something, open a network connection, leak a secret value, or
  run an executable other than the `kestrix-scan` or `kestrix` on your PATH;
- the skills and commands, where their instructions could make Claude act against the user (for example, following
  instructions planted in the code under review);
- the `kestrix-scan` scanner, including its parsing of untrusted files and its `db update` download.

Out of scope:

- missed findings and false positives. These are accuracy issues; open a normal issue;
- findings that need an attacker who already runs code as your user, or has root;
- vulnerabilities in Claude Code itself or in third-party services. Report those to their maintainers.

## Safe harbor

Research done in good faith under this policy is authorized, and no legal action will be taken or supported against
you for it. Good faith means you test only against your own installation and systems you own or are permitted to
test, you do not access, change or delete other people's data, and you report promptly and keep the details private
until a fix is released or we agree on a disclosure date. If you are unsure whether something is allowed, ask in the
advisory thread first.
