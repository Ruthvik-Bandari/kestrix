# Security policy

If you find a vulnerability in Kestrix, report it privately so it can be fixed before details are public. This page says how to report, which versions get fixes, what counts as in scope, and how good-faith research is treated. The design and its known limitations are in [docs/security-model.md](docs/security-model.md); check there first, because a documented limitation may already cover what you found.

## Report a vulnerability

Use GitHub private vulnerability reporting:

1. Open the [new security advisory form](https://github.com/Ruthvik-Bandari/kestrix/security/advisories/new) for this repository.
2. Describe the issue, the affected version or commit, and the steps to reproduce it. A minimal proof of concept helps.
3. Say whether you want to be credited, and under what name.

Do not open a public issue, pull request or discussion for a vulnerability. Kestrix has a single maintainer, so response times vary. You will get a reply in the advisory thread, and the fix, the advisory and the credit are coordinated with you there.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.1.x | Yes |
| Earlier code in this repository (the retired CTPPO prototype) | No |

Fixes go into the latest 0.1 release. Upgrade with `pip install --upgrade kestrix`.

## Scope

In scope:

- the `kestrix` Python package and the `kestrix` CLI;
- the local server started by `kestrix dashboard` and its API, including the loopback-only, cross-site and body-size protections;
- the bundled dashboard;
- parsing of untrusted rules, mappings, fixtures, files, URLs and addresses;
- outbound request guards (`core/netguard.py`, the website check, mempool.space lookups);
- storage and handling of the Anthropic API key;
- the CI workflow and the release artifacts built from this repository.

Out of scope:

- vulnerabilities in third-party services (mempool.space, the Anthropic API) or in dependencies, unless Kestrix uses them unsafely. Report those to their maintainers;
- the Elasticsearch container's own security settings, which `detect engine-up` disables by design for a loopback-only replay engine;
- findings that need an attacker who already runs code as your user, or has root;
- limitations already listed in [docs/security-model.md](docs/security-model.md#known-limitations), unless you show a way around a documented mitigation;
- results of the heuristic checks, such as a phishing URL that scores low. These are accuracy issues; open a normal issue for them;
- the historical CTPPO code in git history.

## Safe harbor

Research done in good faith under this policy is authorized, and no legal action will be taken or supported against you for it. Good faith means:

- you test only against your own installation and systems you own or are permitted to test;
- you do not access, change or delete other people's data;
- you do not degrade services, including mempool.space and the Anthropic API;
- you report promptly and keep the details private until a fix is released or we agree on a disclosure date.

If you are unsure whether something is allowed, ask in the advisory thread first. This policy cannot authorize testing of third-party systems.
