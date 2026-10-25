# ADR 0003: Mail module: explainable email analysis with an optional read-only mailbox connector

- Status: accepted
- Date: 2026-10-18
- Decision owner: Ruthvik Bandari

## Context

Phishing, business email compromise (BEC) and account takeover mostly arrive by email. Kestrix already checks
websites, files and detection rules locally. It has no way to look at a message.

The owner wants two things: an analyzer for saved messages, and a connector that reads a Gmail or Microsoft 365
mailbox. The connector conflicts with three current invariants, so it needs an explicit decision:

- outbound requests are opt-in and must pass `netguard`;
- secrets live only in the environment or the 0600 `secrets.json`;
- there are no accounts.

## Decision

### 1. Module `kestrix.mail` analyzes one RFC 5322 message (`.eml` bytes) entirely offline

It follows the same shape as the other modules: `models`, analysis functions, and thin `cli.py` / `api.py`
adapters.

**Parsing:**
- stdlib `email` with `policy.default`;
- hard caps on message size (25 MiB), header count and line length, MIME depth and part count;
- HTML is never rendered or executed; it is tokenized with `html.parser` only to extract links and visible text;
- malformed input gives `Rejected(INVALID_INPUT)`, never a partial "clean" verdict.

**Analyzers.** Each one emits findings with a stable reason code, a severity and the evidence behind it:

| Analyzer | Looks at |
| --- | --- |
| `auth` | SPF, DKIM, DMARC and ARC results in the `Authentication-Results` header. Only a header whose `authserv-id` the user configured is trusted. Without one, the topmost header is read but unverified (amended 2026-10-25): its failures are reported, its pass lowers nothing, because anyone can write that header into a saved message. |
| `sender` | From vs Reply-To vs Return-Path domains; a display name that contains a different address or domain; a display name that matches a protected contact while the domain differs. |
| `lookalike` | From and link domains against the user's protected domains: IDN or punycode, mixed scripts, confusable skeletons, and edit distance of 2 or less after homoglyph folding. |
| `links` | The href host vs the host shown in the link text; IP-literal hosts; credentials in the URL; `javascript:` and `data:` schemes; known shorteners; redirect parameters. |
| `attachments` | Dangerous types (executables, scripts, LNK, ISO/IMG, HTA, OneNote, HTML); double extensions; magic bytes that disagree with the declared type; macro-enabled Office files; encrypted archives; archive listings (bounded) that contain executables. |
| `intent` | BEC cues: payment or bank-detail changes, gift cards, urgency, secrecy, credential requests. Labeled a heuristic. |

**Verdict.** The result is `clean`, `suspicious`, `malicious` or `insufficient_evidence`, plus:
- the ordered findings that explain it;
- a SHA-256 of the message.

Any score is labeled a heuristic, not a probability. Evidence never contains the message body or attachment bytes.
It carries only headers needed to explain a finding, hosts, hashes and reason codes.

### 2. Optional AI explainer

This mirrors the bitcoin guardian:
- it uses the user's own Anthropic key and the `[ai]` extra;
- it may summarize intent and explain the findings;
- it never decides the verdict on its own;
- message text is passed as quoted data, with a fixed output schema, so text inside an email cannot steer it.

### 3. Optional connector (`kestrix mail connect gmail|m365`)

The connector is read-only and opt-in:

- **Bring your own OAuth client.** The user registers a client in their own Google Cloud project, in testing mode,
  or as their own Entra ID app registration. Kestrix ships no client secret.
- **Sign-in flow.** OAuth 2.0 authorization code with PKCE and a loopback redirect on 127.0.0.1, for installed
  apps.
- **Scopes:**
  - Gmail `https://www.googleapis.com/auth/gmail.readonly`;
  - Microsoft Graph delegated `Mail.Read`.
  - No send, modify or delete scope is ever requested.
- **Fetch and analyze.** It fetches raw MIME (Gmail `format=raw`; Graph `/messages/{id}/$value`) and analyzes it
  with the same offline analyzer. Nothing is sent anywhere except the request to the provider.
- **Outbound requests:**
  - go through `netguard`, plus a fixed host allowlist for the provider endpoints;
  - only TLS is used;
  - responses are bounded.
- **Token storage.** The refresh token is stored with the existing 0600 `secrets.json` mechanism and is never
  logged, returned by the API or written to evidence. `kestrix mail disconnect` deletes it and revokes it at the
  provider.
- **Monitor-only.** Kestrix never moves, labels or deletes mail. Any enforcement stays with the user.

These rules amend the invariants. "No accounts" still holds for Kestrix itself. The connector signs in to the
user's own mailbox and holds no Kestrix account.

## Consequences

- **Evaluation.** The analyzers ship as heuristics. Claims about detection or false-positive rates need an
  evaluation on public labeled corpora with recorded licenses. Until that exists, the docs report no rates.
- **Gmail restrictions.** `gmail.readonly` is a restricted scope. An unverified personal client works only for the
  test users listed in the user's own Google project. That fits personal use, not distribution.
- **Delivery slices:**
  1. parser plus the auth, sender, links and attachments analyzers, verdict, CLI and API;
  2. lookalike and intent analyzers, dashboard page;
  3. Gmail connector;
  4. Microsoft 365 connector;
  5. evaluation on public corpora;
  6. AI explainer.
