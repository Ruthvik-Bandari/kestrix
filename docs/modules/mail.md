# Mail analysis

The mail module checks one saved email message (an `.eml` file) for common phishing and malware-delivery signs and explains each one. It reads the sender authentication results your mail provider stamped on the message, compares the sender's addresses, looks for domains that imitate ones you protect, checks links and attachments, and looks for the wording of payment and credential scams. Use it on a message you are unsure about before you click, reply or open anything. It is available from the CLI, the API and the dashboard's **Email check** page.

It is a set of heuristics, not a classifier. A `clean` verdict means none of the checks fired, not that the message is safe. On a one-time locked test of 10,897 public-corpus messages never used for tuning (Nazario phishing 2003–2025, SpamAssassin 2002, Enron 1999–2002), the current rules flag 61.2% of phishing (95% CI 54.0–69.3), 50.0% of spam (27.9–54.9) and 1.2% of normal mail (0.7–2.0); 95.2% of flagged phishing-vs-normal messages are phishing. The normal mail is old and mostly lacks modern headers, so false alarms on today's mail are not measured; see [the email benchmark](../research/mail-benchmark.md). The design is recorded in [ADR 0003](../adr/0003-mail-module.md); this page describes the first two delivery slices: the parser, the `auth`, `sender`, `lookalike`, `links`, `attachments` and `intent` analyzers, and the dashboard page. Source files are under [`src/kestrix/mail/`](../../src/kestrix/mail/).

## Privacy

Analysis runs entirely on your machine. Nothing is sent anywhere (the optional [mailbox connector](#mailbox-connector-local-mode-only) fetches a message you pick from your own mailbox first, and only then): links are never visited or resolved, HTML is never rendered and scripts in it are skipped, and attachments are never opened, executed or extracted. The report holds reason codes, hosts, the header values needed to explain a finding, file names and hashes. It never holds the message body, link text or attachment bytes, with one exception: an `intent` finding's evidence is the short cue phrase that matched (at most 60 characters), such as `wire transfer`.

## Commands

| Command | Options | Exit codes |
| --- | --- | --- |
| `kestrix mail analyze PATH` | `--protected-domain D` (repeatable, at most 20), `--trusted-authserv-id X` (repeatable, at most 5), `--json` | 0 analysed; 2 rejected (for example, larger than 25 MiB or not an email message) |

Rejections print `Rejected (<reason>): <detail>` to stderr. The file size is checked before the file is read. The API uses the same function; see [`docs/api.md`](../api.md#mail).

```text
$ kestrix mail analyze sample.eml
From:     alerts@notice.example
Subject:  Quarterly update
SHA-256:  e47c7c75cf954f41944828d8e23d003e665eb2d4527242689e083e76a441b857
Verdict:  malicious (heuristic score 100/100)
Parts:    5, links 1, attachments 1

Findings:
  [HIGH] Display name shows a different address or domain
      evidence: display name names example-bank.com; actual From domain notice.example
  [HIGH] Link text shows one site but the link goes to another
      evidence: text shows www.example-bank.com; link goes to login.notice.example
  [HIGH] Attachment type .exe can run code or open a fake page
      evidence: statement.pdf.exe
  [HIGH] Name disguises a .exe file as .pdf
      evidence: statement.pdf.exe
  [MEDIUM] Replies go to a different domain than the sender
      evidence: From domain notice.example; Reply-To domain other.example
  [LOW] SPF soft-failed
      evidence: authserv-id mx.example.net: spf=softfail
  [INFO] Authentication results are unverified
      evidence: topmost header, authserv-id mx.example.net: spf=softfail dkim=pass dmarc=pass
```

The sample is a synthetic message built by the test helpers. Each finding is also followed by a plain-language explanation, omitted here.

**Options.**

- `--protected-domain` names a domain you care about, such as your bank or your employer. A display name that contains its name (for example `PayPal` for `paypal.com`) on a message from another domain is flagged, and so are look-alikes of it in the From domain and link hosts (see [Look-alike domains](#look-alike-domains)).
- `--trusted-authserv-id` names your mail provider's `authserv-id`, the first word of the `Authentication-Results` header it adds (for example `mx.google.com`). See [Authentication](#authentication).

## Verdict and score

The rules are applied in this order ([`analyze.py`](../../src/kestrix/mail/analyze.py)):

1. `malicious`: any high finding from the `sender`, `lookalike`, `links`, `attachments` or `intent` analyzers, or `mail.auth.dmarc_fail` together with any other medium or high finding.
2. `suspicious`: any other medium or high finding. A DMARC failure on its own lands here.
3. `suspicious` by combination: at least 3 distinct low findings from at least 2 different analyzers. Info findings never count, and neither does `mail.sender.return_path_mismatch`, which mailing lists and email service providers produce routinely. Each counted finding is weak alone; several unrelated ones are worth a look. The report's `verdict_reason` names them.
4. `insufficient_evidence`: no trusted authentication results (`mail.auth.missing`) and no other finding above info.
5. `clean`: none of the above.

`heuristic_score` is the sum of per-severity weights of all findings (high 35, medium 15, low 5, info 0), capped at 100. It orders messages for attention. It is not a probability.

## Report

| Field | Meaning |
| --- | --- |
| `schema_version` | `1`. |
| `notice` | The privacy and heuristic notice shown above. |
| `sha256` | SHA-256 of the raw message bytes. |
| `subject` | Subject header, cut to 200 characters. |
| `from_address` | The address in `From`, if one could be parsed. |
| `verdict`, `heuristic_score` | See above. |
| `verdict_reason` | `null`, or a sentence naming the low findings when rule 3 alone made the message `suspicious`. |
| `findings` | Most severe first. Each has `id` (a stable reason code), `analyzer` (`auth`, `sender`, `lookalike`, `links`, `attachments` or `intent`), `severity`, `title`, `explanation` and `evidence` (at most 300 characters; never body text other than an `intent` cue phrase of at most 60 characters). |
| `counts` | `parts`, `links`, `attachments`, and `text_truncated` / `links_truncated` when a limit below was reached. |

## Authentication

The `auth` analyzer reads one `Authentication-Results` header (RFC 8601). Anyone can write such a header, including the sender, so which one is read, and whether it is believed, depends on `--trusted-authserv-id`:

- **With `--trusted-authserv-id`**, the first header whose `authserv-id` matches is read and trusted. If none matches, the results count as missing. A `dmarc=pass` in it lowers `mail.intent.credential_request` to low (see [Intent](#intent)). Use it only for messages saved from your own mailbox: whoever hands you an `.eml` can put a header with any `authserv-id` on top.
- **Without it**, the topmost header is read, which your provider adds last on delivery. In a saved or forwarded `.eml`, or a sample someone sent you, that header could have been written by anyone, so it is **unverified**: its failures are still reported (raising severity is the safe direction), but a pass lowers no finding and no verdict, and the info finding `mail.auth.unverified` names the header that was read. A forged failure can therefore still make a genuine message look worse; the evidence shows which header said so.

Comments in parentheses and quoted strings are handled. `ARC` results are not judged in this slice.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.auth.dmarc_fail` | high | `dmarc=fail`. |
| `mail.auth.no_dmarc_with_failure` | medium | DMARC is `none` or absent, and SPF failed or every DKIM signature failed. |
| `mail.auth.spf_fail` | medium | `spf=fail`. |
| `mail.auth.spf_softfail` | low | `spf=softfail`. Forwarding often causes this. |
| `mail.auth.dkim_fail` | medium | Every DKIM result is `fail` or `permerror`. One passing signature outweighs a broken one, which mailing lists often cause. |
| `mail.auth.dkim_not_aligned` | low | DKIM passed, but no passing signature's domain (`header.d`, or the domain of `header.i`) is in the From domain's organization. |
| `mail.auth.missing` | info | No trusted `Authentication-Results` header. The checks cannot be judged; this leads to `insufficient_evidence`, never to a worse verdict. |
| `mail.auth.unverified` | info | No `--trusted-authserv-id` was given and the topmost `Authentication-Results` header was read. The evidence names its `authserv-id` and the results it records (for example `topmost header, authserv-id mx.example.net: spf=pass dkim=pass dmarc=pass`). A pass in it lowers nothing. |

## Sender

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.sender.reply_to_mismatch` | medium (low on list mail) | A `Reply-To` address is in another organization than `From` and is not the message's own mailing list (next row). Severity is `low` when the message has list headers and every such `Reply-To` is at a free-mail provider (Gmail, Outlook, Hotmail, Live, Yahoo, iCloud, Proton, QQ, 163, 126, Mykolab): on a list that is a participant's own setting. |
| `mail.sender.reply_to_mailing_list` | info | The message has a `List-Id`, `List-Post` or `List-Unsubscribe` header and a foreign `Reply-To` is in the same organization as a domain named there (the list identifier, a `mailto:` address or a URL), as when a list sets `Reply-To` to itself. It explains the `Reply-To` and adds nothing to the verdict. List headers are easy to forge, so they only explain a `Reply-To` that points at the list's own domain; `Precedence: list` or `bulk` alone names no domain and explains nothing. |
| `mail.sender.return_path_mismatch` | low | `Return-Path` is in another organization than `From`. Mailing lists and email service providers do this routinely. |
| `mail.sender.display_name_spoof` | high; medium when a domain appears among other words | The display name contains an email address or a domain outside the From organization. A bare word counts as a domain only with a common or two-letter top-level domain, so `invoice.pdf` does not. It is high when the display name holds an address or is nothing but the domain (`PayPal.com`), and medium when the domain is one word among others (`PayPal.com Billing`), which genuine newsletters also do. |
| `mail.sender.display_name_brand` | high | The display name contains the name of a protected domain (its first label, three characters or more) and `From` is outside that domain's organization. |
| `mail.sender.random_domain` | low | A label of the From domain looks machine-generated (see **Machine-generated names** below). |
| `mail.sender.outdated_mailer` | low | `X-Mailer` names a mail program discontinued long ago (`Outlook Express`, `Microsoft Internet Mail`, `Netscape Messenger` or `Communicator`, `Eudora`). Spam tools forge these; the header is easy to set, so it is a hint only. |

**Machine-generated names.** A host label (the top-level domain excluded, hyphenated labels judged piece by piece, punycode skipped) of 8 characters or more reads as machine-generated when it switches between letters and digits three or more times, as in `q7vk2mx9r4tz8wn3`, or has six consonants in a row. It is lexical only: a pronounceable random name such as `velomarquintasy` passes, and some click trackers and CDNs also use generated names.

**Organization.** Two domains are in the same organization when their last two labels match, or their last three under a short list of two-label suffixes such as `co.uk`. This approximates DMARC relaxed alignment without the full Public Suffix List, so some domains are grouped incorrectly. Domains are compared lower-cased in their ASCII (punycode) form and shown decoded.

## Look-alike domains

The `lookalike` analyzer ([`lookalike.py`](../../src/kestrix/mail/lookalike.py)) compares the From domain and every `http(s)` link host (IP addresses excluded) with the protected domains. Hosts in the same organization as a protected domain, such as `mail.paypal.com` for `paypal.com`, are genuine and never flagged.

A host is compared by its registrable label, the first label of its organization (`paypa1` in `secure.paypa1.com`). Both sides are folded to a skeleton first:

1. NFKC normalization, so fullwidth letters become ASCII, then lower case;
2. a fixed table of letters that look Latin: Cyrillic `а е о р с у х і ј ԁ ѕ ԝ`, Greek `ν ο α ι κ τ`, Armenian `ո` and Latin script `ɡ`;
3. ASCII look-alikes: `0`→`o`, `1`→`l`, `3`→`e`, `5`→`s`, then `rn`→`m`, `vv`→`w`, `cl`→`d`.

The table is a curated subset of the Unicode confusables list, not all of it, so some look-alikes are missed. A host whose registrable label is exactly the protected label under another suffix (`paypal.de` for `paypal.com`) is not flagged: brands own many such domains and Kestrix has no registry data to tell them apart. Each reason is reported once per host, and at most 50 look-alike findings are reported.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.lookalike.homograph` | high | The host has non-ASCII (internationalized) letters and its skeleton equals a protected domain's, as with a Cyrillic `а` in `pаypal.com`. |
| `mail.lookalike.domain` | high for the From domain; medium for a link host | The skeleton equals the protected label, or is within Damerau-Levenshtein distance 1 of it (protected labels of 5 to 8 characters) or 2 (9 characters or more), as with `paypa1.com` or `rnicrosoft.com`. Shorter protected labels must match exactly after folding. |
| `mail.lookalike.brand_in_host` | medium | A dot- or hyphen-separated part of another organization's host folds to the protected label (3 characters or more), as in `paypal.com.account-verify.example` or `paypal-secure.example`. |
| `mail.lookalike.mixed_script` | medium | One label mixes Latin letters with Cyrillic or Greek ones. Raised with or without protected domains. |

## Links

Links come from HTML `<a href>` anchors (with their visible text) and from `http://` and `https://` URLs written in plain-text parts. They are checked as text only. Each reason is reported once per host, and at most 50 link findings are reported. A link through a URL-rewriting security gateway (Microsoft Defender Safe Links `*.safelinks.protection.outlook.com`, Proofpoint `urldefense.com` and `urldefense.proofpoint.com`, Mimecast `protect-<region>.mimecast.com` and `*.mimecastprotect.com`, Barracuda `linkprotect.cudasvc.com`, Cisco `secure-web.cisco.com`) is judged by the address it wraps, the first query value that is an `http(s)://` URL. If none can be read, the visible text is not compared for that link, because the real destination is unknown.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.links.text_href_mismatch` | high | An anchor's visible text reads as a web address in another organization than both the link's real host and the From domain. |
| `mail.links.sender_domain_redirect` | low | The visible text shows the sender's own domain and the link goes through a host or path that looks like click tracking (for example `click.`, `/ls/click`). Newsletters do this; a forged sender is caught by the authentication findings instead. |
| `mail.links.sender_domain_mismatch` | medium | The visible text shows the sender's own domain, but the link goes to another site that does not look like click tracking. |
| `mail.links.userinfo` | high | The URL has text before `@`, as in `https://bank.com@evil.example`, which opens `evil.example`. |
| `mail.links.script_scheme` | high | The href uses `javascript:`, `data:` or `vbscript:`, also when split by spaces, tabs or control characters. |
| `mail.links.ip_host` | medium (info for private addresses) | The host is an IP address, including numeric forms such as `3232235777`. Severity is `info` when the address is not globally routable (private, loopback, link-local, documentation range): phishing kits use public addresses. |
| `mail.links.punycode_host` | medium | A host label is internationalized (`xn--`), written either way. |
| `mail.links.shortener` | low | The host is on a fixed list of URL shorteners such as `bit.ly`. |
| `mail.links.redirect_param` | low | A query parameter's value is another `http(s)://` or `//` URL. |
| `mail.links.insecure_login` | low | An `http:` link whose path contains `login`, `logon`, `signin`, `verify` or `password`. |
| `mail.links.random_host` | low | A link host has a machine-generated label (see **Machine-generated names** under Sender). Reported once per host. |
| `mail.links.plain_http` | low | At least half of the message's web links use `http:` rather than `https:`. Reported once per message, with the count as evidence (for example `2 of 2 web links use http`). |

## Attachments

A part is an attachment when it has a file name, is marked as an attachment, or is not plain text or HTML. Each one is hashed with SHA-256 and its first 8 bytes are kept in memory for type sniffing. ZIP-based files are listed from their central directory (at most 1,000 member names); nothing is decompressed.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.attachments.dangerous_type` | high; medium for `html`, `htm`, `svg` | The extension is one of `exe scr com pif bat cmd js jse vbs vbe wsf wsh ps1 hta lnk iso img vhd vhdx msi jar one chm cpl reg html htm svg`. |
| `mail.attachments.double_extension` | high | A document-like extension is followed by a high-risk one, as in `invoice.pdf.exe`. |
| `mail.attachments.magic_mismatch` | high when the content is a Windows program; medium otherwise | The first bytes (`MZ`, `PK\x03\x04`, `%PDF`, or the OLE signature) disagree with the extension or, without a known extension, the declared content type. |
| `mail.attachments.macro_office` | medium | A macro-enabled Office extension (`docm`, `xlsm`, `pptm` and similar), legacy OLE Office content (except `.msg`), or a ZIP-based file that contains `vbaProject.bin`. |
| `mail.attachments.encrypted_archive` | medium | A ZIP member is encrypted. Mail filters cannot scan it. |
| `mail.attachments.archive_dangerous_member` | high | A ZIP member has a high-risk extension from the list above. |

## Intent

The `intent` analyzer ([`intent.py`](../../src/kestrix/mail/intent.py)) looks for the wording of business email compromise (BEC), credential phishing and spam offers in the subject and the decoded text (HTML visible text, scripts skipped, within the 5 MiB scan budget). It is a heuristic: small, curated, case-insensitive phrase lists, in English for every family and also in Russian for the gambling and prize families. It misses paraphrases and other languages, and ordinary mail can use the same words. The subject and each text part are searched separately, so a phrase never spans two of them. Each family is reported at most once, with the first matched phrase as evidence.

| `id` | Severity | Raised for phrases such as |
| --- | --- | --- |
| `mail.intent.payment_change` | medium | "bank details have changed", "new account number", "wire transfer", "update your payment"; also "invoice attached" when an urgency cue is present (evidence `invoice attached + <urgency cue>`). |
| `mail.intent.gift_cards` | medium | A request: "buy some gift cards", "gift card codes", "iTunes cards", "scratch off the back". A mention such as "our gift cards never expire" does not fire. |
| `mail.intent.credential_request` | medium (low when a trusted authserv-id records DMARC pass) | "verify your account", "confirm your password", "sign in to continue", "unusual sign-in", and looser wording: "update your billing information", "restore your account", "your account has been limited", "suspicious activity", "click here to verify". Genuine provider alerts use these words, so when the header of a trusted authserv-id (`--trusted-authserv-id`) records DMARC pass it is low and the links decide. Without a trusted authserv-id it stays medium, so a genuine provider alert checked that way is `suspicious`. |
| `mail.intent.urgency` | low | "urgent", "immediately", "within 24 hours", "account will be suspended", "as soon as possible", "final notice". |
| `mail.intent.secrecy` | low | "keep this confidential", "don't tell anyone", "be discreet". |
| `mail.intent.gambling_offer` | medium | "free spins", "no deposit bonus", "100 FS" (upper case only), "casino bonus"; in Russian "фриспины", "бесплатные спины", "без депозита", "бонус на депозит". |
| `mail.intent.spam_offer` | medium | One of 23 classic spam-offer phrases: loans and mortgages ("credit card offers", "bad credit", "debt consolidation", "mortgage rates", "refinance now", "lowest interest rates"), health ("lose weight", "weight loss", "enlarge your", "online pharmacy", "no prescription"), home-based income ("be your own boss", "home-based business", "work from home opportunity", "make money online", "extra income", "easy money"), "100% guaranteed" and bulk e-mail lists ("bulk e-mail", "million addresses"). Chosen for being rare in ordinary mail on the benchmark; a discussion about spam uses them too. |
| `mail.intent.prize_claim` | medium | "you have won", "claim your prize", "lottery winner"; in Russian "вы выиграли", "ваш приз", "получите выигрыш". |
| `mail.intent.hidden_text` | low | The subject and text together hold 20 or more invisible characters (zero-width spaces and joiners, soft hyphens, word joiners, byte-order marks). The evidence gives the count and the most common one, for example `120 invisible characters, mostly U+200C`. Newsletters pad their preview line with a few; spam uses long runs. |
| `mail.intent.bec_pattern` | high | `payment_change` or `gift_cards` together with `urgency` or `secrecy`. The evidence names the families, for example `gift_cards with secrecy`. |

## Dashboard

The **Email check** page (`/mail`, after Forensics in the navigation) is the same analysis in the browser. Choose or drop an `.eml` file, optionally list protected domains (comma-separated, up to 20) and your provider's `authserv-id`, and select **Check message**. The page explains how to save a message: in Gmail, ⋮ (More) → **Download message**; in Outlook, **File → Save as**.

The file goes only to the Kestrix server on this computer (`POST /api/mail/analyze`). The result shows:

- the verdict with an icon and a word (`Clean`, `Suspicious`, `Malicious`, `Insufficient evidence`), never color alone;
- the heuristic score, labeled as a heuristic and not a probability;
- the From address, part, link, attachment and finding counts, and the message SHA-256;
- the findings grouped by severity, each with its title, explanation, evidence, analyzer and reason code;
- the raw JSON report, which can be copied or downloaded.

Files over 25 MiB and more than 20 protected domains are refused in the browser before anything is sent. Server errors show their `reason` and `detail`. All message-derived values are rendered as plain text.

## Mailbox connector (local mode only)

On a local dashboard (`kestrix dashboard`) the **Email check** page has a second tab, **Check from your mailbox**, that lists messages from your Gmail or Microsoft 365 / Outlook.com mailbox so you can pick single messages to check. There is no bulk scan: nothing is read except what you search for and the messages you press **Check** on. It is [ADR 0009](../adr/0009-mailbox-connector.md); the setup steps are in the docs page "Connect Gmail or Outlook (local)" (`/docs/tools/email/connect-mailbox` in the dashboard).

- **It is read-only.** The only scopes are Gmail `gmail.readonly` and Microsoft Graph delegated `Mail.Read` (plus `offline_access`, `openid`, `profile` for the refresh token and the account label). Every mail call is a `GET`. Kestrix never labels, moves, marks as read, sends or deletes.
- **You bring your own app.** Register a Google OAuth client of type Desktop app (publishing status Testing) or a Microsoft Entra public-client app, then give Kestrix its client ID (and for Google its client secret) with `kestrix mail connect` or the dashboard. Kestrix ships no credentials.
- **What is kept.** The refresh token and the app settings, in the `0600` `secrets.json`. Access tokens stay in memory. The message list is shown in the page only. A checked message's raw MIME is fetched into memory, analyzed and dropped; the normal report goes to Recent results like any check (its list summary holds the verdict and finding count, no subject or address).
- **What it contacts.** Only `accounts.google.com`, `oauth2.googleapis.com`, `gmail.googleapis.com`, `login.microsoftonline.com` and `graph.microsoft.com` over HTTPS, after you press a connect button. Redirects are refused, answers are size-capped, and every request passes `netguard`.
- **Hosted service.** Not available there: the routes do not exist and the page does not show the tab.
- **Authentication.** A message fetched this way is judged like an uploaded file: without the authserv-id in Advanced options its `Authentication-Results` are unverified, so a DMARC pass lowers nothing.

| Command | What it does |
| --- | --- |
| `kestrix mail connect gmail --client-id ID [--client-secret S]` | Saves your app settings, then opens Google's sign-in in your browser and waits for the redirect on a one-shot `127.0.0.1` port (RFC 8252). The secret can also come from `KESTRIX_MAIL_CLIENT_SECRET`. |
| `kestrix mail connect outlook --client-id GUID [--tenant T]` | The same for Microsoft. The tenant is `common` unless you pass `organizations`, `consumers` or a tenant ID or domain. |
| `kestrix mail disconnect gmail\|outlook [--forget-app]` | Revokes at Google (Microsoft has no revoke call for this sign-in) and deletes the saved sign-in; `--forget-app` also deletes the client ID and secret. |
| `kestrix mail status` | Which providers are configured or connected. Prints no secrets. |

Explicit outcomes: `mailbox_not_configured`, `mailbox_not_connected` and `mailbox_reconnect_required` (HTTP 409; the saved sign-in was revoked, expired or, for a Google app in Testing status, passed its 7 days), `rate_limited` (429 with the provider's `Retry-After`), `target_unreachable` (no network), `input_too_large` (message over 25 MiB) and `upstream_error`. Routes: [`docs/api.md`](../api.md#mailbox-connector-local-mode-only).

## Limits

| Limit | Value | When exceeded |
| --- | --- | --- |
| Message size | 25 MiB (26,214,400 bytes) | `input_too_large` |
| Header fields per part | 500 | `input_too_large` |
| One header field | 16 KiB (16,384 characters, name plus value) | `input_too_large` |
| One header block (a message's or a part's headers), checked on the raw bytes before parsing | 64 KiB | `input_too_large` |
| All header blocks together, checked before parsing | 1 MiB | `input_too_large` |
| Parameters (`;`) in one `Content-Type` or `Content-Disposition` field, checked before parsing | 50 | `input_too_large` |
| Nesting inside a header value (comments, groups) | Python's recursion limit | `nesting_too_deep` |
| MIME nesting depth | 10 | `nesting_too_deep` |
| MIME parts | 200 | `input_too_large` |
| Decoded text scanned | 5 MiB of characters | The rest is skipped; `counts.text_truncated` is true. |
| Links extracted | 500 | The rest are skipped; `counts.links_truncated` is true. |
| ZIP members listed | 1,000 | The rest are not listed. |

The checks marked "before parsing" run on the raw bytes, because the standard library's MIME parameter parsing slows down sharply with many parameters. They look at the message's own headers, the headers after every line that starts with `--` (any possible MIME boundary, however it is declared), and the headers of attached messages. The hosted service also caps messages at 10 MiB and runs each analysis in a limited worker process ([hosted.md](../hosted.md)).

Input with none of the usual message headers (`From`, `Date`, `Message-ID`, `Received`, `Subject`, `To`, `MIME-Version`) is rejected with `invalid_input` rather than reported as clean. Bad character encodings are decoded with replacement characters. Mailing-list headers (`List-Id`, `List-Post`, `List-Unsubscribe`, `Precedence`) are each cut to 300 characters, and at most 10 domains are read from them. A header the standard library cannot parse at all (for example a NUL in a charset name) rejects the message with `invalid_input`, and undecodable header bytes appear as U+FFFD in the report.
