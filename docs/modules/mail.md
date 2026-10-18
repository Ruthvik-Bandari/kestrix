# Mail analysis

The mail module checks one saved email message (an `.eml` file) for common phishing and malware-delivery signs and explains each one. It reads the sender authentication results your mail provider stamped on the message, compares the sender's addresses, looks for domains that imitate ones you protect, checks links and attachments, and looks for the wording of payment and credential scams. Use it on a message you are unsure about before you click, reply or open anything. It is available from the CLI, the API and the dashboard's **Email check** page.

It is a set of heuristics, not a classifier. A `clean` verdict means none of the checks fired, not that the message is safe. Kestrix has not yet measured detection or false-positive rates for this module, so none are claimed. The design is recorded in [ADR 0003](../adr/0003-mail-module.md); this page describes the first two delivery slices: the parser, the `auth`, `sender`, `lookalike`, `links`, `attachments` and `intent` analyzers, and the dashboard page. Source files are under [`src/kestrix/mail/`](../../src/kestrix/mail/).

## Privacy

Analysis runs entirely on your machine. Nothing is sent anywhere: links are never visited or resolved, HTML is never rendered and scripts in it are skipped, and attachments are never opened, executed or extracted. The report holds reason codes, hosts, the header values needed to explain a finding, file names and hashes. It never holds the message body, link text or attachment bytes, with one exception: an `intent` finding's evidence is the short cue phrase that matched (at most 60 characters), such as `wire transfer`.

## Commands

| Command | Options | Exit codes |
| --- | --- | --- |
| `kestrix mail analyze PATH` | `--protected-domain D` (repeatable, at most 20), `--trusted-authserv-id X` (repeatable, at most 5), `--json` | 0 analysed; 2 rejected (for example, larger than 25 MiB or not an email message) |

Rejections print `Rejected (<reason>): <detail>` to stderr. The file size is checked before the file is read. The API uses the same function; see [`docs/api.md`](../api.md#mail).

```text
$ kestrix mail analyze sample.eml
From:     alerts@notice.example
Subject:  Quarterly update
SHA-256:  837cdce0d7529d6a502dd9e26c5fbea70f9750ed621ff92aa358dbd29ff6e016
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
```

The sample is a synthetic message built by the test helpers. Each finding is also followed by a plain-language explanation, omitted here.

**Options.**

- `--protected-domain` names a domain you care about, such as your bank or your employer. A display name that contains its name (for example `PayPal` for `paypal.com`) on a message from another domain is flagged, and so are look-alikes of it in the From domain and link hosts (see [Look-alike domains](#look-alike-domains)).
- `--trusted-authserv-id` names your mail provider's `authserv-id`, the first word of the `Authentication-Results` header it adds (for example `mx.google.com`). See [Authentication](#authentication).

## Verdict and score

The rules are applied in this order ([`analyze.py`](../../src/kestrix/mail/analyze.py)):

1. `malicious`: any high finding from the `sender`, `lookalike`, `links`, `attachments` or `intent` analyzers, or `mail.auth.dmarc_fail` together with any other medium or high finding.
2. `suspicious`: any other medium or high finding. A DMARC failure on its own lands here.
3. `insufficient_evidence`: no trusted authentication results (`mail.auth.missing`) and no other finding above info.
4. `clean`: none of the above.

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
| `findings` | Most severe first. Each has `id` (a stable reason code), `analyzer` (`auth`, `sender`, `lookalike`, `links`, `attachments` or `intent`), `severity`, `title`, `explanation` and `evidence` (at most 300 characters; never body text other than an `intent` cue phrase of at most 60 characters). |
| `counts` | `parts`, `links`, `attachments`, and `text_truncated` / `links_truncated` when a limit below was reached. |

## Authentication

The `auth` analyzer reads `Authentication-Results` headers (RFC 8601). Anyone can write such a header, including the sender, so only one is trusted:

- by default, the topmost one, which your provider adds last on delivery;
- with `--trusted-authserv-id`, the first one whose `authserv-id` matches. If none matches, the results count as missing.

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

## Sender

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.sender.reply_to_mismatch` | medium | A `Reply-To` address is in another organization than `From`. |
| `mail.sender.return_path_mismatch` | low | `Return-Path` is in another organization than `From`. Mailing lists and email service providers do this routinely. |
| `mail.sender.display_name_spoof` | high | The display name contains an email address or a domain outside the From organization. A bare word counts as a domain only with a common or two-letter top-level domain, so `invoice.pdf` does not. |
| `mail.sender.display_name_brand` | high | The display name contains the name of a protected domain (its first label, three characters or more) and `From` is outside that domain's organization. |

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

Links come from HTML `<a href>` anchors (with their visible text) and from `http://` and `https://` URLs written in plain-text parts. They are checked as text only. Each reason is reported once per host, and at most 50 link findings are reported.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.links.text_href_mismatch` | high | An anchor's visible text reads as a web address in another organization than both the link's real host and the From domain. |
| `mail.links.sender_domain_redirect` | low | The visible text shows the sender's own domain and the link goes through a host or path that looks like click tracking (for example `click.`, `/ls/click`). Newsletters do this; a forged sender is caught by the authentication findings instead. |
| `mail.links.sender_domain_mismatch` | medium | The visible text shows the sender's own domain, but the link goes to another site that does not look like click tracking. |
| `mail.links.userinfo` | high | The URL has text before `@`, as in `https://bank.com@evil.example`, which opens `evil.example`. |
| `mail.links.script_scheme` | high | The href uses `javascript:`, `data:` or `vbscript:`, also when split by spaces, tabs or control characters. |
| `mail.links.ip_host` | medium | The host is an IP address, including numeric forms such as `3232235777`. |
| `mail.links.punycode_host` | medium | A host label is internationalized (`xn--`), written either way. |
| `mail.links.shortener` | low | The host is on a fixed list of URL shorteners such as `bit.ly`. |
| `mail.links.redirect_param` | low | A query parameter's value is another `http(s)://` or `//` URL. |
| `mail.links.insecure_login` | low | An `http:` link whose path contains `login`, `logon`, `signin`, `verify` or `password`. |

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

The `intent` analyzer ([`intent.py`](../../src/kestrix/mail/intent.py)) looks for the wording of business email compromise (BEC) and credential phishing in the subject and the decoded text (HTML visible text, scripts skipped, within the 5 MiB scan budget). It is a heuristic: small, curated, case-insensitive English phrase lists. It misses paraphrases and other languages, and ordinary mail can use the same words. The subject and each text part are searched separately, so a phrase never spans two of them. Each family is reported at most once, with the first matched phrase as evidence.

| `id` | Severity | Raised for phrases such as |
| --- | --- | --- |
| `mail.intent.payment_change` | medium | "bank details have changed", "new account number", "wire transfer", "update your payment"; also "invoice attached" when an urgency cue is present (evidence `invoice attached + <urgency cue>`). |
| `mail.intent.gift_cards` | medium | A request: "buy some gift cards", "gift card codes", "iTunes cards", "scratch off the back". A mention such as "our gift cards never expire" does not fire. |
| `mail.intent.credential_request` | medium (low when DMARC passes) | "verify your account", "confirm your password", "sign in to continue", "unusual sign-in". Genuine provider alerts use these words, so when DMARC proves the From domain sent the message it is low and the links decide. |
| `mail.intent.urgency` | low | "urgent", "immediately", "within 24 hours", "account will be suspended", "as soon as possible", "final notice". |
| `mail.intent.secrecy` | low | "keep this confidential", "don't tell anyone", "be discreet". |
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

## Limits

| Limit | Value | When exceeded |
| --- | --- | --- |
| Message size | 25 MiB (26,214,400 bytes) | `input_too_large` |
| Header fields per part | 500 | `input_too_large` |
| One header field | 16 KiB (16,384 characters, name plus value) | `input_too_large` |
| MIME nesting depth | 10 | `nesting_too_deep` |
| MIME parts | 200 | `input_too_large` |
| Decoded text scanned | 5 MiB of characters | The rest is skipped; `counts.text_truncated` is true. |
| Links extracted | 500 | The rest are skipped; `counts.links_truncated` is true. |
| ZIP members listed | 1,000 | The rest are not listed. |

Input with none of the usual message headers (`From`, `Date`, `Message-ID`, `Received`, `Subject`, `To`, `MIME-Version`) is rejected with `invalid_input` rather than reported as clean. Bad character encodings are decoded with replacement characters.
