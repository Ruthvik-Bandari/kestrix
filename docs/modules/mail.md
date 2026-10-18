# Mail analysis

The mail module checks one saved email message (an `.eml` file) for common phishing and malware-delivery signs and explains each one. It reads the sender authentication results your mail provider stamped on the message, compares the sender's addresses, and checks links and attachments. Use it on a message you are unsure about before you click, reply or open anything.

It is a set of heuristics, not a classifier. A `clean` verdict means none of the checks fired, not that the message is safe. Kestrix has not yet measured detection or false-positive rates for this module, so none are claimed. The design is recorded in [ADR 0003](../adr/0003-mail-module.md); this page describes the first delivery slice (parser plus the `auth`, `sender`, `links` and `attachments` analyzers). Source files are under [`src/kestrix/mail/`](../../src/kestrix/mail/).

## Privacy

Analysis runs entirely on your machine. Nothing is sent anywhere: links are never visited or resolved, HTML is never rendered and scripts in it are skipped, and attachments are never opened, executed or extracted. The report holds reason codes, hosts, the header values needed to explain a finding, file names and hashes. It never holds the message body, link text or attachment bytes.

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

- `--protected-domain` names a domain you care about, such as your bank or your employer. A display name that contains its name (for example `PayPal` for `paypal.com`) on a message from another domain is flagged.
- `--trusted-authserv-id` names your mail provider's `authserv-id`, the first word of the `Authentication-Results` header it adds (for example `mx.google.com`). See [Authentication](#authentication).

## Verdict and score

The rules are applied in this order ([`analyze.py`](../../src/kestrix/mail/analyze.py)):

1. `malicious`: any high finding from the `sender`, `links` or `attachments` analyzers, or `mail.auth.dmarc_fail` together with any other medium or high finding.
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
| `findings` | Most severe first. Each has `id` (a stable reason code), `analyzer`, `severity`, `title`, `explanation` and `evidence` (at most 300 characters; never body text). |
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

## Links

Links come from HTML `<a href>` anchors (with their visible text) and from `http://` and `https://` URLs written in plain-text parts. They are checked as text only. Each reason is reported once per host, and at most 50 link findings are reported.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.links.text_href_mismatch` | high | An anchor's visible text reads as a web address in another organization than both the link's real host and the From domain. |
| `mail.links.sender_domain_redirect` | low | The visible text shows the sender's own domain, but the link goes through another host. Newsletter click tracking does this; a forged sender is caught by the authentication findings instead. |
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
