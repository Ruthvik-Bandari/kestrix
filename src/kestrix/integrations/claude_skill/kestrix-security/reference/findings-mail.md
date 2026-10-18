# Mail finding ids (`kestrix mail analyze`)

Every finding has `id`, `analyzer`, `severity`, `title`, `explanation` and `evidence` (at most 300
characters). The ids below are stable reason codes. Source: `src/kestrix/mail/`.

## Verdict rules (applied in order)

1. `malicious`: any high finding from `sender`, `lookalike`, `links`, `attachments` or `intent`, or
   `mail.auth.dmarc_fail` together with any other medium or high finding.
2. `suspicious`: any other medium or high finding. A DMARC failure on its own lands here.
3. `insufficient_evidence`: no trusted authentication results (`mail.auth.missing`) and no other finding
   above info.
4. `clean`: none of the above. It means no check fired, not that the message is safe.

`heuristic_score` = sum of high 35, medium 15, low 5, info 0, capped at 100. Not a probability.

## Authentication (`auth`)

Only the topmost `Authentication-Results` header is trusted, or the first one whose `authserv-id`
matches `--trusted-authserv-id`.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.auth.dmarc_fail` | high | `dmarc=fail`. |
| `mail.auth.no_dmarc_with_failure` | medium | DMARC is `none` or absent, and SPF failed or every DKIM signature failed. |
| `mail.auth.spf_fail` | medium | `spf=fail`. |
| `mail.auth.spf_softfail` | low | `spf=softfail`. Forwarding often causes this. |
| `mail.auth.dkim_fail` | medium | Every DKIM result is `fail` or `permerror`. One passing signature outweighs a broken one, which mailing lists often cause. |
| `mail.auth.dkim_not_aligned` | low | DKIM passed, but no passing signature's domain (`header.d`, or the domain of `header.i`) is in the From domain's organization. |
| `mail.auth.missing` | info | No trusted `Authentication-Results` header. The checks cannot be judged; this leads to `insufficient_evidence`, never to a worse verdict. |

## Sender (`sender`)

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.sender.reply_to_mismatch` | medium | A `Reply-To` address is in another organization than `From`. |
| `mail.sender.return_path_mismatch` | low | `Return-Path` is in another organization than `From`. Mailing lists and email service providers do this routinely. |
| `mail.sender.display_name_spoof` | high | The display name contains an email address or a domain outside the From organization. A bare word counts as a domain only with a common or two-letter top-level domain, so `invoice.pdf` does not. |
| `mail.sender.display_name_brand` | high | The display name contains the name of a protected domain (its first label, three characters or more) and `From` is outside that domain's organization. |

## Look-alike domains (`lookalike`)

Needs `--protected-domain` except `mail.lookalike.mixed_script`.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.lookalike.homograph` | high | The host has non-ASCII (internationalized) letters and its skeleton equals a protected domain's, as with a Cyrillic `а` in `pаypal.com`. |
| `mail.lookalike.domain` | high for the From domain; medium for a link host | The skeleton equals the protected label, or is within Damerau-Levenshtein distance 1 of it (protected labels of 5 to 8 characters) or 2 (9 characters or more), as with `paypa1.com` or `rnicrosoft.com`. Shorter protected labels must match exactly after folding. |
| `mail.lookalike.brand_in_host` | medium | A dot- or hyphen-separated part of another organization's host folds to the protected label (3 characters or more), as in `paypal.com.account-verify.example` or `paypal-secure.example`. |
| `mail.lookalike.mixed_script` | medium | One label mixes Latin letters with Cyrillic or Greek ones. Raised with or without protected domains. |

## Links (`links`)

Links are read as text only, never visited.

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

## Attachments (`attachments`)

Attachments are hashed and sniffed, never opened or extracted.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `mail.attachments.dangerous_type` | high; medium for `html`, `htm`, `svg` | The extension is one of `exe scr com pif bat cmd js jse vbs vbe wsf wsh ps1 hta lnk iso img vhd vhdx msi jar one chm cpl reg html htm svg`. |
| `mail.attachments.double_extension` | high | A document-like extension is followed by a high-risk one, as in `invoice.pdf.exe`. |
| `mail.attachments.magic_mismatch` | high when the content is a Windows program; medium otherwise | The first bytes (`MZ`, `PK\x03\x04`, `%PDF`, or the OLE signature) disagree with the extension or, without a known extension, the declared content type. |
| `mail.attachments.macro_office` | medium | A macro-enabled Office extension (`docm`, `xlsm`, `pptm` and similar), legacy OLE Office content (except `.msg`), or a ZIP-based file that contains `vbaProject.bin`. |
| `mail.attachments.encrypted_archive` | medium | A ZIP member is encrypted. Mail filters cannot scan it. |
| `mail.attachments.archive_dangerous_member` | high | A ZIP member has a high-risk extension from the list above. |

## Intent (`intent`, English-only heuristic)

| `id` | Severity | Raised for phrases such as |
| --- | --- | --- |
| `mail.intent.payment_change` | medium | "bank details have changed", "new account number", "wire transfer", "update your payment"; also "invoice attached" when an urgency cue is present (evidence `invoice attached + <urgency cue>`). |
| `mail.intent.gift_cards` | medium | A request: "buy some gift cards", "gift card codes", "iTunes cards", "scratch off the back". A mention such as "our gift cards never expire" does not fire. |
| `mail.intent.credential_request` | medium (low when DMARC passes) | "verify your account", "confirm your password", "sign in to continue", "unusual sign-in". Genuine provider alerts use these words, so when DMARC proves the From domain sent the message it is low and the links decide. |
| `mail.intent.urgency` | low | "urgent", "immediately", "within 24 hours", "account will be suspended", "as soon as possible", "final notice". |
| `mail.intent.secrecy` | low | "keep this confidential", "don't tell anyone", "be discreet". |
| `mail.intent.bec_pattern` | high | `payment_change` or `gift_cards` together with `urgency` or `secrecy`. The evidence names the families, for example `gift_cards with secrecy`. |

## Plain-language hints

- Authentication failures mean the sender's domain did not vouch for this message; forwarding and mailing
  lists can cause SPF or DKIM failures on genuine mail, so weigh them with the other findings.
- `display_name_*`, `lookalike.*` and `links.text_href_mismatch` are impersonation signs: describe who the
  message pretends to be and where it really comes from or links to.
- `intent.bec_pattern` is the business-email-compromise pattern: payment or gift-card request plus pressure
  or secrecy. Advise calling the requester on a known number before paying.
