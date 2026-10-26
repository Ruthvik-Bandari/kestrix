# File and URL forensics

The forensics module tells you what a file really is and whether a link shows common phishing signs, without running the file or opening the link. Use it on a download or attachment you are unsure about, on a photo before you share it, or on a link from an email or message. File analysis gives four hashes you can look up in malware databases, the real format detected from the content, entropy measurements that reveal packed or encrypted data, and photo metadata such as GPS location. URL analysis scores the link text against a set of offline checks.

Neither check is a malware or phishing verdict. A clean result means none of the checks fired, not that the file or site is safe. The module is adapted from [CyberSafeX Detection Suite](https://github.com/Ruthvik-Bandari/CyberSafeX-Detection-Suite) (MIT). Source files are under [`src/kestrix/forensics/`](../../src/kestrix/forensics/).

## Commands

| Command | Options | Exit codes |
| --- | --- | --- |
| `kestrix forensics file PATH` | `--json` | 0 analysed; 2 rejected (for example, larger than 50 MiB) |
| `kestrix forensics url URL` | `--json` | 0 analysed; 2 rejected (for example, not http or https) |

Rejections print `Rejected (<reason>): <detail>` to stderr. The dashboard and API use the same functions; see [`docs/api.md`](../api.md#forensics).

## File analysis

```text
$ kestrix forensics file invoice.pdf.exe
File:     invoice.pdf.exe (20,004 bytes)
Type:     DOS or unrecognised MZ executable
...
Entropy:  7.990 bits per byte (0 = one repeated byte, 8 = looks random)
Random-looking regions: 1 (20,004 bytes)
Printable text: 38% of bytes
EXIF:     not applicable (not an image format that carries EXIF)

Findings:
  [HIGH] Name disguises a .exe file as .pdf
  [MEDIUM] Program may be packed or contain encrypted code
  [INFO] File is a program
```

The sample above is a synthetic file: an `MZ` header followed by random bytes. Each finding is followed by a plain-language explanation, omitted here.

### What is measured

The file is read once, in 1 MiB chunks, with memory bounded by one chunk, a 64 KiB header sample and one number per 4 KiB block ([`analysis.py`](../../src/kestrix/forensics/analysis.py)). Nothing is executed, decompressed or rendered.

| Report field | Meaning |
| --- | --- |
| `filename` | Base name only. Directories, control characters and invisible characters are removed; at most 255 characters. |
| `size` | Bytes. Files over 50 MiB (52,428,800 bytes) are refused with `input_too_large`. |
| `hashes` | `md5`, `sha1`, `sha256`, `sha512`. MD5 and SHA-1 are included for older lookup databases and are not collision-resistant. |
| `file_type` | `id`, `label`, `executable`, `extension`, `expected_extensions`, `extension_mismatch` (see below). |
| `entropy` | Whole-file Shannon entropy in bits per byte (0 to 8), per-block entropy over 4096-byte blocks, at most 512 chart points, and random-looking regions. |
| `byte_histogram` | Count of each byte value 0 to 255. |
| `printable_ratio` | Share of bytes that are printable ASCII, tab, CR or LF. |
| `exif`, `exif_status` | Image metadata (see [Photo metadata](#photo-metadata)). |
| `findings` | Observations, most severe first. Each has `id`, `severity`, `title`, `explanation`. |

**Random-looking regions.** A region is a run of at least two consecutive blocks with entropy at or above 7.2 bits per byte. Up to 32 regions are listed; `high_entropy_region_count` and `high_entropy_bytes` count them all.

### Format detection

The format comes from the first bytes of the content, never from the name. Recognised formats:

- programs: `pe`, `dos_mz`, `elf`, `macho`, `macho_fat`, and `script` (a `#!` line);
- code: `java_class`, `wasm`;
- documents: `pdf`, `docx`, `xlsx`, `pptx`, `ooxml`, `ole2`;
- archives: `zip`, `gzip`, `bzip2`, `xz`, `7z`, `rar`;
- images: `png`, `jpeg`, `gif`, `webp`, `tiff`;
- other: `swf`, `sqlite`, `text`, `empty`, `unknown`.

`extension_mismatch` is true when the extension is not one normally used for the detected format. For `text`, it is true only when the extension belongs to a binary-only format such as `.exe` or `.pdf`. It is never set for `unknown` or `empty` content.

### File findings

| `id` | Severity | Raised when |
| --- | --- | --- |
| `bidi_control_in_name` | high | The name contains a Unicode bidirectional control (U+202A to U+202E, U+2066 to U+2069) that can make `photo[RLO]gpj.exe` display as `photoexe.jpg`. |
| `double_extension` | high | The name ends in a document-like extension followed by one Windows runs, such as `.pdf.exe` or `.jpg.scr`. |
| `extension_mismatch` | high for programs, medium otherwise | The extension does not fit the detected content. |
| `executable_file` | info | The content is a program or script. |
| `empty_file` | info | The file has no content. |
| `expected_high_entropy` | info | Random-looking data in a format that normally stores compressed data (PDF, Office Open XML, legacy Office OLE2, ZIP, SWF, PNG, JPEG and similar). |
| `possible_packing` | medium | A program has random-looking regions. Packers, encrypted payloads, installers and compressed resources all look like this. |
| `high_entropy_file` | medium | The whole file is at or above 7.2 bits per byte, in a format that does not explain it. |
| `high_entropy_region` | low | Part of a file looks random, in a format that does not explain it. |
| `macro_office_file` | high for `.docx`, `.xlsx`, `.pptx` and other macro-free extensions, medium otherwise (Office Open XML); low (legacy) | An Office Open XML package holds a `vbaProject.bin` macro part (found in the first or last 64 KiB), or a legacy OLE2 file (`.doc`, `.xls`, `.ppt`) has a VBA storage in its directory (`VBA`, `Macros`, `_VBA_PROJECT`, `_VBA_PROJECT_CUR`). Legitimate macro-enabled documents look the same; about 4% of the legacy Office files measured held a VBA project, so legacy is low. |
| `encrypted_archive` | medium | A ZIP has the encryption flag set in a local file header, so its contents cannot be inspected. |
| `embedded_executable` | high | A PDF, image or Office Open XML file holds a Windows program (an `MZ` header whose `e_lfanew` points at `PE\0\0`) after offset 0. |
| `active_content_svg` | medium | An SVG image holds `<script`, a `javascript:` link or an `onload`-style event handler. |
| `obfuscated_html` | medium | An `.html`, `.htm`, `.xhtml`, `.shtml` or `.svg` file (first and last 64 KiB) shows hidden code: a decoder (`atob`, `unescape`, `eval`, `document.write`, `Function(`) run on a long encoded string or next to a 300-character or longer base64, hex, `\xNN` or `%uNNNN` blob, or a script loaded from a `data:` or `blob:` URL; or two weaker signals together (a form posted to another site by script plus a meta refresh to another site). Inline images are ignored. |
| `runnable_script_file` | medium for `.vbs`, `.vbe`, `.jse`, `.wsf`, `.wsh`, `.hta`, `.bat`, `.cmd`, `.ps1`, `.psm1`, `.scf`, and for `.js` that uses `WScript`, `ActiveXObject`, `Scripting.FileSystemObject`, `Shell.Application`, `WSH`, `GetObject(` or `eval(` of `atob`, `unescape`, `decodeURIComponent` or `String.fromCharCode`; low for other `.js` | Text content under a script extension that Windows runs on a double click. |
| `ole_unreadable` | info | The file starts like a legacy Office (OLE2) file but its directory could not be read within the bounds (truncated, looping or damaged), so macros could not be checked. No claim either way. |
| `gps_location` | high | A photo has GPS tags. Decoded coordinates are shown when complete. |
| `identifying_metadata` | low | A photo includes `Make`, `Model`, `BodySerialNumber`, `LensSerialNumber`, `CameraOwnerName`, `Artist`, `Software` or `DateTimeOriginal`. |

### Photo metadata

EXIF reading needs the optional Pillow extra, `pip install "kestrix[exif]"`, and Python 3.11 or newer: the extra requires Pillow 13, which fixes header-parsing vulnerabilities and has no Python 3.10 build, so on 3.10 it installs nothing and `exif_status` is `pillow_not_installed`. It runs only for JPEG, PNG, TIFF and WebP content, and Pillow is restricted to those four formats ([`exif.py`](../../src/kestrix/forensics/exif.py)).

- Pixel data is never decoded. PNG metadata comes only from the header pass.
- Images declaring more than 200,000,000 pixels (twice Pillow's limit, which is set to 100,000,000) are not opened.
- At most 200 tags are returned, each value cut to 200 characters. Binary values appear as `<N bytes of binary data>`.

`exif_status` is one of:

| Status | Meaning |
| --- | --- |
| `ok` | Metadata returned in `exif`. |
| `no_exif` | An image without EXIF. |
| `not_image` | Not a format that carries EXIF. |
| `pillow_not_installed` | Install `kestrix[exif]` to read it. |
| `unreadable` | Metadata present but malformed. |
| `too_many_pixels` | The image declares implausibly large dimensions, so it was not opened. |

## URL analysis

URL analysis reads the link as text. It never fetches, resolves or follows the URL ([`url.py`](../../src/kestrix/forensics/url.py)).

```text
$ kestrix forensics url "http://paypa1-login.example.top/verify"
URL:      http://paypa1-login.example.top/verify
Host:     paypa1-login.example.top
Score:    55/100 (medium)

Findings:
  [HIGH] Brand name 'paypal' used in front of another domain
  [LOW] Uses the .top ending, often abused
  [LOW] Not encrypted (http, not https)
  [LOW] Contains words common in phishing links
```

The score is the sum of the weights of the checks that fired, capped at 100. It is a heuristic, not a probability. The level bands are `none` (0), `low` (under 30), `medium` (30 to 59) and `high` (60 and above).

| `id` | Severity | Weight | Raised when |
| --- | --- | --- | --- |
| `ip_address_host` | high | 30 | The host is an IP address, including numeric forms browsers accept such as `3232235777`, `0x7f000001` and `127.1`. Name checks are skipped for IP hosts. |
| `mixed_script_host` | high | 30 | A host label mixes Latin letters with Cyrillic, Greek, Armenian or Cherokee letters. |
| `international_host` | medium | 15 | The host uses international characters (punycode) without mixing look-alike scripts. |
| `brand_in_subdomain` | high | 25 | A known brand, or a close imitation, appears in a subdomain of a domain that is not the brand's own. |
| `brand_in_domain` | medium | 20 | A known brand, or a close imitation, appears inside the registered domain name. |
| `many_subdomains` | medium | 10 | Three or more subdomain levels, not counting `www`. |
| `hosting_platform_subdomain` | low, or info without weight when it is the only weighted sign | 10 | The host is a user subdomain of a free publishing, static-hosting or dynamic-DNS service from a fixed list (`weebly.com`, `github.io`, `duckdns.org` and similar). The service's own root does not count. It fires on every page of those services, including the many legitimate ones, so it is shown as `info` with weight 0 unless another weighted finding is present. |
| `digits_in_subdomain` | low | 5 | The subdomain labels (not the registered domain) hold three or more digits in total. |
| `suspicious_tld` | low | 10 | The top-level domain is on a fixed list of endings common in abuse reports, such as `.top`, `.xyz` or `.zip`. |
| `url_shortener` | medium | 15 | The host is a known link shortener such as `bit.ly`. |
| `userinfo_in_url` | high | 30 | The URL has text before `@` in the authority, which browsers ignore. |
| `not_https` | low | 10 | The scheme is `http`. |
| `unusual_port` | low | 5 | An explicit port other than 80 or 443. |
| `long_url` | low | 5 | 200 characters or more (100 or more before the real-URL measurement: 19.9% of real pages passed 100). |
| `suspicious_keywords` | low | 5 per word, at most 15 | Words such as `login`, `verify` or `password` appear in the host, path or query. |

**Brand imitation.** A host token counts as a brand when it matches the built-in brand list after replacing look-alike digits (`0→o`, `1→l`, `3→e`, `4→a`, `5→s`, `7→t`) and letter pairs (`rn→m`, `vv→w`). Tokens of five or more characters also count when they are one edit away from a brand of five or more characters. When the registered domain itself is a brand (for example `paypal.com`), no brand finding is raised.

**Registered domain.** The registered domain is an offline estimate: the last two labels, or three for a short list of common second-level suffixes such as `co.uk` and `com.au`. It is not the full Public Suffix List, so some domains are split incorrectly.

**Input rules.** A URL without a scheme, such as `example.com/login`, is accepted and reported with `scheme: null`, so `not_https` cannot fire for it. A scheme other than `http` or `https`, an empty URL, a missing host, an invalid DNS label or a host over 253 characters is refused with `invalid_url`. URLs over 8,192 characters are refused with `input_too_large`.

## Measured accuracy

Measurements on public data are in [`docs/research/linkfile-benchmark.md`](../research/linkfile-benchmark.md). On the one-time locked test of the first benchmark (round 1), 0.28% of 6,877 presumed-benign real files raise a security finding at `medium` or higher (4.26% with the old rules), 168 of 180 synthetic malicious-style files are caught, and 83.3% of phishing URLs reach `low` but only 3.6% reach `medium`. For links, 54% of the PhiUSIIL phishing is flagged by `not_https` alone because every legitimate URL in that data is an `https` host root, which is why round 2 measured real URLs.

**Round 2 (development numbers for files, locked test for real URLs).** Files: on 12,816 Govdocs1 development files the security-alarm rate at `medium` or higher stays 0.23%; legacy-Office macros add 104 `low` findings (1.05% at `low` or higher, 4.2% of legacy Office files hold a VBA project); on the synthetic cases the checker catches 400 of 440 at `medium` or higher (336 before), the missed 40 being the legacy-macro cases, which raise `low`. Links, on 65,426 real benign URLs from the Common Crawl URL index (never visited): the shipped rules flagged 52.5% of the development sample at `low` or higher (31.6% of top-domain pages, 100% of pages on `github.io`, `vercel.app`, `netlify.app` and `blogspot.com`), mostly through `long_url` (19.9% of top-domain pages) and `hosting_platform_subdomain`. After the adjustments in this page's URL table the rate is 13.9% on development and **13.5% (12.4-14.6) on the once-only test** (52.2% before), and 0.18% reach `medium` or higher; the cost is phishing at `low` or higher falling from 86.4% to 75.6% on the PhiUSIIL development split, with the `medium` catch unchanged at 3.0%. Of the top-domain pages 10.2% are `http` and all of them raise `not_https`. These benign URLs are popular-site pages and user pages from one crawl, not links from mail, so they are not an estimate of false alarms on mail links.

## Limits

- File analysis looks at structure, not behavior. It does not detect malware, unpack archives or follow embedded links. A legacy Office file is checked only through its compound-file directory (bounded, never decoded or run); macros in password-protected or malformed files are not seen, and legitimate documents with macros look the same. HTML is checked only in its first and last 64 KiB.
- High entropy has innocent causes, such as compression, media, keys and certificates. The findings say so.
- The URL brand, keyword, shortener and TLD lists are fixed in the source. A brand outside the list is not recognised.
- Heuristic findings are signals for a person to weigh. Report fields with descriptions are listed in the OpenAPI schema at `/api/openapi.json`.
