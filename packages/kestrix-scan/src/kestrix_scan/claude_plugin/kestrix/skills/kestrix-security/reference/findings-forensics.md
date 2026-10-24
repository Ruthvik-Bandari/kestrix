# Forensics finding ids (`kestrix forensics file` / `kestrix forensics url`)

Each finding has `id`, `severity`, `title` and `explanation`. Source: `src/kestrix/forensics/`.
Neither check is a malware or phishing verdict: no findings means no check fired, not that the file
or link is safe.

## File findings (`kestrix forensics file PATH --json`)

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

`file_type.id` is detected from content, never the name: programs `pe`, `dos_mz`, `elf`, `macho`,
`macho_fat`, `script`; code `java_class`, `wasm`; documents `pdf`, `docx`, `xlsx`, `pptx`, `ooxml`,
`ole2`; archives `zip`, `gzip`, `bzip2`, `xz`, `7z`, `rar`; images `png`, `jpeg`, `gif`, `webp`, `tiff`;
other `swf`, `sqlite`, `text`, `empty`, `unknown`.

`exif_status`: `ok`, `no_exif`, `not_image`, `pillow_not_installed` (install the `kestrix[exif]` extra),
`unreadable`, `too_many_pixels`.

## URL findings (`kestrix forensics url URL --json`)

`score` is the sum of the weights below, capped at 100: a heuristic, not a probability. `level` is
`none` (0), `low` (under 30), `medium` (30 to 59) or `high` (60 and above).

| `id` | Severity | Weight | Raised when |
| --- | --- | --- | --- |
| `ip_address_host` | high | 30 | The host is an IP address, including numeric forms browsers accept such as `3232235777`, `0x7f000001` and `127.1`. Name checks are skipped for IP hosts. |
| `mixed_script_host` | high | 30 | A host label mixes Latin letters with Cyrillic, Greek, Armenian or Cherokee letters. |
| `international_host` | medium | 15 | The host uses international characters (punycode) without mixing look-alike scripts. |
| `brand_in_subdomain` | high | 25 | A known brand, or a close imitation, appears in a subdomain of a domain that is not the brand's own. |
| `brand_in_domain` | medium | 20 | A known brand, or a close imitation, appears inside the registered domain name. |
| `many_subdomains` | medium | 10 | Three or more subdomain levels, not counting `www`. |
| `hosting_platform_subdomain` | low, or info without weight when it is the only weighted sign | 10 | The host is a user subdomain of a free publishing, static-hosting or dynamic-DNS service from a fixed list (`weebly.com`, `github.io`, `duckdns.org` and similar). The service's own root does not count. It fires on every page of those services, including legitimate ones, so it is shown as `info` with weight 0 unless another weighted finding is present. |
| `digits_in_subdomain` | low | 5 | The subdomain labels (not the registered domain) hold three or more digits in total. |
| `suspicious_tld` | low | 10 | The top-level domain is on a fixed list of endings common in abuse reports, such as `.top`, `.xyz` or `.zip`. |
| `url_shortener` | medium | 15 | The host is a known link shortener such as `bit.ly`. |
| `userinfo_in_url` | high | 30 | The URL has text before `@` in the authority, which browsers ignore. |
| `not_https` | low | 10 | The scheme is `http`. |
| `unusual_port` | low | 5 | An explicit port other than 80 or 443. |
| `long_url` | low | 5 | 200 characters or more. |
| `suspicious_keywords` | low | 5 per word, at most 15 | Words such as `login`, `verify` or `password` appear in the host, path or query. |

A URL without a scheme is accepted (`scheme: null`). Other schemes, empty URLs and invalid hosts are
refused with `invalid_url` (exit 2); URLs over 8,192 characters with `input_too_large`.
