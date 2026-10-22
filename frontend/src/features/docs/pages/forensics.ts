// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { guide, list, note, p, section, see, table } from "../blocks";
import type { DocPage } from "../model";
import { LIMITS_NAV, ref, toolOverview } from "./helpers";

/* Follows docs/modules/forensics.md and docs/research/linkfile-benchmark.md. */

const BASE = "tools/forensics";

export const forensicsPages: DocPage[] = [
  toolOverview("forensics", BASE, [`${BASE}/how-it-works`, `${BASE}/using-it`, `${BASE}/findings`, `${BASE}/limits`]),
  {
    path: `${BASE}/how-it-works`,
    title: "File & link forensics: how it works",
    nav: "How it works",
    summary: "How a file is read and measured, which formats are recognised, and how a link is scored from its text alone.",
    sections: [
      ref("forensics", "How it works"),
      section(
        "What is measured in a file",
        table(
          ["Report field", "Meaning"],
          [
            ["`filename`", "Base name only. Directories, control characters and invisible characters are removed; at most 255 characters."],
            ["`size`", "Bytes. Files over 50 MiB are refused with `input_too_large` (10 MiB on the hosted service)."],
            ["`hashes`", "`md5`, `sha1`, `sha256`, `sha512`. MD5 and SHA-1 are included for older lookup databases and are not collision-resistant."],
            ["`file_type`", "`id`, `label`, `executable`, `extension`, `expected_extensions`, `extension_mismatch`."],
            ["`entropy`", "Whole-file Shannon entropy in bits per byte (0 to 8), per-block entropy over 4096-byte blocks, and random-looking regions."],
            ["`printable_ratio`", "Share of bytes that are printable ASCII, tab, CR or LF."],
            ["`exif`, `exif_status`", "Image metadata, with the optional `exif` extra."],
            ["`findings`", "Observations, most severe first."],
          ],
        ),
        p("A random-looking region is a run of at least two consecutive blocks with entropy at or above 7.2 bits per byte."),
      ),
      section(
        "Recognised formats",
        p("The format comes from the first bytes of the content, never from the name."),
        list(
          "Programs: `pe`, `dos_mz`, `elf`, `macho`, `macho_fat`, and `script` (a `#!` line).",
          "Code: `java_class`, `wasm`.",
          "Documents: `pdf`, `docx`, `xlsx`, `pptx`, `ooxml`, `ole2`.",
          "Archives: `zip`, `gzip`, `bzip2`, `xz`, `7z`, `rar`.",
          "Images: `png`, `jpeg`, `gif`, `webp`, `tiff`.",
          "Other: `swf`, `sqlite`, `text`, `empty`, `unknown`.",
        ),
        p("`extension_mismatch` is true when the extension is not one normally used for the detected format. It is never set for `unknown` or `empty` content."),
      ),
      section(
        "How a link is scored",
        p("URL analysis reads the link as text. It never fetches, resolves or follows the URL. The score is the sum of the weights of the checks that fired, capped at 100. It is a heuristic, not a probability. The level bands are `none` (0), `low` (under 30), `medium` (30 to 59) and `high` (60 and above)."),
        p("A host token counts as a brand when it matches the built-in brand list after replacing look-alike digits and letter pairs, and tokens of five or more characters also count when they are one edit away from a brand. When the registered domain itself is a brand, no brand finding is raised. The registered domain is an offline estimate (the last two labels, or three for a short list of common second-level suffixes), not the full Public Suffix List."),
      ),
    ],
  },
  {
    path: `${BASE}/using-it`,
    title: "File & link forensics: using it",
    nav: "Using it",
    summary: "Analyze a file or a link in the dashboard or with `kestrix forensics`, and read the photo-metadata status.",
    sections: [
      section(
        "In the dashboard",
        p("The File & link page has two tabs. Drop a file to see its hashes, real format, entropy chart and photo metadata, or paste a link to score it. The file goes only to the Kestrix server (on your computer, or on the hosted service, which never stores it). A link is analyzed as text and never opened."),
      ),
      section("On the command line", guide("forensics")),
      section(
        "Commands and exit codes",
        table(
          ["Command", "Options", "Exit codes"],
          [
            ["`kestrix forensics file PATH`", "`--json`", "0 analysed; 2 rejected (for example larger than 50 MiB)"],
            ["`kestrix forensics url URL`", "`--json`", "0 analysed; 2 rejected (for example not http or https)"],
          ],
        ),
        p("Rejections print `Rejected (<reason>): <detail>` to stderr. A URL without a scheme, such as `example.com/login`, is accepted and reported with `scheme: null`. A scheme other than `http` or `https`, an empty URL, a missing host or an invalid DNS label is refused with `invalid_url`; URLs over 8,192 characters with `input_too_large`."),
      ),
      section(
        "Photo metadata",
        p("Reading photo metadata needs the optional `exif` extra (Pillow). It runs only for JPEG, PNG, TIFF and WebP content. Pixel data is never decoded, images declaring more than 200,000,000 pixels are not opened, and at most 200 tags are returned, each cut to 200 characters."),
        table(
          ["exif_status", "Meaning"],
          [
            ["`ok`", "Metadata returned in `exif`."],
            ["`no_exif`", "An image without EXIF."],
            ["`not_image`", "Not a format that carries EXIF."],
            ["`pillow_not_installed`", "Install the `exif` extra to read it."],
            ["`unreadable`", "Metadata present but malformed."],
            ["`too_many_pixels`", "The image declares implausibly large dimensions, so it was not opened."],
          ],
        ),
        see("Every finding id", `${BASE}/findings`),
      ),
    ],
  },
  {
    path: `${BASE}/findings`,
    title: "File & link forensics: findings reference",
    nav: "Findings reference",
    summary: "Every file finding and every link check, with severity, weight and what raises it.",
    sections: [
      section(
        "File findings",
        table(
          ["id", "Severity", "Raised when"],
          [
            ["`bidi_control_in_name`", "high", "The name contains a Unicode bidirectional control that can make `photo[RLO]gpj.exe` display as `photoexe.jpg`."],
            ["`double_extension`", "high", "The name ends in a document-like extension followed by one Windows runs, such as `.pdf.exe` or `.jpg.scr`."],
            ["`extension_mismatch`", "high for programs, medium otherwise", "The extension does not fit the detected content."],
            ["`executable_file`", "info", "The content is a program or script."],
            ["`empty_file`", "info", "The file has no content."],
            ["`expected_high_entropy`", "info", "Random-looking data in a format that normally stores compressed data (PDF, Office, ZIP, SWF, PNG, JPEG and similar)."],
            ["`possible_packing`", "medium", "A program has random-looking regions. Packers, encrypted payloads, installers and compressed resources all look like this."],
            ["`high_entropy_file`", "medium", "The whole file is at or above 7.2 bits per byte, in a format that does not explain it."],
            ["`high_entropy_region`", "low", "Part of a file looks random, in a format that does not explain it."],
            ["`macro_office_file`", "high for `.docx`, `.xlsx`, `.pptx` and other macro-free extensions, medium otherwise", "An Office Open XML package holds a `vbaProject.bin` macro part. Legitimate macro-enabled documents look the same."],
            ["`encrypted_archive`", "medium", "A ZIP has the encryption flag set, so its contents cannot be inspected."],
            ["`embedded_executable`", "high", "A PDF, image or Office Open XML file holds a Windows program after offset 0."],
            ["`active_content_svg`", "medium", "An SVG image holds `<script`, a `javascript:` link or an `onload`-style event handler."],
            ["`runnable_script_file`", "medium for `.vbs`, `.vbe`, `.jse`, `.wsf`, `.wsh`, `.hta`, `.bat`, `.cmd`, `.ps1`, `.psm1`, `.scf`; low for `.js`", "Text content under a script extension that Windows runs on a double click."],
            ["`gps_location`", "high", "A photo has GPS tags. Decoded coordinates are shown when complete."],
            ["`identifying_metadata`", "low", "A photo includes `Make`, `Model`, serial numbers, `CameraOwnerName`, `Artist`, `Software` or `DateTimeOriginal`."],
          ],
        ),
      ),
      section(
        "Link checks",
        table(
          ["id", "Severity", "Weight", "Raised when"],
          [
            ["`ip_address_host`", "high", "30", "The host is an IP address, including numeric forms browsers accept such as `3232235777` and `127.1`."],
            ["`mixed_script_host`", "high", "30", "A host label mixes Latin letters with Cyrillic, Greek, Armenian or Cherokee letters."],
            ["`international_host`", "medium", "15", "The host uses international characters (punycode) without mixing look-alike scripts."],
            ["`brand_in_subdomain`", "high", "25", "A known brand, or a close imitation, appears in a subdomain of a domain that is not the brand's own."],
            ["`brand_in_domain`", "medium", "20", "A known brand, or a close imitation, appears inside the registered domain name."],
            ["`many_subdomains`", "medium", "10", "Three or more subdomain levels, not counting `www`."],
            ["`hosting_platform_subdomain`", "low", "10", "The host is a user subdomain of a free publishing, static-hosting or dynamic-DNS service from a fixed list."],
            ["`digits_in_subdomain`", "low", "5", "The subdomain labels hold three or more digits in total."],
            ["`suspicious_tld`", "low", "10", "The top-level domain is on a fixed list of endings common in abuse reports, such as `.top`, `.xyz` or `.zip`."],
            ["`url_shortener`", "medium", "15", "The host is a known link shortener such as `bit.ly`."],
            ["`userinfo_in_url`", "high", "30", "The URL has text before `@` in the authority, which browsers ignore."],
            ["`not_https`", "low", "10", "The scheme is `http`."],
            ["`unusual_port`", "low", "5", "An explicit port other than 80 or 443."],
            ["`long_url`", "low", "5", "100 characters or more."],
            ["`suspicious_keywords`", "low", "5 per word, at most 15", "Words such as `login`, `verify` or `password` appear in the host, path or query."],
          ],
        ),
      ),
    ],
  },
  {
    path: `${BASE}/limits`,
    title: "File & link forensics: limits and measured accuracy",
    nav: LIMITS_NAV,
    summary: "What the file and link checks cannot tell you, and the development-split measurements, with the locked test not yet run.",
    sections: [
      ref("forensics", "Limits"),
      section(
        "Measured accuracy",
        note("Every number below is a development-split number from public data. The locked test has not been run, so none of these is a final measurement.", "caution"),
        p("Files. On Govdocs1 (12,816 presumed-benign real files), 0.2% of files raise a security finding at `medium` or higher after the benchmark's first round of rule changes, against 5.0% before. On 360 synthetic malicious-style cases the file checker catches 336 at `medium` or higher, against 180 before, with no alarm on the 240 benign synthetic controls. The synthetic cases show that the rules fire as intended, not how real malware fares. Govdocs1 states that malware was not removed from it, so its false-alarm rates are upper bounds."),
        table(
          ["File measure", "Before round 1", "After round 1"],
          [
            ["Govdocs1 files with a security finding at `medium` or higher", "5.0%", "0.2%"],
            ["Synthetic malicious-style cases caught at `medium` or higher", "180 of 360", "336 of 360"],
          ],
        ),
        p("Links. On PhiUSIIL, 86.4% of phishing URLs reach `low` or higher but only 3.0% reach `medium` or higher, against 63.7% and 2.0% before round 1. False alarms are 0.19% (PhiUSIIL host roots) and 1.65% (Majestic host roots) at `low` or higher, and 0.0% at `medium`."),
        table(
          ["Link measure", "Before round 1", "After round 1"],
          [
            ["Phishing URLs at `low` or higher", "63.7%", "86.4%"],
            ["Phishing URLs at `medium` or higher", "2.0%", "3.0%"],
            ["Benign false alarms at `low` or higher (PhiUSIIL / Majestic)", "0.13% / 1.62%", "0.19% / 1.65%"],
          ],
        ),
      ),
      section(
        "Why the link numbers are weak evidence",
        list(
          "In the PhiUSIIL data every legitimate URL is an `https` host root with no path, while 54% of its phishing URLs are `http`, so `not_https` alone flags 54% of the phishing there. The benign data has no URLs with paths, queries or `http`, so false-alarm rates on real browsing are unmeasured.",
          "Most of the gain from round 1 comes from two signals, `hosting_platform_subdomain` and `digits_in_subdomain`, whose benign side the data cannot test: a legitimate user page on a free host is absent from it, so their false-alarm cost on real browsing is unmeasured.",
          "Not covered and not claimed: macros inside legacy `.doc` and `.xls` files, password-protected 7z, RAR and Office files, HTML or JavaScript obfuscation, and any malware that is not built to show one of the traits the rules look for.",
          "Govdocs1 holds US government web documents from about 2009 with very few Office Open XML files, so the false-alarm cost of the macro rule on modern documents is unmeasured.",
        ),
      ),
    ],
  },
];
