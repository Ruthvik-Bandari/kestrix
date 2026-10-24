# Link and file checker accuracy benchmark

This page records how well the `kestrix.forensics` URL checker and file checker do on public data, where they fail, and what one round of rule changes bought. It is research tooling: the package is [`src/kestrixlinkfilebench/`](../../src/kestrixlinkfilebench/) (not in the published wheel; it follows the [email benchmark](mail-benchmark.md) and imports its shared helpers), the jobs are `hpc/linkfile_*`, and the aggregate outputs are in [`docs/data/linkfile/`](../data/linkfile/README.md).

**Status (2026-10-23).** The first sections (up to round 1) are **development-split** numbers; the one-time locked test of 2026-10-22 is reported under *Locked test*. Round 2 (below it) was measured on the development splits, and its real-URL test split was evaluated once on 2026-10-23. The module page [`forensics.md`](../modules/forensics.md) still says the checks are not verdicts; nothing here changes that.

## What the dev numbers say

- **The link results mostly measure how the data was collected.** In PhiUSIIL every legitimate URL is an `https` host root (no path, no query). Phishing URLs are 54% `http`, 24% have a path. The baseline "catches" 63.7% of phishing at `low` or higher, but 54% of all phishing is flagged by `not_https` alone, and on a matched subset (https, bare host, same length band) the baseline catch is **9.0%** (6.4-14.6) at `low` or higher and **0.3%** at `medium` or higher.
- **Almost nothing reaches `medium`.** At `medium` or higher the baseline flags 2.0% of phishing (1.6-2.5) and no benign URL; `high` is reached by 4 URLs in 66,593. The score weights are too small for the signals that fire on real phishing hosts.
- **Link false alarms were first measured only on host roots (superseded by round 2, which measures real URLs).** Benign false alarms are 0.1% (PhiUSIIL roots) and 1.6% (Majestic roots, 83% of them `suspicious_tld`) at `low` or higher, and zero at `medium`. There are no benign URLs with paths, queries or `http` in the data, so `long_url`, `suspicious_keywords`, `not_https` and every path signal have no measurable false-alarm rate here. These rates are a floor, not an estimate for real browsing.
- **File false alarms on real documents are dominated by two format blind spots.** On Govdocs1 (12,816 presumed-benign files) the baseline raises a security finding at `medium` or higher on **5.0%** (3.8-6.6): 74% of those are `high_entropy_file` on legacy PowerPoint (`.ppt`, 473 of 722), then Flash (`.swf`, 65) and legacy Word (`.doc`, 48). Legacy Office (OLE2) and Flash store compressed data, which the checker did not know.
- **File recall is measured only on synthetic cases.** The baseline catches 180 of 360 dev cases at `medium` or higher (9 of 18 families fully). It misses macro Office files, encrypted ZIPs, programs appended to PDFs or images, SVG scripts and script attachments, because it has no rule for them.
- **Round 1 (details below) cut file false alarms from 5.0% to 0.2% at `medium` or higher and raised synthetic catch from 180 to 336 of 360, with no benign-control alarm. For links it raised `low`-or-higher catch from 63.7% to 86.4% and `medium`-or-higher from 2.0% to 3.0%, with false alarms unchanged (0.2% and 1.7% at `low`). Most of the link gain comes from two signals whose benign side the data cannot test (see the caveat in round 1).**

## Datasets

| Dataset | Used for | Items after dedupe | Size (downloaded) | License | URL |
| --- | --- | --- | --- | --- | --- |
| PhiUSIIL Phishing URL dataset (UCI 967) | phishing and benign URLs (label 1 = legitimate, 0 = phishing, inverted here) | 95,124 phishing, 134,807 benign (of 100,945 and 134,850) | 15,376,007 B zip, sha256 `0a639fd0...c9a59a` | CC BY 4.0 | <https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset> |
| Majestic Million | 30,000 seeded domains turned into host-root URLs (`https://domain/`, half with `www.`): 28,270 kept | 28,270 benign | 78,945,327 B csv, sha256 `78b104b1...2a8a3c` | CC BY 3.0 | <https://majestic.com/reports/majestic-million> |
| Govdocs1 (Digital Corpora), 20 seeded zip threads of 1,000 (`144 152 217 240 264 327 366 444 470 489 536 553 569 653 656 683 763 822 827 880`) | false alarms on real files of many formats | 19,693 files (of 19,734 read; 31 content duplicates, 10 over 50 MiB dropped) | 8,129,431,646 B in 20 zips | "freely redistributable" (no formal license) | <https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/> |
| Common Crawl URL index, crawl `CC-MAIN-2026-43` (round 2) | benign full URLs: 45,426 pages of 5,000 Majestic top-100,000 domains plus 20,000 user-site pages on four platforms (after the cap, 65,426 URLs, 19,318 groups) | 65,426 | `cluster.idx` 104,520,381 B, plus several GB of range reads | Common Crawl Terms of Use (limited license; crawled content stays under its owners' terms) | <https://commoncrawl.org/terms-of-use> |
| Synthetic files (`synth.py`) | recall per case, benign controls | 900 (18 malicious-style and 12 benign-control families x 30) | generated in memory | Generated here (Apache-2.0) | `src/kestrixlinkfilebench/synth.py` |

[`linkfilebench-manifest.json`](../data/linkfile/linkfilebench-manifest.json) records URL, size, SHA-256 and download time of every file (trust on first use, downloaded 2026-10-22 on the transfer node).

**Attribution.** PhiUSIIL: Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website)* [Dataset]. UCI Machine Learning Repository. <https://doi.org/10.1016/j.cose.2023.103545> (CC BY 4.0). Majestic: *Majestic Million*, Majestic, <https://majestic.com/reports/majestic-million> (CC BY 3.0). Govdocs1: Garfinkel, S., Farrell, P., Roussev, V., & Dinolt, G. (2009). Bringing science to digital forensics with standardized forensic corpora. *Digital Investigation, 6*, S2-S11 (DFRWS 2009).

**Not used, on purpose.** OpenPhish and URLhaus (their terms forbid this use). PhishTank: the terms page shows an archived 2006 text that limits use to personal, non-commercial purposes while also calling the data free for commercial use, forbids automated access without permission, and requires registration; that does not read as a clear permission, so it was skipped (PhiUSIIL's URLs come from it and carry PhiUSIIL's CC BY 4.0). No live-malware set (MalwareBazaar, VirusShare, UNSAFE-DOCS, SOREL) was downloaded.

**Safety.** URLs are text; nothing fetches, resolves or visits one. Files are read as bytes from the zips and never executed or rendered. Govdocs1 states that malware was not removed, so "benign" means presumed benign and file false-alarm rates are upper bounds (no antivirus check was run).

## Method

1. **Acquire** (`hpc/linkfile_acquire.sh`, transfer node, standard library only). Reuses the email benchmark's download, size/SHA-256 and manifest code.
2. **Build** (Slurm, CPU). *Links:* PhiUSIIL labels inverted (tested), Majestic domains chosen by seeded hash (`kestrixlinkfile-v1`) and turned into host roots, URLs the analyzer rejects dropped (none were), exact duplicates (same lower-cased scheme, host, path, query) and near duplicates (same host without `www.`, same path, query ignored) collapsed, any near-duplicate key that carries both labels dropped from both. PhiUSIIL lost 5,821 phishing and 43 benign URLs; Majestic lost 1,730. *Files:* every zip member hashed, content duplicates across threads kept once, members over 50 MiB dropped.
3. **Split before any tuning** ([`link-split-manifest.json`](../data/linkfile/link-split-manifest.json), [`file-split-manifest.json`](../data/linkfile/file-split-manifest.json)). Links are grouped by registered domain, estimated offline (last two labels, three under a country code with a common second level; coarser than the Public Suffix List, which only keeps more together); group names are hashed, so no host is stored with the features. Files are grouped by Govdocs thread. Groups go to dev or test within each (source, label) stratum by seeded hash until about 30% is in test. Dev: 180,739 links (142,071 groups), 13,416 files (13 Govdocs threads plus 30 synthetic groups). Test: 77,462 links, 7,177 files. Synthetic variants 0-19 of each family are dev, 20-29 test.
4. **Features** (Slurm arrays, 16 and 20 tasks). `analyze_url` and `analyze_file` run offline per item; only finding ids and severities, the URL level and score, URL shape counts (length, path, query, scheme, host dots/hyphens/digits, TLD), the detected file type, extension, size and entropy are stored. No URL, host, file name or content. Each shard report records the code version; the locked test refuses to run when dev and test features come from different rules. Pillow 12.2.0 was installed beside the code (not in the shared environment), so photo-metadata findings are included.
5. **Metrics.** Links: share of phishing at or above each level (`low`, `medium`, `high`), benign false alarms per cohort, precision at the corpus class mix (not real-world precision). Files: the *alarm* of a file is the highest severity among its **security** findings; photo-metadata findings (`gps_location`, `identifying_metadata`) are privacy findings and `executable_file`, `empty_file`, `expected_high_entropy` are context, both reported separately. Intervals are the email benchmark's 95% percentile bootstrap that resamples whole groups (1,000 resamples); cohorts under 8 groups show a message-level binomial interval marked `msg`.
6. **Leakage controls (links).** See below.
7. **Error analysis and round 1.** Aggregate probes (`probe.py`) count curated tags per cohort on the cluster; the rules were changed one at a time, each measured alone on the full dev split, then the kept set together.
8. **Locked test.** `hpc/linkfile_locked.sh` (not run).

## Dev results: the shipped rules (baseline)

Dev: 66,593 phishing, 94,344 PhiUSIIL benign and 19,802 Majestic benign URLs (no analyzer errors); 12,816 Govdocs files and 600 synthetic cases (no errors).

### Links

| Level | Phishing caught | False alarms, PhiUSIIL benign | False alarms, Majestic benign | Precision vs all benign |
| --- | --- | --- | --- | --- |
| low or higher | 63.7% (53.1-75.7) | 0.1% (0.1-0.2) | 1.6% (1.4-1.8) | 99.0% (98.8-99.1) |
| medium or higher | 2.0% (1.6-2.5) | 0.0% (0.0-0.0) | 0.0% (0.0-0.0) | 100% (1,336 of 1,336) |
| high | 0.0% (4 of 66,593) | 0.0% | 0.0% | 100% (4 of 4) |

The wide interval on `low` comes from group resampling: a few big shared-hosting groups hold many phishing URLs. Phishing by shape (share flagged at `low` or higher): `http` host roots 100.0% (31,308), `http` with path 100.0% (4,872), `https` host roots 11.3% (18,832), `https` with a path 35.2% (11,581). By TLD, `.cf`, `.ga`, `.ml` are 100% caught (they are on the checker's TLD list) while `.co` is 18.3% and `.io` 25.3%; Majestic roots on abused-list TLDs are the false alarms (`suspicious_tld` is 88% of them). Registration age is not in either dataset, so no per-age numbers exist.

Why phishing is missed (below `medium`, 65,257 URLs, 24,206 with no finding at all): `not_https` 54%, `suspicious_tld` 8%, `suspicious_keywords` 4%, `long_url` 3%, `many_subdomains` 2%, `url_shortener` 1%. Why benign roots are flagged at `low` or higher: `suspicious_tld`, `many_subdomains` and `brand_in_domain` (PhiUSIIL), `suspicious_tld` and `international_host` (Majestic).

### Leakage: collection artifacts in PhiUSIIL

| Class | Share `https` | Has path | Has query | Median length |
| --- | --- | --- | --- | --- |
| phishing | 45.7% | 23.8% | 4.3% | 34 |
| PhiUSIIL benign | 100% | 0% | 0% | 27 |
| Majestic benign (host roots by construction) | 100% | 0% | 0% | 25 |

Single shape features separate the classes without any risk judgement: AUC (phishing against PhiUSIIL benign) is 0.71 for URL length, 0.23 for `https` (so `http` marks phishing), 0.62 for has-path, 0.67 for digits in the host. The **matched subset** draws equal numbers of phishing and PhiUSIIL benign URLs from each (scheme, path, query, length band) cell; because benign URLs only exist as `https` host roots, it keeps 11,948 per class in 5 cells (17.9% of phishing), all `https` host roots, where AUC for scheme, path and query is exactly 0.5.

Baseline on the matched subset: **9.0% (6.4-14.6) caught at `low` or higher, 0.3% (0.2-0.6) at `medium` or higher, false alarms 0.2% and 0.0%**. Findings whose class gap shrinks by half or more (or flips) from the full set to the matched subset are flagged collection-driven: `not_https` (54.3% of phishing against 0.0% benign, 0.0% matched gap), `long_url`, `many_subdomains`, `suspicious_keywords` and `suspicious_tld`. The matched subset says nothing about path signals (it has none), and it can only be as good as the benign side: legitimate pages with paths, queries or `http` links are not in the data.

### Files (Govdocs1 dev, 12,816 files, 13 threads)

| Measure | Baseline |
| --- | --- |
| Security finding at `low` or higher | 8.6% (6.7-10.8) |
| Security finding at `medium` or higher | 5.0% (3.8-6.6) |
| Security finding at `high` | 0.0% (0.0-0.1), 4 files |
| Security or privacy finding at `medium` or higher | 5.0% (3.8-6.6) |
| By detected type, `medium` or higher | `ole2` 22.5% (17.3-28.0), `unknown` 9.5% (3.8-16.5), `gzip` 3.0% (1.2-4.8), `pdf` 0.0%, `jpeg` 0.0%, `gif` 0.0%, `text` 0.0% |
| Finding id (share of files) | `expected_high_entropy` 34.4% (context), `high_entropy_file` 4.9%, `high_entropy_region` 3.6%, `identifying_metadata` 1.5% (privacy), `extension_mismatch` 0.1%, `executable_file` 0.0%, `gps_location` 0.0% (privacy) |

False alarms at `medium` or higher by cause: `high_entropy_file` on `.ppt` 473, on `.swf` 65, on `.doc` 48, on `.pps` 25; `extension_mismatch` on gzip data named `.ps` 7 (a compressed PostScript), on shebang text named `.txt` 3. Only 4 programs and 19 mismatches were found among the 12,816 files.

Synthetic cases (dev, 20 variants per family; never pooled with Govdocs): caught at `medium` or higher: `double_ext_exe`, `double_ext_scr`, `bidi_name`, `pe_named_pdf`, `pe_named_png`, `elf_named_txt`, `script_named_png`, `packed_pe`, `encrypted_blob` (20 of 20 each). Missed (0 of 20): `macro_docm`, `macro_named_docx`, `macro_xlsm`, `encrypted_zip`, `pdf_with_pe_appended`, `jpeg_with_pe_appended`, `svg_script`, `script_attachment`, `html_obfuscated`. The 12 benign-control families raised no alarm (0 of 240). Because the author wrote both the cases and the rules, a catch says the rule does what was intended and nothing about real malware; the families `packed_pe`, `encrypted_blob` and the macro and encrypted-archive families have legitimate look-alikes that no static check can tell apart.

## Round 1: rule changes measured on dev

**Decision rule, fixed before the candidates were measured.** Files: keep a change if its target synthetic family is caught more, no family or control gets worse, and Govdocs dev false alarms at `medium` or higher rise by at most 0.1 point (or fall). Links: keep a change if catch rises by at least 0.5 point on the full set and on the matched subset, and false alarms of each benign cohort at the same level rise by at most 0.1 point. Each candidate was measured alone on the full dev split (Slurm job ids in [`linkfile-rules-round1.json`](../data/linkfile/linkfile-rules-round1.json)), then the kept set together. Candidates came from the checker's known gaps (the synthetic families) and from the dev error analysis and probes (Govdocs false-alarm causes, link host shapes). Host-shape tags that did not separate the classes in the probe (hyphens, digits in the registered label, entropy) were not built.

### Files

| Change | Dev result alone | Decision |
| --- | --- | --- |
| E1: legacy Office (OLE2) counts as a format that stores compressed data | Govdocs `medium` or higher 5.00% to 0.73%; no synthetic change | keep |
| E2: recognise SWF (`CWS`, `ZWS`, `FWS` signature, version below 64, not plain text) as compressed | 5.00% to 4.49%; no synthetic change | keep |
| F1: `macro_office_file` (`vbaProject.bin` in the first or last 64 KiB of an Office Open XML package; high under a macro-free extension such as `.docx`, else medium) | synthetic catch 180 to 240 (3 families 0 to 20); Govdocs unchanged | keep |
| F2: `encrypted_archive` (ZIP encryption flag, medium) | 180 to 200; Govdocs unchanged | keep |
| F3: `embedded_executable` (PE image after offset 0 in a PDF, image or Office Open XML file, high) | 180 to 220; Govdocs unchanged | keep |
| F4: `active_content_svg` (script, `javascript:` or event handler in an SVG, medium) | 180 to 200; Govdocs unchanged | keep |
| F5: `runnable_script_file` (`.vbs .vbe .jse .wsf .wsh .hta .bat .cmd .ps1 .psm1 .scf` medium, `.js` low) | 180 to 196 (16 of 20: the `.js` variants stay low by design); Govdocs unchanged | keep |

Kept together: Govdocs security alarms at `low` or higher **8.6% to 0.2%** (0.1-0.3), at `medium` or higher **5.0% to 0.2%** (0.1-0.3); synthetic malicious cases caught **180 to 336 of 360** (16 of 18 families fully; still missed: `html_obfuscated`, and the `.js` variants of `script_attachment`); benign controls 0 alarms of 240. With privacy findings included the `low` rate is 1.7% (0.9-2.7), almost all `identifying_metadata` on photos. The remaining Govdocs alarms are gzip data named `.ps`, high-entropy `.bmp` and `.dwf` files and a few mislabeled text files. Not covered and not claimed: macros inside legacy `.doc`/`.xls`, password-protected 7z, RAR and Office files, HTML or JavaScript obfuscation, and any malware that is not built to show one of these traits.

### Links

| Change | Catch `low`+ (full / matched) | Catch `medium`+ (full / matched) | False alarms `low`+ (PhiUSIIL / Majestic) | Decision |
| --- | --- | --- | --- | --- |
| baseline | 63.7% / 9.0% | 2.0% / 0.3% | 0.13% / 1.62% | |
| L1: `hosting_platform_subdomain` (user subdomain of a free site builder, static host or dynamic-DNS service from a fixed list; low, weight 10) | 81.2% / 56.7% | 2.6% / 0.9% | 0.13% / 1.62% | keep, provisional |
| L2: `digits_in_subdomain` (three or more digits in the subdomain labels; low, weight 5) | 76.6% / 45.4% | 2.8% / 2.2% | 0.19% / 1.65% | keep |
| L3: `long_host` (host of 35 characters or more; low, weight 5) | 72.5% / 14.4% | 2.5% / 0.6% | 0.52% / 1.90% (matched 3.3%) | reject: benign false alarms +0.39 point on PhiUSIIL roots |

L1 and L2 together: **86.4% (82.7-89.5) caught at `low` or higher, 3.0% (2.4-3.8) at `medium` or higher; matched subset 75.9% (47.8-86.6) and 2.5% (0.8-4.7); false alarms 0.19% and 1.65% at `low`, 0.0% at `medium`; precision against all benign 99.1%.** `high` is still reached by none of the changes.

**Caveat on L1 and L2, which the data cannot resolve.** In this data legitimate URLs are popular roots, so a legitimate user page on a free host (a student site on `github.io`, a store on `weebly.com`) is absent: the benign false-alarm side of `hosting_platform_subdomain` is zero by construction, and `digits_in_subdomain` fires on 0.06% of benign roots mostly because a few generated names exist. The matched-subset jump from 9.0% to 75.9% reflects that the phishing side is rich in platform subdomains (45% of https host-root phishing is on a static or cloud host, 14% on a site builder) while the benign side has none. The rule is kept at `low` severity because the host class is a documented abuse pattern and a `low` finding alone prompts no alarm, but its false-alarm cost on real browsing is **unmeasured**. A benign URL set with paths, queries and platform subdomains is needed to measure it. Nothing in round 1 moves a phishing URL to `high`, and `medium` or higher catch stays at 3.0%: a score of 30 needs several signals that real phishing hosts rarely carry together.

## Round 2 (2026-10-23): file gaps and real-browsing links

Rules and data added after the locked test. Round 2 is measured on the **development split only**, and the old locked splits stay spent: nothing here was tuned on them. The code versions are in [`linkfile-rules-round2.json`](../data/linkfile/linkfile-rules-round2.json); each candidate was measured on the cluster with the same synthetic cases, the same 12,816 Govdocs1 dev files and the same split as round 1.

### File gaps

**Decision rule, fixed before measuring.** As in round 1, keep a change if its target synthetic family is caught more and Govdocs dev false alarms at `medium` or higher rise by at most 0.1 point. A change that only adds `low` findings is judged at `medium` or higher too, and its rise at `low` or higher is reported next to it.

| Change | Govdocs dev, `medium`+ | Govdocs dev, `low`+ | Synthetic target | Decision |
| --- | --- | --- | --- | --- |
| Shipped rules (round 1), re-measured | 0.23% (29 files) | 0.23% (30) | 336 of 440 malicious-style files caught, 16 of 22 families | |
| G1: `macro_office_file` for legacy OLE2 files (`.doc .xls .ppt`) at `medium` | 0.23% to 1.04% (+104 files: 95 `.xls`, 9 `.doc`) | | `macro_doc_legacy`, `macro_xls_legacy` 0 to 20 of 20 each | reject: +0.81 point |
| G1: the same at `low` | 0.23% (unchanged) | 0.23% to 1.05% (+104) | both families raise the finding at `low` only (caught at `medium`: 0 of 40) | keep at `low`, see below |
| G2 v1: `obfuscated_html`, a decoder (`eval`, `document.write`, `Function(`) run on `atob`/`unescape`/`decodeURIComponent`/`fromCharCode` | 0.23% to 0.68% (+58 `.html` files) | | | reject: +0.45 point |
| G2 v2: the decoder must be run on a string of 100 or more characters (or 20 or more character codes), or sit within 700 characters of a 300-character or longer base64, hex, `\xNN` or `%uNNNN` blob; inline images ignored; a `data:` or `blob:` script URL; or two weaker signals together | 0.23% (unchanged, 0 of 2,751 `.html` files) | 0.23% (unchanged) | `html_obfuscated` and `html_form_redirect` 0 to 20 of 20 each | keep |
| G3: `.js` is `medium` when it uses `WScript`, `ActiveXObject`, `Scripting.FileSystemObject`, `Shell.Application`, `WSH`, `GetObject(` or `eval(` of an encoded string; `low` otherwise | unchanged (no `.js` files in the dev threads) | unchanged | `wsh_js` 0 to 20 of 20; `script_attachment` `.js` variants now all caught (16 to 20 of 20) | keep; real false-alarm cost unmeasured |

G1 `medium` and G2 v1 were measured in one combined run; their Govdocs effects are separated by finding id, which is exact because each file raises one of them.

Kept together: Govdocs security alarms at `medium` or higher **0.23% (0.13-0.33), unchanged**; at `low` or higher **0.23% to 1.05%** (0.63-1.53), all of the rise legacy macros; synthetic malicious-style files caught at `medium` or higher **336 to 400 of 440** (20 of 22 families fully; the other two are the legacy-macro families, which raise `low`); the 16 benign-control families raise nothing at `medium` or higher (0 of 320), and 20 `low` alarms are the plain `.js` control, which is `low` by design.

What the numbers mean and do not:

- **Legacy macros are common in legitimate files.** 104 of 2,461 legacy Office (OLE2) files in the dev threads hold a VBA project (4.2%; 95 of 887 `.xls`, 9 of 845 `.doc`, none of 722 `.ppt`). A directory check cannot tell a government form with a macro from a malicious document, so the finding stays `low` and its text says so. The rise at `low` or higher (+0.81 point) is above the 0.1 point limit; the finding is kept at `low` for visibility, and moving it to `info` is a one-word change if that rise is not acceptable. The macro is never read or decompressed: only the compound-file directory is parsed, with bounded sector, chain and entry counts; a damaged file gives an `info` note, `ole_unreadable`, and no macro claim.
- **HTML obfuscation was tuned on Govdocs dev.** Version 1 fired on the classic analytics snippet `document.write(unescape("%3Cscript ..."))`, which is on legitimate pages; version 2 needs a long encoded string. Govdocs holds no `.htm` or `.svg` files in dev and old web pages only, so modern minified or generated pages are unmeasured. The synthetic cases are written by the same author as the rules and show only that each shape is caught.
- **JavaScript.** Govdocs dev has no `.js`; the `medium` rule can fire on legitimate Windows administration scripts and on `eval(unescape(...))` in old libraries.

### Real-browsing false alarms on links (Common Crawl)

**Why.** The benign URLs of the first benchmark were host roots, so `long_url`, `not_https`, the keyword and path signals, and the two round-1 subdomain signals had no measurable false-alarm rate on real links. Round 2 builds a benign sample of full URLs and measures them.

**Dataset** ([`commoncrawl-manifest.json`](../data/linkfile/commoncrawl-manifest.json), [`realurl-build.json`](../data/linkfile/realurl-build.json), [`realurl-split-manifest.json`](../data/linkfile/realurl-split-manifest.json)).

- *Source and terms.* The Common Crawl URL index of crawl `CC-MAIN-2026-43` (crawled 2026-10-05 to 2026-10-18), read through the public `cluster.idx` and `cdx-*.gz` files with range requests of about 250 KB. Terms of Use <https://commoncrawl.org/terms-of-use> (last updated 2024-03-07; saved copy hash `d438ca60...2342c4`): a limited, non-exclusive license to use the service; the crawled content may be subject to its owners' own terms; no unlawful use, no violation of others' rights, no collecting of personal information for use apart from the content. Only the text of index lines (URL, HTTP status, MIME type) is read: no page is fetched, no URL is visited, and the URLs are not redistributed (they stay under `/scratch`, mode 0700/0600); the repository holds counts and rates. This is not legal advice.
- *Top domains.* A seeded sample (`kestrixlinkfile-v1`) of 12,000 domains from the first 100,000 Majestic ranks was tried in order until 5,000 had at least one usable page (7,900 were tried, 63% had one in the crawl; HTTP status 200 and an HTML MIME type). Up to 10 URLs per domain came from one or two random blocks of the domain's key range. This gave 45,428 URLs, 45,426 after exact deduplication. Both `http` and `https` pages are kept as crawled: 89.9% are `https` in the dev sample.
- *User-content hosts.* Random blocks inside the key range of `github.io`, `vercel.app`, `netlify.app` and `blogspot.com` (every `*.platform` host is contiguous in the index), at most 2 URLs per host, then whole hosts in seeded order until 5,000 URLs per platform. `wordpress.com` (2 index blocks) and `pages.dev` (1 block) had no usable pages in this crawl and are not measured. The four platforms hold 0.8% (`blogspot.com`), 0.02%, 0.01% and 0.005% of this crawl's index blocks.
- *Split.* By domain (`top_domain`) or by full host (platform pages, so that a platform is spread over both sides), before any look at results: dev 45,789 URLs in 13,518 groups; test 19,637 URLs in 5,800 groups.
- *Metric.* A false alarm is a URL at `low` or higher, or at `medium` or higher; rates are shares of the sample with grouped 95% bootstrap intervals. All items are benign by assumption (popular sites and user pages the crawler reached; some may host abuse), so rates are upper bounds on false alarms for this kind of page. They say nothing about links in mail, which skew to short-lived, promotional or login pages.

**What the shipped rules do on real URLs (dev, 45,789 URLs).**

| Cohort | URLs (groups) | `low` or higher | `medium` or higher |
| --- | --- | --- | --- |
| All | 45,789 (13,518) | **52.5%** (51.6-53.5) | 0.20% (0.14-0.27) |
| Top domains | 31,790 (3,495) | **31.6%** (30.5-32.7) | 0.08% (0.02-0.19) |
| User-content hosts, all four | 13,999 (10,023) | **100.0%** | 0.46% (0.34-0.58) |
| `blogspot.com` / `github.io` / `netlify.app` / `vercel.app` | 3,500 / 3,500 / 3,499 / 3,500 | 100.0% each | 0.06% / 0.49% / 0.14% / 1.14% |

Share of each cohort that raises each finding at any severity (shipped rules), the false-alarm rate per finding id:

| Finding id | Top domains | User-content hosts |
| --- | --- | --- |
| `long_url` (100 characters or more) | **19.9%** (19.0-20.8) | 4.0% (3.7-4.4) |
| `not_https` | **10.2%** (9.3-11.1) | 3.2% (2.9-3.6) |
| `hosting_platform_subdomain` | 0.03% (0.00-0.10) | **100.0%** (by construction: every page is on a listed host) |
| `digits_in_subdomain` | 0.89% (0.66-1.19) | 6.7% (6.3-7.2); `netlify.app` 11.2% (10.1-12.5), `github.io` 5.9%, `vercel.app` 6.8% |
| `suspicious_keywords` | 1.7% (1.5-1.9) | 1.0% (0.8-1.1) |
| `many_subdomains` | 0.39% (0.22-0.56) | 0 |
| `suspicious_tld` | 0.33% (0.15-0.54) | 0 |
| `unusual_port` | 0.28% (0.13-0.44) | 0 |
| `brand_in_subdomain` | 0.24% (0.11-0.40) | 0.45% (0.34-0.57); `vercel.app` 1.14% (0.77-1.52) |
| `international_host` | 0.07% (0.01-0.16) | 0 |

By shape (top domains, dev): every `http` page is at `low` (100.0% of 164 bare and 3,062 with a path), `https` bare hosts 9.2%, `https` with a path 24.3%. So the first benchmark's picture reverses on real links: `long_url` and `not_https`, which look like phishing in PhiUSIIL (3.2% and 54.3% of phishing) fire on one real page in five and one in ten.

**Decisions** (each candidate measured on the real dev sample and on the PhiUSIIL dev split; codes and job ids in [`linkfile-rules-round2.json`](../data/linkfile/linkfile-rules-round2.json); M6 and M5's first look used 100 resamples, the final rules' run and the others use 1,000; the final rules' report is [`link-dev-metrics-round2.json`](../data/linkfile/link-dev-metrics-round2.json)):

| Candidate | Real URLs `low`+ (all / top / platforms) | Phishing `low`+ / `medium`+ (matched subset `low`+) | Decision |
| --- | --- | --- | --- |
| Shipped round-1 rules | 52.5% / 31.6% / 100.0% | 86.4% (82.7-89.5) / 3.0% (2.4-3.8) (75.9%) | |
| M4: `hosting_platform_subdomain` shown as `info`, no weight | 26.5% / 31.6% / 14.7% | 76.6% / 2.8% (45.4%) | reject: same `low` result as M1, and it also drops the corroborated `medium` cases (2.8% against 3.0%) |
| M3: weight only when corroborated or the subdomain looks generated (two or more hyphens, or 20+ characters) | 31.9% / 31.6% / 32.7% | 79.7% / 3.0% (49.8%) | reject: 2.2 times the platform false alarms of M1 for 3 points of catch |
| M1: weight only when another weighted finding is present | 26.5% / 31.6% / 14.7% | 76.6% (71.1-82.2) / 3.0% (2.4-3.8) (45.4%) | keep |
| M1 plus `long_url` as `info` (M6) | 12.6% / 13.2% / 11.2% | 75.4% / 2.9% (45.4%), 100 resamples | reject: 1.8 points fewer top-domain false alarms than M5 (13.2% against 15.0%) but it drops the signal, with `medium` catch 2.9% against 3.0% (within noise); M5 keeps very long URLs as a weak true signal |
| **M1 plus `long_url` from 200 characters (M5), the final rules** | **13.9% / 15.0% / 11.3%** | **75.6% (70.0-81.3) / 3.0% (2.4-3.8) (45.4%)** | **keep** |

The platform candidates M1, M3 and M4 were designed from the signal definitions and run on the PhiUSIIL dev split before any real-URL number existed; M5 and M6 (`long_url`) were added after the shipped rules' real-URL rates were known. The rule applied was a judgement made at that point, not a pre-registered one: change a signal when it flags more than 5% of the real dev sample on its own, and keep the change when the `medium`-or-higher phishing catch does not fall and the `low`-or-higher catch falls by less than 12 points. `long_url` (19.9%) and the platform signal (100% of platform pages) were over the line; `not_https` (10.2%) is too, but it is the strongest real phishing signal (54% of PhiUSIIL phishing is `http`) and an unencrypted page is a true warning, so it stays and its false alarms are reported. Per-signal results of the final rules, `low`-or-higher false alarms on the real dev sample: all 13.9% (13.2-14.6), top domains 15.0% (14.0-16.0), user-content hosts 11.3% (10.8-12.0); `medium` or higher 0.18% (0.12-0.24). About two thirds of the final rules' top-domain `low` alarms (3,226 of 4,767) are `http` pages, which all raise `not_https`.

What changed in the rules: `hosting_platform_subdomain` still appears on every page of a listed host, but as `info` without weight unless another weighted finding is present (then `low`, weight 10 as before); `long_url` starts at 200 characters. Cost, measured on the PhiUSIIL dev split: phishing at `low` or higher **86.4% (82.7-89.5) to 75.6% (70.0-81.3)**, at `medium` or higher unchanged at 3.0%, benign host-root false alarms unchanged (0.2% and 1.6%). On the matched subset (https host roots on both sides) the `low` catch falls from 75.9% to 45.4%, which shows how much of round 1's matched-subset gain was the platform signal alone. The platform signal alone is therefore a measurable trade: it caught about ten points of phishing at the price of flagging every legitimate user page.

**Locked test of the real URLs, run once on 2026-10-23** ([`realurl-locked-realurl-v1.json`](../data/linkfile/realurl-locked-realurl-v1.json), claim [`realurl-LOCKED_EVAL.json`](../data/linkfile/realurl-LOCKED_EVAL.json); 19,637 URLs in 5,800 groups, never analyzed before; shipped rules `0ca93a7+main-rules`, final rules `0ca93a7+worktree-c47647f043dc`):

| Cohort | Shipped rules, `low`+ | Final rules, `low`+ | Shipped, `medium`+ | Final, `medium`+ |
| --- | --- | --- | --- | --- |
| All | 52.2% (50.7-53.6) | **13.5%** (12.4-14.6) | 0.24% (0.13-0.37) | 0.18% (0.10-0.27) |
| Top domains (13,636) | 31.1% (29.4-32.8) | 14.6% (13.1-16.2) | 0.19% (0.05-0.37) | 0.10% (0.03-0.20) |
| User-content hosts (6,001) | 100.0% | 11.0% (10.1-11.9) | 0.35% (0.18-0.53) | 0.35% (0.18-0.53) |

`long_url` on test: 19.7% (shipped) and 2.0% (200 characters) of top-domain URLs; `not_https` 9.5%; `digits_in_subdomain` 0.68% of top domains and 6.6% of platform pages. The test agrees with dev within its intervals, so the dev tuning did not overfit this sample. No `high` alarm on either side.

**Limits of the real-URL numbers.** The sample is one crawl of pages the crawler reached on popular domains and four platforms; mail links, short-lived campaign pages, tracking redirects and login pages are not in it. `wordpress.com`, `pages.dev` and the rest of the platform list are unmeasured. Majestic rank is a link-popularity ranking, so it can include domains that are not benign. What remains at `low` on top-domain pages is mostly `not_https`, a true property of the link. Phishing catch is measured on PhiUSIIL, whose benign side is host roots (see the leakage section), so the 10-point catch loss is measured against a data set whose platform signal was inflated by collection; the real cost to catch on live phishing is unknown.

## Limits and caveats

- Links: in the PhiUSIIL and Majestic data the benign URLs are `https` host roots only, so those false-alarm rates are floors; round 2 adds real URLs (Common Crawl) for false alarms, but they carry no phishing label, so catch is still measured on PhiUSIIL alone. TLD and URL shape are the only strata (no registration age in the data).
- The registered-domain grouping is an approximation. The group bootstrap interval is wide where a few groups are large.
- Files: Govdocs1 is US government web documents from about 2009 and holds few Office Open XML files (3 `.docx` in the sample), so the macro rule's false-alarm cost on modern documents is unmeasured. Recall is synthetic only.
- Rounds 1 and 2 were measured on the same dev splits they were derived from; the locked tests are the unbiased comparisons. Round 2's file rules have no locked test (the file test split was spent in round 1), so their numbers are development numbers.
- `/scratch` is purged on 2026-11-03; every download is reproducible from the manifest, and raw data never left the cluster.

## Reproducing

```bash
ssh explorer-xfer 'mkdir -p /scratch/$USER/kestrix/linkfilebench/logs && cd ~/kestrix-linkfile && nohup bash -l hpc/linkfile_acquire.sh > /scratch/$USER/kestrix/linkfilebench/logs/acquire.log 2>&1 &'
bash hpc/linkfile_sync.sh                  # laptop: code to ~/kestrix-linkfile (writes LINKFILEBENCH_SHA)
ssh explorer 'cd ~/kestrix-linkfile && bash hpc/linkfile_chain.sh full'   # build, dev features, dev metrics
```

The locked test, once the owner approves, is `ssh explorer 'cd ~/kestrix-linkfile-rounds/final && bash hpc/linkfile_locked.sh --name linkfile-v1'` (add `--dry-run` to print the submissions first).

## Locked test (2026-10-22)

Run once each (link: features 11301724/11301726, evaluation 11301728; file: features 11301731/11301733, evaluation
11301745) on the held-out test split, baseline and round-1 rules side by side. Reports:
[`link-locked-linkfile-v1.json`](../data/linkfile/link-locked-linkfile-v1.json) and
[`file-locked-linkfile-v1.json`](../data/linkfile/file-locked-linkfile-v1.json). 95% grouped-bootstrap intervals
(file intervals are message-level: the test has only 7 Govdocs threads).

**Files** (6,877 Govdocs1 files; 180 synthetic malicious-style and 120 synthetic benign-control files):

| Measure | Old rules | Round 1 |
| --- | --- | --- |
| Govdocs1 files with a security finding at `medium` or higher | 4.26% (3.81–4.77) | **0.28% (0.16–0.41)** |
| Govdocs1 files with any security finding (`low` or higher) | 7.68% (7.08–8.33) | **0.29% (0.17–0.42)** |
| Synthetic malicious-style files caught at `medium` or higher | 90 of 180 | **168 of 180** |
| Synthetic families fully caught | 9 of 18 | **16 of 18** |
| Synthetic benign controls flagged | 0 of 120 | 0 of 120 |

**Links** (28,531 phishing; 40,463 PhiUSIIL and 8,468 Majestic benign host roots):

| Measure | Old rules | Round 1 |
| --- | --- | --- |
| Phishing at `low` or higher | 58.4% (42.8–77.5) | **83.3% (74.7–90.3)** |
| Phishing at `medium` or higher | 1.8% (1.2–2.5) | 3.6% (2.3–5.5) |
| Benign false alarms at `low` or higher (PhiUSIIL / Majestic) | 0.10% / 1.36% | 0.12% / 1.39% |
| Benign false alarms at `medium` or higher | 0.0% | 0.0% |
| Matched subset (https host roots on both sides), phishing at `low` or higher | 7.5% (5.3–20.8) | 87.3% (32.7–95.5) |

What the locked test shows:

- **Files: the round-1 rules held up.** False alarms on real benign files fell about fifteenfold, and the
  synthetic catch nearly doubled. The synthetic cases show that the rules fire as intended, not how real malware
  fares; Govdocs1 was not screened for malware, so its false-alarm rates are upper bounds.
- **Links: more phishing reaches `low`, almost none reaches `medium`.** The gain comes from the two new subdomain
  signals, which the benign data cannot test (it has no user pages on free hosts), so their false-alarm cost on real
  browsing is still unmeasured; the matched-subset interval is very wide. A link verdict at `low` is a hint to look,
  not a phishing call.
- The locked splits are now spent.
