# Link and file checker accuracy benchmark

This page records how well the `kestrix.forensics` URL checker and file checker do on public data, where they fail, and what one round of rule changes bought. It is research tooling: the package is [`src/kestrixlinkfilebench/`](../../src/kestrixlinkfilebench/) (not in the published wheel; it follows the [email benchmark](mail-benchmark.md) and imports its shared helpers), the jobs are `hpc/linkfile_*`, and the aggregate outputs are in [`docs/data/linkfile/`](../data/linkfile/README.md).

**Status (2026-10-22).** Every number below is a **development-split** number. The locked test split has not been analyzed or opened. The module page [`forensics.md`](../modules/forensics.md) still says the checks are not verdicts; nothing here changes that.

## What the dev numbers say

- **The link results mostly measure how the data was collected.** In PhiUSIIL every legitimate URL is an `https` host root (no path, no query). Phishing URLs are 54% `http`, 24% have a path. The baseline "catches" 63.7% of phishing at `low` or higher, but 54% of all phishing is flagged by `not_https` alone, and on a matched subset (https, bare host, same length band) the baseline catch is **9.0%** (6.4-14.6) at `low` or higher and **0.3%** at `medium` or higher.
- **Almost nothing reaches `medium`.** At `medium` or higher the baseline flags 2.0% of phishing (1.6-2.5) and no benign URL; `high` is reached by 4 URLs in 66,593. The score weights are too small for the signals that fire on real phishing hosts.
- **Link false alarms are measured only on host roots.** Benign false alarms are 0.1% (PhiUSIIL roots) and 1.6% (Majestic roots, 83% of them `suspicious_tld`) at `low` or higher, and zero at `medium`. There are no benign URLs with paths, queries or `http` in the data, so `long_url`, `suspicious_keywords`, `not_https` and every path signal have no measurable false-alarm rate here. These rates are a floor, not an estimate for real browsing.
- **File false alarms on real documents are dominated by two format blind spots.** On Govdocs1 (12,816 presumed-benign files) the baseline raises a security finding at `medium` or higher on **5.0%** (3.8-6.6): 74% of those are `high_entropy_file` on legacy PowerPoint (`.ppt`, 473 of 722), then Flash (`.swf`, 65) and legacy Word (`.doc`, 48). Legacy Office (OLE2) and Flash store compressed data, which the checker did not know.
- **File recall is measured only on synthetic cases.** The baseline catches 180 of 360 dev cases at `medium` or higher (9 of 18 families fully). It misses macro Office files, encrypted ZIPs, programs appended to PDFs or images, SVG scripts and script attachments, because it has no rule for them.
- **Round 1 (details below) cut file false alarms from 5.0% to 0.2% at `medium` or higher and raised synthetic catch from 180 to 336 of 360, with no benign-control alarm. For links it raised `low`-or-higher catch from 63.7% to 86.4% and `medium`-or-higher from 2.0% to 3.0%, with false alarms unchanged (0.2% and 1.7% at `low`). Most of the link gain comes from two signals whose benign side the data cannot test (see the caveat in round 1).**

## Datasets

| Dataset | Used for | Items after dedupe | Size (downloaded) | License | URL |
| --- | --- | --- | --- | --- | --- |
| PhiUSIIL Phishing URL dataset (UCI 967) | phishing and benign URLs (label 1 = legitimate, 0 = phishing, inverted here) | 95,124 phishing, 134,807 benign (of 100,945 and 134,850) | 15,376,007 B zip, sha256 `0a639fd0...c9a59a` | CC BY 4.0 | <https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset> |
| Majestic Million | 30,000 seeded domains turned into host-root URLs (`https://domain/`, half with `www.`): 28,270 kept | 28,270 benign | 78,945,327 B csv, sha256 `78b104b1...2a8a3c` | CC BY 3.0 | <https://majestic.com/reports/majestic-million> |
| Govdocs1 (Digital Corpora), 20 seeded zip threads of 1,000 (`144 152 217 240 264 327 366 444 470 489 536 553 569 653 656 683 763 822 827 880`) | false alarms on real files of many formats | 19,693 files (of 19,734 read; 31 content duplicates, 10 over 50 MiB dropped) | 8,129,431,646 B in 20 zips | "freely redistributable" (no formal license) | <https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/> |
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

## Limits and caveats

- Links: benign URLs are `https` host roots only; false-alarm rates are floors; brand, path and keyword signals cannot be validated against real legitimate links. TLD and URL shape are the only strata (no registration age in the data).
- The registered-domain grouping is an approximation. The group bootstrap interval is wide where a few groups are large.
- Files: Govdocs1 is US government web documents from about 2009 and holds few Office Open XML files (3 `.docx` in the sample), so the macro rule's false-alarm cost on modern documents is unmeasured. Recall is synthetic only.
- Both rule rounds were measured on the same dev split they were derived from; the locked test is the unbiased comparison.
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
