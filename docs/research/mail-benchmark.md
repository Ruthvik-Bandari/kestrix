# Email accuracy benchmark

This page records how well `kestrix.mail` detects phishing and spam on public corpora, why it misses or over-flags, and what signal weights a simple explainable model learns from the same data. It is research tooling: the package is [`src/kestrixmailbench/`](../../src/kestrixmailbench/) (not in the published wheel), the jobs are `research/hpc/mail/mail_*`, and the aggregate outputs are in [`docs/data/mail/`](../data/mail/README.md).

**Status (2026-10-24, modern-mail section added at the end).** Everything below is **development-split** numbers. Sections up to "Learned weights" describe the rules as shipped when the benchmark ran; [Round 1](#round-1-rule-changes-measured-on-dev) records the rule changes made from that analysis and their before and after numbers. The locked test split has not been opened. No learned weights are wired into `kestrix.mail`; `docs/modules/mail.md` still says Kestrix has not measured detection or false-alarm rates, and that stays true until the locked test has run and the owner decides.

## What the dev numbers say

- **Phishing catch is about half, and spam catch about a third.** With every `auth` finding removed, the shipped rules flag 52.9% of Nazario phishing (95% CI 45.5-58.8) and 31.3% of SpamAssassin spam. Only 13.1% of phishing reaches `malicious`.
- **False alarms are concentrated, not spread.** Pooled over all ham the false-alarm rate is 3.7%, but that number is 83% Enron mail. SpamAssassin ham, which carries real mailing-list headers, is flagged 19.8% of the time; 86% of those flags are `mail.sender.reply_to_mismatch` (a list sets Reply-To to the list). The two SpamAssassin `hard_ham` sets reach `malicious` 17.4% and 22.6% of the time.
- **Authentication findings do not drive these numbers.** Almost no message in these corpora carries a trusted `Authentication-Results` header (none of the ham, none of the spam, 73% of 2015-2025 phishing), so `mail.auth.missing` fires everywhere and nothing else from `auth` fires on old mail. Results with and without `auth` findings differ by under one point.
- **Era and corpus provenance do leak.** Nine finding ids differ strongly between era cells or between the two ham corpora; the learned weights on the plain content set lean on them. The Nazario README says the early mailboxes were anonymized (destination IPs and domain names), which fits `links.sender_domain_mismatch` firing on 40.0% of phishing up to 2007 and on almost nothing after. Enron has no `Received`, `Return-Path` or `Reply-To` headers at all, which makes it easy ham for any header-based signal.
- **Learned weights match the shipped rule's flagged catch at equal or lower false alarms and raise `malicious` phishing catch (13.1% to 20.6% on `content`, 8.8% to 17.1% on `content_noera`), but they lose spam catch.** The dev comparison is optimistic because the thresholds are chosen on the same scores; the locked test is the unbiased comparison.

## Datasets

All four sources are treated as separate cohorts. The synthetic source is reported on its own and never pooled or learned from.

| Source | Messages after dedupe | Label | Years (Date header) | License |
| --- | --- | --- | --- | --- |
| Nazario phishing corpus (raw mbox files) | 9,089 | phishing | 2003-2025 (75 undated) | CC BY 4.0 (attribution required) |
| SpamAssassin public corpus | 4,293 | ham | 2002 (1 undated) | No license stated; research use by owner decision |
| SpamAssassin public corpus | 1,784 | spam | 2000-2002 (66 undated) | No license stated; research use by owner decision |
| Enron email, May 2015 release (20,000-message seeded sample) | 20,000 | ham | 1999-2002 (16 undated) | No license stated; research use by owner decision; PII, stays on cluster |
| Synthetic messages (reported separately) | 120 | ham | 2026 | Generated here (Apache-2.0) |
| Synthetic messages (reported separately) | 210 | phishing | 2026 | Generated here (Apache-2.0) |
| Synthetic messages (reported separately) | 55 | spam | 2026 | Generated here (Apache-2.0) |

Years come from the `Date` header where it parses to 1990-2026; for spam and phishing the header can be forged, so the year is the sender's claim. The year range in the table leaves out stray years that hold under 0.2% of a cohort (see `reports/build.json` for the full histogram). SpamAssassin ham is 2002 only; its spam is almost all 2001-2002, including `20050311_spam_2`, the later addition.

**Attribution.** Phishing messages come from Jose Nazario's phishing corpus, <https://www.monkey.org/~jose/phishing/>, released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Nazario notes that it is hand-classified from one personal inbox, may contain errors, and is not exhaustive.

**SpamAssassin and Enron.** Neither has a stated license. The SpamAssassin readme says copyright for the message text stays with the original senders; the Enron data are real employees' mail with personal information. They are used for research evaluation and for learning the benchmark's weights by the owner's decision. Raw messages never leave `/scratch/$USER/kestrix/mailbench/` on the cluster, and nothing in the reports, logs or committed files contains a message body, address or subject. See [`dataset-licenses.md`](dataset-licenses.md).

TREC 2007 is not available yet. It can be added as another `Source` in `src/kestrixmailbench/sources.py`.

### What was dropped

| Source | Read | Dropped by reason |
| --- | --- | --- |
| enron | 30,000 | duplicate near 2,576, input too large 22, over sample cap 7,402 |
| nazario | 12,007 | duplicate exact 6, duplicate near 2,908, input too large 3, invalid input 1 |
| spamassassin | 9,348 | duplicate exact 184, duplicate near 3,080, input too large 6, invalid input 1 |
| synthetic | 390 | duplicate near 5 |

"Near duplicate" means the same lower-cased subject and body after masking digits and URLs; the first message in a fixed order is kept. Campaign mail is repetitive, so Nazario loses 24% and SpamAssassin 35% of what it read. `invalid input` is a message without any of the usual headers (the analyzer rejects it too). `over sample cap` is the Enron over-sample beyond the first 20,000 unique messages by seeded rank.

## Method

1. **Acquire** (`research/hpc/mail/mail_acquire.sh`, transfer node). Downloads are recorded with URL, size, SHA-256 and time in `manifests/mailbench-manifest.json`; a file that no longer matches its manifest entry is rejected. [`docs/data/mail/mailbench-manifest.json`](../data/mail/mailbench-manifest.json) is the committed copy.
2. **Build** (Slurm, CPU). Messages are split out of mbox files and tar archives without extracting to disk, and anything `kestrix.mail` would reject is dropped with a reason. Enron is sampled by seeded hash (seed `kestrixmail-v1`) from every file of the May 2015 release, over-sampled 1.5 times, deduplicated, and cut to the first 20,000 by rank.
3. **Split before any tuning.** The unit is a *group*: a source file (or Enron mailbox) plus the `Date` year, except one-year files, which are one group whole. Groups are assigned to dev or test within each (source, label) stratum by seeded hash until about 30% of the stratum is in test, so a campaign, a mailbox-year or a corpus file never straddles the split. The split manifest ([`split-manifest.json`](../data/mail/split-manifest.json)) holds counts and ID hashes only.

| Split | Source/label | Messages |
   | --- | --- | --- |
   | dev | enron/ham | 13,986 |
   | dev | nazario/phishing | 6,070 |
   | dev | spamassassin/ham | 2,757 |
   | dev | spamassassin/spam | 1,546 |
   | dev | synthetic/ham | 90 |
   | dev | synthetic/phishing | 150 |
   | dev | synthetic/spam | 55 |
   | test | enron/ham | 6,014 |
   | test | nazario/phishing | 3,019 |
   | test | spamassassin/ham | 1,536 |
   | test | spamassassin/spam | 238 |
   | test | synthetic/ham | 30 |
   | test | synthetic/phishing | 60 |
   
   Groups: dev 298, test 138.

   SpamAssassin spam has only a few large groups, so its test share is 13%: 238 test messages. Test intervals for spam will be wide.
4. **Features** (Slurm array, 16 tasks). `kestrix.mail.analyze` runs on every message offline; per message only the label, source, year, verdict, heuristic score, finding ids with severities, counts and two header probes (`Received` count, `Authentication-Results` count) are kept. No analyzer error occurred on any message.
5. **Baseline metrics on dev.** *Catch rate* is recall of flagged (verdict `suspicious` or `malicious`) over phishing or spam; *false-alarm rate* is the flagged share of ham; *precision* is flagged positives over all flagged messages at the corpora's own class mix, so it is not a real-world precision. Verdicts for restricted feature sets are re-derived from the stored findings with the shipped verdict rules and weights; with all findings the re-derivation matches the analyzer's own verdict (tested).
6. **Intervals.** `(a-b)` is a 95% percentile bootstrap that resamples whole groups, 1,000 resamples (same percentile bootstrap as `kestrixvul`, run per group on count vectors for speed). Where a cohort has fewer than 8 groups a group bootstrap says nothing (one group has no spread), so the cell shows `(msg a-b)` instead: a message-level binomial interval, which treats messages as independent and understates the uncertainty when they are not.
7. **Learning** (dev only). Non-negative L2 logistic regression over finding-id indicators plus the documented product `links.random_host x links.plain_http` (never seen together often enough to get weight). Ids seen in fewer than 5 dev messages get no weight and are listed. Class-balanced weights, with every source/label cell sharing equally inside its class, so 14,000 easy Enron messages cannot outvote 2,800 SpamAssassin ham. The L2 strength is picked by 5-fold cross-validated log-loss with folds made of whole groups. Thresholds for `suspicious` and `malicious` are the lowest scores whose false-alarm rate on ham is at most 5% and 1%, either on **each ham source** (default) or on pooled ham (`_pooled` files). Fitted by accelerated projected gradient in numpy (deterministic; no new runtime dependency, `numpy` is in the `research` extra).
8. **Locked test.** `research/hpc/mail/mail_locked.sbatch` claims `reports/LOCKED_EVAL.json` with an exclusive create, evaluates every baseline and the chosen weights once, and refuses a second run. Test features are written to separate files that no dev stage opens. Not run.

## Dev results: the shipped rules

Three feature sets, same messages: *all findings*; *content only* (every `auth` finding removed, the verdict re-derived); and *content only without header-era ids* (also removing `sender.outdated_mailer` and `sender.return_path_mismatch`, which read headers that track the mail era). Dev has 24,359 messages (SpamAssassin 2,757 ham and 1,546 spam; Enron 13,986; Nazario 6,070; synthetic excluded) in 288 groups.

| Measure on dev | All findings | Content only (no auth) | Content only, no header-era ids |
| --- | --- | --- | --- |
| Phishing catch (suspicious or malicious) | 53.8% (47.0-59.3) | 52.9% (45.5-58.8) | 52.9% (45.5-58.8) |
| Phishing catch (malicious only) | 13.2% (10.1-17.4) | 13.1% (10.0-17.2) | 13.1% (10.0-17.2) |
| Spam catch (suspicious or malicious) | 31.3% (msg 29.1-33.7) | 31.3% (msg 29.1-33.7) | 31.3% (msg 29.1-33.7) |
| Spam catch (malicious only) | 3.8% (msg 2.8-4.7) | 3.8% (msg 2.8-4.7) | 3.8% (msg 2.8-4.7) |
| SpamAssassin ham false alarms (suspicious or malicious) | 19.8% (msg 18.4-21.4) | 19.8% (msg 18.4-21.4) | 19.8% (msg 18.4-21.4) |
| SpamAssassin ham false alarms (malicious only) | 2.5% (msg 1.9-3.1) | 2.5% (msg 1.9-3.1) | 2.5% (msg 1.9-3.1) |
| Enron ham false alarms (suspicious or malicious) | 0.5% (0.3-0.8) | 0.5% (0.3-0.8) | 0.5% (0.3-0.8) |
| Enron ham false alarms (malicious only) | 0.1% (0.0-0.1) | 0.1% (0.0-0.1) | 0.1% (0.0-0.1) |
| All ham false alarms (suspicious or malicious) | 3.7% (0.5-7.6) | 3.7% (0.5-7.6) | 3.7% (0.5-7.6) |
| All ham false alarms (malicious only) | 0.5% (0.0-1.1) | 0.5% (0.0-1.1) | 0.5% (0.0-1.1) |
| Precision, phishing vs ham (flagged) | 84.1% (60.6-98.0) | 83.9% (59.7-98.0) | 83.9% (59.7-98.0) |
| Precision, spam vs ham (flagged) | 43.9% (0.0-90.5) | 43.9% (0.0-90.5) | 43.9% (0.0-90.5) |

The three columns match to within a point because the finding ids that separate them rarely decide a verdict (see [leakage](#leakage-and-era-controls)).

### Same-era comparisons

Ham is 1999-2002; phishing runs to 2025. These rows compare like with like.

| Comparison | Findings | Positives / ham | Catch (flagged) | Catch (malicious) | False alarms (flagged) | False alarms (malicious) |
| --- | --- | --- | --- | --- | --- | --- |
| ham 2002 2005 vs positives 2005 2007 | all | 2,445 / 3,753 | 64.4% (msg 62.5-66.3) | 10.7% (msg 9.5-12.0) | 14.7% (0.6-17.4) | 1.8% (0.0-8.7) |
| ham 2002 2005 vs positives 2005 2007 | content | 2,445 / 3,753 | 64.4% (msg 62.5-66.3) | 10.7% (msg 9.5-12.0) | 14.7% (0.6-17.4) | 1.8% (0.0-8.7) |
| same corpus spamassassin 2002 2005 | all | 1,546 / 2,756 | 31.3% (msg 29.1-33.7) | 3.8% (msg 2.8-4.7) | 19.8% (msg 18.4-21.4) | 2.5% (msg 1.9-3.1) |
| same corpus spamassassin 2002 2005 | content | 1,546 / 2,756 | 31.3% (msg 29.1-33.7) | 3.8% (msg 2.8-4.7) | 19.8% (msg 18.4-21.4) | 2.5% (msg 1.9-3.1) |

SpamAssassin ham and spam are both 2002 in this data, so the second row is a clean same-corpus, same-era comparison, and it is the sharpest summary of the module on spam: 31% caught at 20% false alarms. The first row compares 2002 ham (SpamAssassin and Enron) with 2005-2007 phishing.

### By subset

| Source/subset/label | Messages | Flagged | Malicious |
| --- | --- | --- | --- |
| enron/maildir/ham | 13,986 | 0.5% (0.3-0.8) | 0.1% (0.0-0.1) |
| nazario/phishing-2015/phishing | 272 | 40.8% (msg 34.9-46.3) | 12.5% (msg 8.8-16.9) |
| nazario/phishing-2017/phishing | 276 | 35.5% (msg 29.7-40.9) | 7.2% (msg 4.3-10.5) |
| nazario/phishing-2020/phishing | 147 | 54.4% (msg 46.3-62.6) | 31.3% (msg 23.1-38.8) |
| nazario/phishing-2023/phishing | 366 | 41.3% (msg 36.3-46.2) | 27.9% (msg 23.2-32.5) |
| nazario/phishing-2025/phishing | 437 | 32.3% (msg 28.1-36.6) | 23.6% (msg 19.7-27.5) |
| nazario/phishing0.mbox/phishing | 261 | 69.3% (msg 64.0-75.1) | 10.7% (msg 6.9-14.6) |
| nazario/phishing1.mbox/phishing | 33 | 69.7% (msg 54.5-84.8) | 12.1% (msg 3.0-24.2) |
| nazario/phishing2.mbox/phishing | 808 | 59.8% (msg 56.2-63.0) | 11.5% (msg 9.4-13.7) |
| nazario/phishing3.mbox/phishing | 1,033 | 68.0% (msg 64.9-70.7) | 8.4% (msg 6.8-10.2) |
| nazario/private-phishing4.mbox/phishing | 2,437 | 50.8% (45.2-55.8) | 11.3% (7.8-15.5) |
| spamassassin/20021010_easy_ham/ham | 2,400 | 18.7% (msg 17.2-20.4) | 0.0% (msg 0.0-0.0) |
| spamassassin/20021010_hard_ham/ham | 224 | 26.8% (msg 21.0-32.1) | 17.4% (msg 12.5-22.8) |
| spamassassin/20021010_spam/spam | 445 | 19.8% (msg 16.2-23.6) | 2.7% (msg 1.3-4.3) |
| spamassassin/20030228_hard_ham/ham | 133 | 27.8% (msg 19.5-35.3) | 22.6% (msg 15.8-30.1) |
| spamassassin/20050311_spam_2/spam | 1,101 | 36.0% (msg 33.2-39.0) | 4.2% (msg 2.9-5.4) |

`20021010_easy_ham` shows the mailing-list effect (18.7% flagged, 0.0% malicious). The `hard_ham` sets show a second problem: high-severity findings on legitimate HTML mail (17-23% malicious).

### By year (content only)

| Cohort | Year | Messages | Flagged | Malicious |
| --- | --- | --- | --- | --- |
| phishing | 2004 | 50 | 68.0% (msg 54.0-80.0) | 6.0% (msg 0.0-14.0) |
| phishing | 2005 | 241 | 70.5% (msg 64.7-76.3) | 12.0% (msg 7.9-16.2) |
| phishing | 2006 | 804 | 59.6% (msg 56.1-62.8) | 11.4% (msg 9.3-13.7) |
| phishing | 2007 | 1,400 | 66.1% (msg 63.6-68.5) | 10.0% (msg 8.4-11.6) |
| phishing | 2008 | 361 | 57.9% (msg 52.9-62.9) | 15.2% (msg 11.6-19.1) |
| phishing | 2009 | 290 | 53.8% (msg 48.3-59.3) | 22.1% (msg 17.2-27.2) |
| phishing | 2010 | 550 | 49.1% (msg 45.1-53.5) | 8.4% (msg 6.0-10.7) |
| phishing | 2011 | 408 | 48.5% (msg 43.9-53.4) | 5.6% (msg 3.4-8.1) |
| phishing | 2013 | 261 | 35.2% (msg 29.5-41.0) | 7.3% (msg 4.2-10.7) |
| phishing | 2014 | 189 | 44.4% (msg 37.6-51.3) | 8.5% (msg 4.8-12.7) |
| phishing | 2015 | 270 | 40.7% (msg 34.8-46.7) | 12.6% (msg 8.9-17.0) |
| phishing | 2017 | 273 | 35.2% (msg 29.7-40.7) | 7.3% (msg 4.4-10.6) |
| phishing | 2020 | 147 | 54.4% (msg 46.3-62.6) | 31.3% (msg 23.1-38.8) |
| phishing | 2023 | 315 | 45.7% (msg 40.3-51.1) | 32.4% (msg 27.3-37.5) |
| phishing | 2025 | 433 | 32.3% (msg 27.9-36.7) | 23.6% (msg 19.6-27.5) |
| phishing | unknown | 55 | 16.4% (msg 7.3-27.3) | 1.8% (msg 0.0-5.5) |
| spam | 2002 | 1,546 | 31.3% (msg 29.1-33.7) | 3.8% (msg 2.8-4.7) |
| ham | 1999 | 351 | 0.3% (0.0-1.2) | 0.0% (0.0-0.0) |
| ham | 2000 | 5,456 | 0.2% (0.1-0.4) | 0.0% (0.0-0.0) |
| ham | 2001 | 7,149 | 0.7% (0.4-1.2) | 0.1% (0.0-0.2) |
| ham | 2002 | 3,750 | 14.7% (0.5-17.4) | 1.8% (0.0-8.6) |

Phishing catch falls from 60-70% in 2005-2007 to 32-54% in 2013-2025 (single years vary with how many campaigns the author kept). The malicious share is 23-32% in 2020, 2023 and 2025: `attachments.dangerous_type` appears in 5.7% of phishing from 2015 on and almost never before.

### Why: misses and false alarms (content only)

| Group | Size | Finding ids among them (share of the group) |
| --- | --- | --- |
| missed phishing | 2,861 of 6,070 (47%); 427 with no finding at all | `links.plain_http` 69%, `sender.outdated_mailer` 25%, `intent.urgency` 20%, `sender.return_path_mismatch` 16%, `links.insecure_login` 10%, `links.redirect_param` 5% |
| missed spam | 1,062 of 1,546 (69%); 111 with no finding at all | `links.plain_http` 79%, `sender.return_path_mismatch` 22%, `sender.outdated_mailer` 19%, `intent.urgency` 12%, `links.redirect_param` 1%, `links.random_host` 1% |
| false alarms, enron ham | 72 of 13,986 (0.5%) | `links.ip_host` 71%, `intent.prize_claim` 14%, `intent.payment_change` 8%, `links.userinfo` 8%, `intent.credential_request` 1%, `intent.bec_pattern` 1% |
| false alarms, spamassassin ham | 546 of 2,757 (19.8%) | `sender.reply_to_mismatch` 86%, `sender.display_name_spoof` 9%, `links.text_href_mismatch` 3%, `links.ip_host` 1%, `links.script_scheme` 0%, `intent.prize_claim` 0% |

Misses are mostly mail with only *low* findings. `links.plain_http` is present in 69% of missed phishing and 79% of missed spam but is low severity and cannot flag a message alone; 427 phishing messages (7%) had no finding at all. The module has no signal for generic bulk spam wording: the only intent findings on this spam are `intent.urgency` (12.7%) and `intent.prize_claim` (1.2%).

False alarms come from two ids. `sender.reply_to_mismatch` (medium) is the whole story for mailing-list mail; `links.ip_host` (medium) is 71% of the few Enron false alarms.

### Synthetic source (dev)

These are templates written to exercise the analyzers, so the result is a regression check, not accuracy. All ham families are clean and every positive family is flagged; the two spam families are `suspicious`, never `malicious`, as documented.

| Family | Label | Messages (dev) | Flagged | Malicious |
| --- | --- | --- | --- | --- |
| ham_business | ham | 30 | 0 | 0 |
| ham_invite | ham | 30 | 0 | 0 |
| ham_newsletter | ham | 30 | 0 | 0 |
| phish_bec_payment_change | phishing | 30 | 30 | 30 |
| phish_display_spoof | phishing | 30 | 30 | 30 |
| phish_double_extension | phishing | 30 | 30 | 30 |
| phish_href_mismatch | phishing | 30 | 30 | 30 |
| phish_userinfo_link | phishing | 30 | 30 | 30 |
| spam_casino_ru | spam | 30 | 30 | 0 |
| spam_prize_en | spam | 25 | 25 | 0 |

## Leakage and era controls

Ham is 1999-2002 and phishing runs to 2025, so a signal that follows the era can separate the classes without detecting anything. Three controls:

**(a)-(c) Three views of the baseline.** All findings, content only, and same-era strata (tables above). The first two agree, so the baseline does not rely on authentication findings. The strata put the flagged rates in context: 2005-2007 phishing is flagged at 64.4% against 14.7% false alarms on 2002 ham, and within SpamAssassin the module catches 31% of spam at 19.8% false alarms.

**Finding frequencies by era cell.** An id is flagged when two same-class cells differ by at least 10 points and a factor of 3 (Enron against SpamAssassin ham; phishing up to 2007 against phishing from 2015). Authentication ids are shown for contrast. The differences between Enron and SpamAssassin ham mix era with provenance: Enron lacks the headers entirely.

| Finding id | Era-sensitive | Enron ham | SpamAssassin ham | SpamAssassin spam | Phishing 2007 and earlier | Phishing 2015 and later |
| --- | --- | --- | --- | --- | --- | --- |
| `auth.dkim_fail` | no | 0.0% | 0.0% | 0.0% | 0.0% | 1.4% |
| `auth.dkim_not_aligned` | no | 0.0% | 0.0% | 0.0% | 0.0% | 6.7% |
| `auth.dmarc_fail` | no | 0.0% | 0.0% | 0.0% | 0.0% | 1.7% |
| `auth.missing` | yes | 100.0% | 100.0% | 100.0% | 100.0% | 27.2% |
| `auth.no_dmarc_with_failure` | no | 0.0% | 0.0% | 0.0% | 0.0% | 1.9% |
| `auth.spf_fail` | no | 0.0% | 0.0% | 0.0% | 0.0% | 2.4% |
| `auth.spf_softfail` | no | 0.0% | 0.0% | 0.0% | 0.0% | 7.0% |
| `links.insecure_login` | yes | 0.2% | 5.8% | 0.3% | 21.9% | 1.3% |
| `links.ip_host` | yes | 0.4% | 0.2% | 16.0% | 24.5% | 0.0% |
| `links.plain_http` | yes | 12.5% | 74.1% | 82.3% | 94.2% | 33.7% |
| `links.sender_domain_mismatch` | yes | 0.0% | 0.0% | 0.1% | 40.0% | 0.5% |
| `sender.display_name_spoof` | yes | 0.0% | 1.8% | 0.8% | 1.1% | 15.4% |
| `sender.outdated_mailer` | yes | 0.0% | 5.1% | 18.3% | 41.5% | 2.7% |
| `sender.reply_to_mismatch` | yes | 0.0% | 17.1% | 12.4% | 2.8% | 7.3% |
| `sender.return_path_mismatch` | yes | 0.0% | 55.3% | 19.9% | 15.6% | 17.1% |

Nine ids are flagged: `auth.missing`, `links.insecure_login`, `links.ip_host`, `links.plain_http`, `links.sender_domain_mismatch`, `sender.display_name_spoof`, `sender.outdated_mailer`, `sender.reply_to_mismatch` and `sender.return_path_mismatch`. All but `auth.missing` are in the content set, so a model trained on it can still learn the era. That is why the default learner is also run on a third set, `content_noera`, that drops them (below).

**Header probes.** Single era probes as separators of positives from ham, as AUC (0.5 means no information):

| Pool | Positives / ham | Auth header present | Received count | MIME parts | Link count |
| --- | --- | --- | --- | --- | --- |
| all dev | 7,616 / 16,743 | 0.5758 | 0.8971 | 0.7044 | 0.8245 |
| ham 2002 2005 vs positives 2005 2007 | 2,445 / 3,753 | 0.5 | 0.5284 | 0.7139 | 0.6094 |
| same corpus spamassassin 2002 2005 | 1,546 / 2,756 | 0.5 | 0.408 | 0.5583 | 0.6037 |

Across all dev the `Received` count alone separates the classes (0.90) because Enron has none; inside the same-era strata it falls to 0.41-0.53 and the authentication probe to exactly 0.50. Mean values by cell:

| Cell | Messages | Has Authentication-Results | Mean Received headers | Has links | Mean MIME parts |
| --- | --- | --- | --- | --- | --- |
| ham_enron | 13,986 | 0.0% | 0.0 | 12.6% | 1.0 |
| ham_spamassassin | 2,757 | 0.0% | 5.223 | 81.9% | 1.114 |
| phishing_early | 2,513 | 0.0% | 3.988 | 96.6% | 1.709 |
| phishing_late | 1,443 | 72.8% | 2.794 | 90.2% | 2.464 |
| spam_spamassassin | 1,546 | 0.0% | 4.521 | 88.1% | 1.318 |

## Learned weights

The default feature set is `content` (no `auth` findings). Because that set still contains era-sensitive ids, the job also learns `content_strict`, `content_noera`, and, for contrast, `all`. Weights are on a logit scale: a message's score is `intercept + sum of the weights of the findings present`. They are not probabilities, and they are not wired into anything.

| Finding id | all | content | content_strict | content_noera |
| --- | --- | --- | --- | --- |
| `attachments.dangerous_type` | 5.79 | 1.85 | 6.14 | 5.33 |
| `links.sender_domain_mismatch` | 6.05 | 2.28 | 6.12 | - |
| `intent.credential_request` | 5.50 | 1.98 | 5.56 | 5.80 |
| `auth.spf_softfail` | 5.15 | - | - | - |
| `auth.dkim_not_aligned` | 4.90 | - | - | - |
| `attachments.archive_dangerous_member` | 4.31 | 0.59 | 4.33 | 3.66 |
| `auth.dkim_fail` | 3.94 | - | - | - |
| `intent.hidden_text` | 3.86 | 0.47 | 3.75 | 3.23 |
| `links.userinfo` | 3.11 | 0.82 | 3.40 | 3.71 |
| `links.ip_host` | 3.46 | 2.37 | 3.49 | - |
| `auth.spf_fail` | 3.37 | - | - | - |
| `sender.random_domain` | 3.01 | 0.33 | 2.79 | 2.43 |
| `intent.payment_change` | 2.92 | 0.50 | 2.90 | 2.69 |
| `links.sender_domain_redirect` | 2.31 | 0.21 | 2.75 | 2.92 |
| `intent.secrecy` | 1.93 | 0.21 | 2.50 | 2.86 |
| `auth.dmarc_fail` | 2.73 | - | - | - |
| `links.text_href_mismatch` | 1.84 | 1.19 | 2.06 | 2.42 |
| `sender.outdated_mailer` | 2.22 | 2.00 | - | - |
| `links.punycode_host` | 2.00 | 0.12 | 2.01 | 2.21 |
| `intent.prize_claim` | 2.11 | 0.60 | 2.12 | 2.02 |

Among the top weights on `all` are authentication findings (`spf_softfail` 5.15, `dkim_not_aligned` 4.90, `dkim_fail` 3.94) that exist only in 2015-2025 phishing, because the old ham has no authentication headers: that is the leakage the control exists to prevent, and it is why `all` is not the default. The `random_host x plain_http` product gets weight 0 in every set where it can be fitted. On `content` the largest weights go to `links.ip_host`, `links.sender_domain_mismatch` and `sender.outdated_mailer`: era- and anonymization-sensitive. On `content_noera` the ranking is credential requests, dangerous attachment types, userinfo links, hidden text and payment-change wording: content that does not depend on the era.

Ids with no weight: `attachments.macro_office`, `intent.gambling_offer` and `lookalike.mixed_script` were seen in fewer than 5 dev messages; other ids (for example `intent.gift_cards` and the `lookalike.*` checks that need protected domains) never fired on these corpora. They keep no learned weight and need the synthetic source or a corpus that contains them.

### Cross-validated performance against the baseline (dev)

Learned scoring against the shipped rule on the same feature set, from 5-fold grouped cross-validation. The learned thresholds are chosen on the same out-of-fold scores, so these numbers are optimistic for the learned scorer.

Learned catch rate at a threshold whose false-alarm rate is no higher than the baseline's on each ham source (`content`, default basis):

| Level | Measure | Baseline | Learned at false alarms no higher than baseline's, per ham source |
| --- | --- | --- | --- |
| flagged | Phishing catch | 52.9% (45.5-58.8) | 52.8% (35.9-65.2) |
| flagged | Spam catch | 31.3% (msg 29.1-33.7) | 28.8% (msg 26.6-31.2) |
| flagged | All positives catch | 48.5% (40.3-56.1) | 47.9% (34.0-60.9) |
| flagged | SA ham FA | 19.8% (msg 18.4-21.4) | 16.2% (msg 14.9-17.7) |
| flagged | Enron ham FA | 0.5% (0.3-0.8) | 0.4% (0.2-0.7) |
| malicious | Phishing catch | 13.1% (10.0-17.2) | 20.6% (11.6-27.7) |
| malicious | Spam catch | 3.8% (msg 2.8-4.7) | 2.8% (msg 1.9-3.6) |
| malicious | All positives catch | 11.2% (8.0-15.6) | 17.0% (8.8-24.8) |
| malicious | SA ham FA | 2.5% (msg 1.9-3.1) | 1.0% (msg 0.6-1.4) |
| malicious | Enron ham FA | 0.1% (0.0-0.1) | 0.1% (0.0-0.2) |

| Same-era comparison | Baseline catch | Learned catch | Baseline FA | Learned FA |
| --- | --- | --- | --- | --- |
| ham 2002 2005 vs positives 2005 2007 | 64.4% (msg 62.5-66.3) | 53.1% (msg 51.1-55.0) | 14.7% (0.6-17.4) | 2.7% (0.1-3.4) |
| same corpus spamassassin 2002 2005 | 31.3% (msg 29.1-33.7) | 10.0% (msg 8.5-11.5) | 19.8% (msg 18.4-21.4) | 3.6% (msg 2.9-4.3) |

Same comparison for `content_noera`:

| Level | Measure | Baseline | Learned at false alarms no higher than baseline's, per ham source |
| --- | --- | --- | --- |
| flagged | Phishing catch | 23.4% (20.6-27.1) | 23.6% (21.4-26.5) |
| flagged | Spam catch | 4.5% (msg 3.4-5.6) | 3.2% (msg 2.3-4.1) |
| flagged | All positives catch | 19.6% (14.3-25.1) | 19.5% (14.2-24.7) |
| flagged | SA ham FA | 0.8% (msg 0.5-1.2) | 0.7% (msg 0.4-1.0) |
| flagged | Enron ham FA | 0.2% (0.1-0.2) | 0.2% (0.1-0.2) |
| malicious | Phishing catch | 8.8% (6.8-10.9) | 17.1% (14.8-20.0) |
| malicious | Spam catch | 3.0% (msg 2.1-3.9) | 0.9% (msg 0.5-1.4) |
| malicious | All positives catch | 7.6% (5.5-9.7) | 13.8% (9.4-18.4) |
| malicious | SA ham FA | 0.7% (msg 0.4-1.1) | 0.0% (msg 0.0-0.1) |
| malicious | Enron ham FA | 0.1% (0.0-0.1) | 0.0% (0.0-0.1) |

| Same-era comparison | Baseline catch | Learned catch | Baseline FA | Learned FA |
| --- | --- | --- | --- | --- |
| ham 2002 2005 vs positives 2005 2007 | 23.6% (msg 22.0-25.4) | 35.5% (msg 33.7-37.5) | 0.6% (0.1-2.8) | 2.0% (0.9-6.4) |
| same corpus spamassassin 2002 2005 | 4.5% (msg 3.4-5.6) | 16.8% (msg 15.0-18.8) | 0.8% (msg 0.5-1.2) | 1.3% (msg 0.9-1.7) |

In words:

- On `content`, equal false alarms buy equal flagged catch (52.8% against 52.9%) with SpamAssassin false alarms 3.6 points lower, and `malicious` catch of 20.6% against 13.1% at 1.0% against 2.5% SpamAssassin false alarms.
- On the same-era SpamAssassin comparison, `content` learned catch is 10.0% against 31.3%: the learned model buys the lower false-alarm rate with spam recall, and the baseline's spam catch rested partly on `reply_to_mismatch`, a signal that is mostly mailing lists.
- On `content_noera` both scorers are weak (about 23% phishing catch at under 1% false alarms), and the learned weights are better only at `malicious` (17.1% against 8.8% phishing catch).
- Targeting 5% and 1% on *each* ham source is demanding because the baseline already flags 19.8% of SpamAssassin ham. The pooled variants (files ending `_pooled`) let SpamAssassin ham reach 14.8-19.4% false alarms in the same-era comparisons because Enron dominates the pooled rate; use them with care.

The thresholds, targets, L2 strengths, cross-validation losses and a hash of the dev training IDs are inside each weights file ([`docs/data/mail/`](../data/mail/README.md)).

## Round 1: rule changes measured on dev

The dev error analysis above pointed at five things: mailing-list mail flagged for its own `Reply-To`, high-severity findings on legitimate HTML mail, many weak findings that never add up, no signal for generic spam wording, and phishing with no finding at all. Round 1 changes `kestrix.mail` for each, **one change at a time, re-measured on the full dev split after each**, and keeps a change only if it raises catch without false alarms moving beyond noise, or cuts false alarms without losing catch. The locked test was not run, and the round tooling cannot run it: `features --splits dev` never analyzes a test message.

**Setup.** Same dev split and the same *content only* feature set as the baseline table (every `auth` finding removed; flagged is `suspicious` or `malicious`; intervals are the same grouped bootstrap, `msg` where a cohort has fewer than 8 groups). `research/hpc/mail/mail_round.sh NAME` runs the changed analyzers over every dev message (16-task array, about a minute each) and then the dev metrics, into `/scratch/$USER/kestrix/mailbench-rules/NAME/`; the benchmark's own `reports/` and `features/` were not touched. The code ran from `~/kestrix-mailrules` (rounds record `MAILBENCH_SHA` there), not `~/kestrix`, so another sync could not change it mid-round. Aggregate probes (`python -m kestrixmailbench probe`, `research/hpc/mail/mail_probe.sbatch`) counted coarse properties and curated candidate terms per cohort inside Slurm jobs and wrote counts only (cells under 3 messages dropped): [`mail-probe-baseline.json`](../data/mail/mail-probe-baseline.json). Re-running the shipped rules through this tooling (`r0`) reproduced the baseline to the digit. All rounds: [`mail-rules-round1.json`](../data/mail/mail-rules-round1.json); the final dev metrics: [`mail-dev-metrics-round1.json`](../data/mail/mail-dev-metrics-round1.json).

### Per change, dev, content only

Each row builds on the kept changes above it, and the decision column is what the code now does. Columns: phishing flagged (and malicious), spam flagged, SpamAssassin ham false alarms (flagged, malicious) and Enron ham false alarms.

| Round | Change | Phishing flagged | Phishing malicious | Spam flagged | SA ham flagged | SA ham malicious | Enron ham flagged | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| r0 | Shipped rules (baseline) | 52.9% (45.5-58.8) | 13.1% (10.0-17.2) | 31.3% (msg 29.1-33.7) | 19.8% (msg 18.4-21.4) | 2.5% (msg 1.9-3.1) | 0.5% (0.3-0.8) | n/a |
| r1 | 1a. List `Reply-To` is info | 52.9% (45.5-58.8) | 13.1% (10.0-17.2) | 30.4% (msg 28.2-32.8) | 3.6% (msg 3.0-4.3) | 2.5% (msg 1.9-3.1) | 0.5% (0.3-0.8) | keep |
| r1b | 1b. Link text via a click tracker is low | 52.6% (45.3-58.6) | 12.8% (9.8-16.8) | 30.1% (msg 27.9-32.5) | 3.3% (msg 2.6-3.9) | 2.1% (msg 1.6-2.7) | 0.5% (0.3-0.8) | revert |
| r1c | 1c. Display-name domain is medium unless it holds an address | 52.9% (45.5-58.8) | 9.4% (7.5-11.7) | 30.4% (msg 28.2-32.8) | 3.6% (msg 3.0-4.3) | 0.8% (msg 0.4-1.1) | 0.5% (0.3-0.8) | superseded by 1d |
| r2 | 2a. 3 low findings from 2 analyzers (on 1a, 1c) | 61.1% (52.0-68.3) | 9.4% (7.5-11.7) | 34.5% (msg 32.2-37.0) | 16.0% (msg 14.7-17.5) | 0.8% (msg 0.4-1.1) | 0.5% (0.3-0.8) | revert |
| r2b | 2b. Same, `return_path_mismatch` does not count | 59.1% (50.2-66.3) | 9.4% (7.5-11.7) | 32.1% (msg 29.9-34.6) | 4.1% (msg 3.4-4.8) | 0.8% (msg 0.4-1.1) | 0.5% (0.3-0.8) | keep |
| r2c | 1d. Display name that is only a domain stays high | 59.1% (50.2-66.3) | 11.4% (9.5-13.9) | 32.1% (msg 29.9-34.6) | 4.1% (msg 3.4-4.8) | 0.8% (msg 0.4-1.1) | 0.5% (0.3-0.8) | keep |
| r3 | 3a. `intent.spam_offer`, 36 phrases | 59.2% (50.2-66.4) | 11.4% (9.5-13.9) | 46.9% (msg 44.4-49.5) | 4.6% (msg 3.8-5.4) | 0.8% (msg 0.4-1.1) | 0.9% (0.7-1.2) | superseded by 3b |
| r3b | 3b. `spam_offer` pruned to 23 phrases | 59.1% (50.2-66.3) | 11.4% (9.5-13.9) | 43.8% (msg 41.4-46.4) | 4.3% (msg 3.6-5.0) | 0.8% (msg 0.4-1.1) | 0.6% (0.4-0.9) | keep |
| r4 | 4a. `links.shared_page_host`, low | 59.2% (50.3-66.3) | 11.4% (9.5-13.9) | 43.8% (msg 41.4-46.4) | 4.3% (msg 3.6-5.0) | 0.8% (msg 0.4-1.1) | 0.6% (0.4-0.9) | revert |
| r6 | 4b. Looser credential wording | 67.9% (60.1-74.0) | 11.4% (9.5-13.9) | 44.0% (msg 41.7-46.6) | 4.5% (msg 3.7-5.3) | 0.8% (msg 0.4-1.1) | 0.7% (0.5-1.0) | superseded by 4c |
| r7 | 4c. Those patterns need "your" | 67.5% (59.4-73.8) | 11.4% (9.5-13.9) | 43.9% (msg 41.5-46.4) | 4.5% (msg 3.7-5.3) | 0.8% (msg 0.4-1.1) | 0.7% (0.5-1.0) | keep (final) |

**1a. Mailing-list `Reply-To` (kept).** Of the 472 SpamAssassin ham messages with `reply_to_mismatch`, 95% carry a `Reply-To` in the same organization as a domain named by some list header (92% by `List-Unsubscribe`, 73% by `List-Id`); 96% have `Precedence: bulk`. The rule uses `List-Id`, `List-Post` and `List-Unsubscribe` only: a foreign `Reply-To` whose organization matches a domain named there becomes the info finding `mail.sender.reply_to_mailing_list`; any other foreign `Reply-To` still raises `reply_to_mismatch`, and `Precedence` alone explains nothing because it names no domain. The rule explains 446 of the 472, and SpamAssassin ham false alarms fell from 19.8% to 3.6% (`easy_ham` from 18.7% to 0.3%). Phishing catch did not move (no phishing message gained the exemption) and spam catch fell 0.9 points (14 messages), inside the interval overlap. Forged list headers are a way around the exemption in principle; none of the dev phishing used it, but the data cannot show that an adversary would not.

**What else makes `hard_ham` malicious (1b to 1d).** After 1a, 69 SpamAssassin ham messages are `malicious`: `display_name_spoof` on 51 and `text_href_mismatch` on 18. The 51 display names are 96% a bare domain (not an address), 98% with other words around it (88% with three words or more), all `.com`. In phishing the same finding fires on 289 messages: 233 bare domains, 56 addresses, and in 126 of them the whole display name is just a domain, which at most 2 ham messages did (the probe drops cells under 3). So an address or a lone domain stays high, and a domain among other words ("Shop.com Deals") becomes medium: it is flagged as before, but no longer `malicious` (SpamAssassin ham malicious 2.5% to 0.8%; `hard_ham` 17.4% and 22.6% to 6.2% and 5.3%). The first version, which made every bare domain medium (1c), also cost 3.7 points of phishing malicious; 1d recovered 2 of them. Phishing malicious ends at 11.4% against 13.1% at the start, a real cost of the change. For `text_href_mismatch`, 11 of the 18 ham cases went through click-tracker hosts (against 17 of 465 in phishing); downgrading those (1b) cut ham false alarms from 100 to 91 messages but lost 14 phishing messages, so it did not pay and was reverted. The 18 stay.

**2. Weak-signal combination (kept, with one exclusion).** The proposed rule (3 distinct low findings from 2 analyzers, `auth.missing` and info excluded) lifted phishing 52.9% to 61.1% but SpamAssassin ham false alarms from 3.6% to 16.0%, because list mail with a tracker routinely has `return_path_mismatch`, `plain_http` and `random_host` together. A sweep over stored dev findings, with no change to code (job 11292604), shows where the false alarms come from:

| Rule (lows needed / analyzers needed, ignored ids) | Phishing | Spam | SA ham | Enron ham |
| --- | --- | --- | --- | --- |
| none (round 1 state) | 52.9% | 30.4% | 3.6% | 0.5% |
| 3 / 2 | 61.1% | 34.5% | 16.0% | 0.5% |
| 4 / 2 | 54.5% | 31.2% | 4.0% | 0.5% |
| 5 / 2 | 53.0% | 30.4% | 3.6% | 0.5% |
| 3 / 3 | 56.2% | 32.9% | 5.0% | 0.5% |
| 3 / 2 without `plain_http` | 54.7% | 31.3% | 4.1% | 0.5% |
| 3 / 2 without `plain_http` and `return_path_mismatch` | 54.2% | 30.4% | 3.6% | 0.5% |
| 3 / 2 without `return_path_mismatch` | 59.1% | 32.1% | 4.1% | 0.5% |
| 2 / 2 without `plain_http` | 62.5% | 34.2% | 13.8% | 0.5% |
| 2 / 2 | 73.7% | 55.6% | 40.3% | 1.6% |

The shipped rule is "3 / 2 without `return_path_mismatch`": the finding's own text already says lists and mail services do this routinely, which is a reason not to count it as an independent signal. It lifts phishing by 6.2 points (about 380 messages) for 0.5 points more SpamAssassin ham false alarms and none on Enron. The rule is explicit in the verdict (`mail.analyze.verdict`, rule 3) and in the report (`verdict_reason`, for example `3 weak findings from different analyzers add up: ...`); `heuristic_score` is unchanged, so three lows score 15. This sweep is 12 variants chosen on dev; the choice carries a selection effect.

**3. Spam wording (kept, pruned).** From curated candidate phrases written before looking at any counts, cohort counts per phrase were taken inside a job (11292761). The first family (36 phrases, r3) lifted spam catch from 32.1% to 46.9% but Enron false alarms from 0.5% to 0.9%. Phrases were pruned where ham hits were not far below spam hits (`penis`, `money-back guarantee`, `free money`, `cash bonus`, `free cash`, `satisfaction guaranteed`, `earn $`, `hot stock`, `penny stock`, `stock alert`, `investment opportunity`, `xxx`, `diet pills`); the 23 that remain (for example `mortgage rates`, `bad credit`, `debt consolidation`, `lose weight`, `weight loss`, `home-based business`, `100% guaranteed`, `bulk e-mail`) add 17 Enron ham messages (0.1% of Enron). Result: spam 32.1% to 43.8% (+11.7), SpamAssassin ham +0.2 points, Enron +0.1 point. `unsubscribe`, `free`, `click` and `viagra` were not used: they are common in the SpamAssassin ham, which is mailing lists, partly about spam (`unsubscribe` is in 15% of that ham and 84% of `hard_ham`, `viagra` in 3%). Pruning used dev ham counts, so these rates are optimistic, and the phrases are 2000s spam.

**4. Phishing with no finding (7%).** Among the 427 dev phishing messages with no content finding: 28% have no link at all, 12% an empty text, 8% no subject (Enron ham: 3.7%, so unusable), 81% no attachment, and 19% one or more attachments (PDF 6%, images 8%), against 3% of SpamAssassin ham; 10% have at most 200 characters of text plus an attachment, in none of the 83 SpamAssassin ham with attachments (Enron's release has none, so this cannot be checked); 9% link to a free page or form host (Google Docs or Forms 5%), against 0.3% of SpamAssassin ham (blogs) and no Enron ham. No single one of these separates the group from ham by enough to flag on, and the era problem is acute (2002 ham has no Google Forms, and modern business mail attaches PDFs with a one-line body). Two checks were tried or ruled out. A low `mail.links.shared_page_host` (free page and form hosts) added 4 phishing messages through the combination rule and was reverted (r4). Private or intranet addresses in links (the `links.ip_host` false alarms on Enron): the 51 Enron messages link to public addresses (45) or numeric hosts (5), and fewer than 3 have a private address (the probe drops smaller cells), so there is nothing to lower and `ip_host` is unchanged. What did pay is wording: 30% of the no-finding group use a verify, confirm or validate word and 33% say "account", but the cue phrases were too narrow. Looser patterns (a verify, confirm, validate, update, restore, unlock or secure word within three words of account, password, login or credentials; an account alarm such as "your account has been limited"; "unusual activity"; "click here to verify") fire on 25% of the phishing the rules had missed, 0.4% of SpamAssassin ham, 0.1% of Enron ham and 0.3% of spam (job 11292963; that count also included a "security alert" phrase that was not shipped). Added to `mail.intent.credential_request` they lift phishing from 59.1% to 67.9% (+8.8) for +0.2 points of SpamAssassin ham false alarms and +0.1 on Enron. Reading the regenerated landing-page sample showed one wart: "Confirm the new account" in a payment-change message matched, which is not a credential request. Requiring "your" after the verify, confirm, validate, update, restore, unlock or secure word (or the word directly before "account", "identity", "login" or "credentials") removed that, cost 0.4 points (67.5%) and changed nothing else (r7, job 11293037 for the counts). "Close to firing" checks (thresholds not quite reached) were not analyzed beyond this.

### Cumulative result and what it does and does not show

| Measure on dev (content only) | Before | After |
| --- | --- | --- |
| Phishing flagged | 52.9% (45.5-58.8) | 67.5% (59.4-73.8) |
| Phishing malicious | 13.1% (10.0-17.2) | 11.4% (9.5-13.9) |
| Spam flagged | 31.3% (msg 29.1-33.7) | 43.9% (msg 41.5-46.4) |
| Spam malicious | 3.8% (msg 2.8-4.7) | 3.8% (msg 2.8-4.7) |
| SpamAssassin ham flagged | 19.8% (msg 18.4-21.4) | 4.5% (msg 3.7-5.3) |
| SpamAssassin ham malicious | 2.5% (msg 1.9-3.1) | 0.8% (msg 0.4-1.1) |
| Enron ham flagged | 0.5% (0.3-0.8) | 0.7% (0.5-1.0) |
| All ham flagged | 3.7% (0.5-7.6) | 1.3% (0.7-2.3) |
| All ham malicious | 0.5% (0.0-1.1) | 0.2% (0.0-0.4) |
| `hard_ham` flagged (2002, 2003) | 26.8%, 27.8% | 26.8%, 27.1% |
| `hard_ham` malicious (2002, 2003) | 17.4%, 22.6% | 6.2%, 5.3% |
| Same corpus, SpamAssassin 2002: spam flagged / ham flagged | 31.3% / 19.8% | 43.9% / 4.5% |
| Ham 2002-2005 vs positives 2005-2007: flagged / false alarms | 64.4% / 14.7% | 78.0% / 3.7% |
| Phishing flagged, all findings / content, no header-era ids | 53.8% / 52.9% | 68.5% / 64.7% |
| Precision, phishing vs ham (flagged, corpus class mix) | 83.9% (59.7-98.0) | 94.8% (87.5-97.9) |
| Synthetic families | all ham clean, all positives flagged | unchanged |

Phishing by Nazario file, flagged before and after: `phishing0.mbox` 69.3% to 77.8%, `phishing2.mbox` 59.8% to 74.4%, `phishing3.mbox` 68.0% to 77.3%, `private-phishing4.mbox` 50.8% to 70.3%, 2015 40.8% to 64.0%, 2017 35.5% to 55.1%, 2020 54.4% to 59.9%, 2023 41.3% to 49.2%, 2025 32.3% to 37.1%. Gains are smaller on the newest phishing.

**Caveats.**

- **Everything is tuned on dev.** Round 1 made about a dozen rule decisions, a 12-variant combination sweep and a phrase pruning, all on the dev split. The numbers above are optimistic by an unknown amount; only the locked test, not yet run, can say how much. The groups behind the intervals were not resampled for the selection.
- **Part of the phishing gain follows the era.** `plain_http` and `outdated_mailer` carry the combination rule on old mail (in the dev phishing it fires on, `plain_http` is in 98% and `outdated_mailer` in 67%). With the two header-era ids removed the phishing figure is 64.7% instead of 67.5%, and the combination rule is worth less on mail where plain HTTP and old mailer names no longer occur.
- **False alarms are low on corpora that cannot show the modern ones.** Enron has no attachments, `Reply-To` or list headers; SpamAssassin ham is one person's 2002 lists, several about spam. Modern ham (shared Google documents, HTTPS-only marketing mail with trackers, forwarded mail) is absent, and the looser credential wording could fire on genuine "verify your account" mail from a real provider; with DMARC passing, such a finding is already low, as before.
- **Malicious phishing fell** from 13.1% to 11.4% because of 1d, and from 13.2% to 11.5% with all findings. Suspicious and malicious are different promises; this trades some `malicious` for fewer `malicious` ham.
- **No learned weights are involved.** The learned weights in this document were fitted to the shipped rules; their findings (era leakage) still apply, and they were not refitted for the new ids.
- **One new report field.** `verdict_reason` is added to the report (`null` unless the combination rule alone decided). It is additive; `docs/api.md` and the dashboard's type for the report do not list it yet.

## What is not claimed

- No test-set number exists yet. Dev numbers, and especially the learned-versus-baseline comparison, are for choosing what to test, not for quoting.
- Nothing here measures how Kestrix performs on current mail, on a user's own mailbox, or on modern authentication. 2005-2025 phishing from one person's inbox, 2002 mailing-list and spam mail, and 1999-2002 Enron mail are three different populations, not a sample of today's traffic.
- Precision depends on the corpora's class mix and is not a prevalence-adjusted real-world figure.
- Year is the `Date` header, which spam and phishing can forge; no year is verified.
- Enron is easy ham for header signals (no `Received`, `Return-Path` or `Reply-To`); its low false-alarm rate says little about modern ham. SpamAssassin ham is one person's mailing lists and `hard_ham`.
- Early Nazario mailboxes are anonymized; some signals (`links.sender_domain_mismatch`, `links.ip_host`) may measure that anonymization.
- Labels are the corpora's own and may contain errors; the near-duplicate hash can merge distinct mail that shares wording.
- The synthetic source is generated from the same patterns the analyzers look for and is not evidence of accuracy.
- `protected_domains` and `trusted_authserv_ids` were not used, so the look-alike and display-name-brand checks and the trusted-authentication path were not exercised.
- A model trained on these corpora learns these corpora. Learned weights are candidates, not shipped behavior.

## Reproduce

On the cluster ([`docs/hpc.md`](../hpc.md)), from `~/kestrix` after syncing the repository and `bash research/hpc/common/setup_env.sh mail`:

```bash
ssh explorer-xfer 'mkdir -p /scratch/$USER/kestrix/mailbench/logs && cd ~/kestrix && nohup bash -l research/hpc/mail/mail_acquire.sh > /scratch/$USER/kestrix/mailbench/logs/acquire.log 2>&1 &'
ssh explorer 'cd ~/kestrix && bash research/hpc/mail/mail_chain.sh smoke'   # a few hundred messages first
ssh explorer 'cd ~/kestrix && bash research/hpc/mail/mail_chain.sh full'    # build -> features -> dev-metrics -> learn
```

Run order after the dev review (once, on the owner's go-ahead):

```bash
ssh explorer 'cd ~/kestrix && sbatch research/hpc/mail/mail_locked.sbatch --name mail-v1 \
  --weights /scratch/$USER/kestrix/mailbench/reports/mail-weights-content.json \
  --weights /scratch/$USER/kestrix/mailbench/reports/mail-weights-content_noera.json'
```

Round 1 (dev only; run from a code tree of your choice, here `~/kestrix-mailrules`, which shares the virtual environment in `~/kestrix`):

```bash
ssh explorer 'cd ~/kestrix-mailrules && export KESTRIX_CODE=$HOME/kestrix-mailrules && bash research/hpc/mail/mail_round.sh NAME'   # dev features, then dev metrics
ssh explorer 'cd ~/kestrix-mailrules && export KESTRIX_CODE=$HOME/kestrix-mailrules && sbatch research/hpc/mail/mail_probe.sbatch'  # aggregate cohort probe
```

`/scratch` is purged on the first Tuesday of each month (next: 2026-11-03). The manifest lets every download be repeated; the learned weights and aggregate reports are committed under `docs/data/mail/`.


## Locked test (2026-10-22)

Run once each, after the round-1 rules were frozen, on the 10,897 locked-test messages (3,019 phishing, 238 spam,
7,550 normal: 6,014 Enron and 1,536 SpamAssassin), in 135 split groups. Reports:
[`mail-locked-rules-baseline.json`](../data/mail/mail-locked-rules-baseline.json) (the old rules, stored features; job
11297308) and [`mail-locked-rules-round1.json`](../data/mail/mail-locked-rules-round1.json) (round-1 rules at
`a3bfd06`, features recomputed on the cluster, job 11297304, evaluated by job 11297306). Content-only feature set;
95% group-bootstrap intervals (SpamAssassin ham has too few groups for one and is shown without).

| Measure | Old rules | Round 1 |
| --- | --- | --- |
| Phishing flagged (suspicious or malicious) | 49.4% (41.1–58.2) | **61.2% (54.0–69.3)** |
| Phishing malicious | 13.6% (8.9–19.7) | 10.6% (7.8–14.5) |
| Spam flagged | 31.1% (17.1–37.2) | **50.0% (27.9–54.9)** |
| SpamAssassin ham flagged | 20.1% | **1.0%** |
| Enron ham flagged | 1.1% (0.4–2.0) | 1.3% (0.6–2.2) |
| All normal mail flagged | 5.0% (0.8–9.9) | **1.2% (0.7–2.0)** |
| Precision, phishing vs normal (flagged) | 79.8% (51.3–97.2) | **95.2% (87.0–98.4)** |

What the locked test shows:

- **Round 1 held up on unseen mail.** Phishing caught rose by 11.8 points (12.6 on dev), spam by 18.9, and false
  alarms on mailing-list mail fell from 20.1% to 1.0%. Enron false alarms are unchanged within noise.
- **Fewer messages are called malicious** (13.6% to 10.6% of phishing), the trade-off accepted on dev for far fewer
  malicious verdicts on normal mail.
- **The learned weights are not adopted.** On the same messages they flag only 34.3% of phishing (94.3% precision),
  though more as malicious (23.6%); the hand rules dominate at the flagged level.
- **Limits:** the normal mail is 1999–2005 and Enron lacks most headers, so modern false-alarm rates are unknown; spam
  has 238 test messages and wide intervals. The locked test is now spent; future rounds need new held-out data (for
  example TREC 2007 if the usage agreement is approved).

## Modern normal mail (2022-2026)

Measured 2026-10-23 and 2026-10-24 on the rules at `main` 0ca93a7 (round 1 included). Question: how often does the email check flag *modern* normal mail, given that the benchmark's normal mail is 1999-2005 (Enron lacks nearly every modern header; SpamAssassin ham is one person's 2002 lists)? Code: `src/kestrixmailbench/modern*.py`; jobs `research/hpc/mail/modern_*.sbatch`; aggregates `docs/data/mail/modern-*.json`.

### Data and its bias

Public mailing-list archives with raw headers, three months a year (spread over the year) 2022-2026, at most 250 messages per list-month after exact and near-duplicate removal (same rule as above).

| Source | Lists (dev / held out) | Read | Kept | Headers |
| --- | --- | --- | --- | --- |
| Apache Software Foundation, `lists.apache.org` API | dev: dev@airflow, dev@arrow, dev@kafka, dev@spark, user@spark; held out: dev@flink, user@flink, users@kafka | 32,925 | 19,119 (dev 12,327; held out 6,792) | Authentication-Results on 97% (topmost is ASF's own stamp), Received, DKIM, ARC on 12%, list headers |
| GNU, `lists.gnu.org` mbox archive | dev: coreutils, emacs-devel, grub-devel, guile-user, help-gnu-emacs; held out: bug-bash, guile-devel | 28,031 | 14,103 (dev 10,976; held out 3,127) | Received, DKIM-Signature (82%), Received-SPF, ARC on 8%, list headers; no Authentication-Results on 96% |
| Synthetic modern newsletters and notices (`.example` senders, 8 families x 15, labelled separately) | n/a | 120 | 120 | provider-style: DKIM by the sending provider, bounce domain on the provider, one-click List-Unsubscribe, ARC, tracked HTTPS links, tracking pixel |

Two months are missing (`user@spark` 2023-03 and 2024-11: the API stalled). The split is by *list*: three of eight ASF lists and two of seven GNU lists were held out by seeded hash before any measurement (dev 23,303 messages in 50 list-year groups, held out 9,919 in 25). Bootstrap resamples list-year groups, so with 5-15 lists the intervals are wide; a message-level interval is shown where it is the only one.

**Bias, stated plainly.** This is mailing-list mail between technical people, not a personal inbox. List servers add list headers and rewrite nothing the rules use; the senders are developers (code, logs, private IP addresses, URLs, patches) and the mail is partly automated (Jira, GitHub, Jenkins). It has no bank statements, shipping notices, marketing newsletters or family mail. Messages are labelled normal by origin, not by hand: a few may be real spam that got through, which would make the rates upper bounds. Both archives drop or keep what their servers accepted, so spam rejected upstream is absent. Authentication is the archive's view, not a mailbox's (see below).

### Results: current rules

Verdict `suspicious` or `malicious` counts as flagged. Same analyzer as the shipped code, all findings (the content-only figure differs by under 0.05 points).

| Cohort | Messages | Flagged | Malicious |
| --- | --- | --- | --- |
| Dev, all modern lists | 23,303 | 1.03% (0.43-1.92) | 0.64% (0.10-1.45) |
| Dev, ASF | 12,327 | 1.72% (0.63-3.45) | 1.18% (0.23-2.73) |
| Dev, GNU | 10,976 | 0.26% (0.15-0.39) | 0.02% (0.00-0.04) |
| **Held out, all modern lists (one run)** | 9,919 | **2.61% (0.62-5.20)** | **0.41% (0.10-0.83)** |
| Held out, ASF | 6,792 | 3.74% (0.92-7.60) | 0.60% (0.15-1.21) |
| Held out, GNU | 3,127 | 0.16% (0.00-0.54) | 0.00% |
| Synthetic modern (regression set) | 120 | 0 | 0 |
| For comparison: 1999-2005 ham, round-1 rules, dev | Enron 13,986 / SpamAssassin 2,757 | 0.7% / 4.5% | 0.05% / 0.8% |
| For comparison: 1999-2005 ham, locked test | Enron 6,014 / SpamAssassin 1,536 | 1.3% / 1.0% | n/a |

Modern list mail is flagged about 1-3% of the time, in the range of the old Enron and SpamAssassin ham, not ten times worse; the held-out rate is higher than dev's and its interval overlaps it. The false alarms are concentrated in a few lists, not spread:

| List | Dev flagged | Held-out flagged |
| --- | --- | --- |
| asf dev-spark / user-spark | 7.2% / 7.4% | |
| asf user-flink | | 10.8% |
| asf users-kafka | | 1.0% |
| asf dev-airflow, dev-arrow, dev-kafka, dev-flink | 0.5%, 0.2%, 0.0% | dev-flink 0.2% |
| all five GNU dev lists / both held-out GNU lists | 0.16-0.35% | 0.04%, 0.56% |

By year (dev, ASF): 2022 2.4%, 2023 1.9%, 2024 3.3%, 2025 0.2%, 2026 0.8%; GNU 0.0-0.4% every year. The swings follow which lists and threads fall in a year, not a trend. Messages the headers mark as automated (Jira, GitHub, Jenkins, Auto-Submitted) are flagged 0.0% on dev (1,525) and 0.3% on held out (1,679): the false alarms are human mail.

### What misfires (dev only)

Of the 241 dev flags, 148 are `malicious`. By finding (share of flagged dev messages): `links.text_href_mismatch` 60% (97% of the malicious ones), `links.ip_host` 17%, `sender.reply_to_mismatch` 7%, `sender.display_name_spoof` 4%, `links.sender_domain_mismatch`, `punycode_host`, `credential_request`, `dangerous_type` and `dmarc_fail` 2% each; three flags come from the weak-signal combination. `return_path_mismatch` is on 36% of all messages and `auth.missing` on 47% but neither flags anything alone (the first is excluded from the combination; the second is info).

- **`text_href_mismatch` (high).** It fires when an HTML link's visible text is a bare web address that is neither the destination nor the sender's domain. 138 of the 145 dev messages are in `dev@spark` and `user@spark`. In a tally of link classes (one message can count in several), 95 entries are links through a URL-rewriting gateway (host names such as Outlook Safe Links, Proofpoint URL Defense or Mimecast; the visible address was kept and the href replaced); in 36 of those the wrapped address is the one the text shows, in 59 no wrapped address could be read. The other 78 entries go to an ordinary host with a different name than the text. A message that quotes a GitHub or Apache address as text and links elsewhere also fires.
- **`ip_host` (medium).** 37 of 41 dev cases are private addresses (192.168.x.x, 10.x.x.x, loopback) in technical discussion; phishing kits use public addresses.
- **`reply_to_mismatch` (medium), the round-1 exemption.** On ASF the exemption works: of 6,652 dev messages with a foreign Reply-To, 6,640 (99.8%) are explained by `List-Id`, `List-Post` or `List-Unsubscribe` and become the info finding. The 12 left carry a list header and a Reply-To at a free-mail provider (a participant's own setting). On GNU lists a foreign Reply-To is almost absent (10 of 10,976 messages). On the held-out lists it is the main cause, not a small one: 186 of 2,569 foreign-Reply-To messages stay `reply_to_mismatch` and make up about two thirds of the held-out flags (user@flink: 10.8% flagged). The dev rule that covers the same finding class (free-mail Reply-To, proposal P6) is not measured on held out, by design.

### Authentication on real modern headers

- The auth analyzer trusts the topmost `Authentication-Results`. On ASF 97% of messages have one and 63% have two or more (the ASF mail gateway's own stamp, topmost, plus `spamproc*.apache.org` stamps lower down). For 11,264 dev messages the topmost stamp is `apache.org`, which almost never carries a method result; for 771 it is a `spamproc*.apache.org` stamp, which does. Across dev only 2 messages show `dmarc=pass`, 85 `dmarc=none`, 53 `spf=pass` and 853 `dkim=pass`. Where results exist at all they are probably in the other stamps, which the analyzer by design does not read without `trusted_authserv_ids` (not checked message by message). So on this archive the auth analyzer is mostly blind, not wrong; it produced 3 `dkim_fail`, 4 `dmarc_fail` (all four flagged), 8 `spf_softfail` and 182 low `dkim_not_aligned` messages in 23,303.
- GNU has no `Authentication-Results` (96%), so every such message gets `auth.missing` (info) and verdict `insufficient_evidence`, which is why 44% of dev messages are `insufficient_evidence`, not `clean`. Authentication that GNU does record (DKIM-Signature on 83%, Received-SPF on 88%) is not read by the analyzer.
- **List re-signing:** ARC seals are on 12% of ASF and 8% of GNU messages, none is read. The "list re-signing or footer breaks DKIM" case was not seen: 3 `dkim_fail` in 23,303 dev messages. These archives may not show it (the footer-adding, subject-rewriting lists were not sampled, and the topmost stamp is mostly result-less), so absence here is weak evidence.
- `dkim_not_aligned` (low) appears on 0.8% of messages (senders that DKIM-sign with a service domain); it never flags alone.

Not tested: a user's own mailbox, whose topmost `Authentication-Results` is the provider's and carries real results; this is the case the analyzer was written for.

### Proposed rule changes (design on dev) and what was applied

**Applied 2026-10-24: P1, P3 and P6 are now in `kestrix.mail`** (`analyzers.py`; docs in `docs/modules/mail.md`). Rerun on dev with the real implementation (`docs/data/mail/modern-variants-applied.json`; harness base column): modern dev flagged 0.49% (114 of 23,303; 0.19-0.89) and malicious 0.33% (77), old-dev phishing 68.45% flagged / 11.50% malicious, spam 43.86%, SpamAssassin ham 4.46%, Enron ham 0.71%, synthetic modern 0 flagged: the P1 + P3 + P6 row below, message for message (same counts in every cohort). Two details differ from the proposal text. The shipped gateway list is anchored to vendor domains, not the broad `REWRITER` pattern: Outlook Safe Links `*.safelinks.protection.outlook.com`, Proofpoint `urldefense.com` and `urldefense.proofpoint.com`, Mimecast `protect-<region>.mimecast.com` and `*.mimecastprotect.com`, plus Barracuda `linkprotect.cudasvc.com` and Cisco `secure-web.cisco.com`. A first version with only the first three vendors gave 126 flagged (0.54%) because 176 dev links went through Barracuda and 4 through Cisco; adding them (the only other gateways seen in dev links) restored the exact numbers. A Proofpoint PhishAlarm host (`*-phishalarm-*.proofpoint.com`, 6 links) matched the old pattern but is a reporting button, not a rewriter, and is not in the list. Proofpoint v2/v3 and Mimecast/Cisco links carry the target in the path or an encoded query value, so for them the wrapped address is usually unreadable and only the text comparison is skipped. Held-out lists were not run. The numbers below are the design measurements.

All numbers below are dev. Variants are applied by monkeypatch in `src/kestrixmailbench/modern_proposals.py` over the unmodified `kestrix.mail`, run on the modern dev lists and on the old dev corpora (24,359 messages) to see what each change costs in catch. Dev only: the held-out lists were not used for any of these and were not re-run with them.

| Variant | Modern dev flagged / malicious | Old dev phishing flagged / malicious | Old dev spam | SA ham | Decision |
| --- | --- | --- | --- | --- | --- |
| current rules | 1.03% (0.43-1.92) / 0.64% | 68.47% / 11.50% | 43.86% | 4.46% | |
| P1 unwrap rewriter links | 0.73% / 0.33% | 68.47% / 11.50% | 43.86% | 4.46% | adopt |
| P3 private-IP links are info | 0.86% / 0.64% | 68.45% / 11.50% | 43.86% | 4.46% | adopt |
| P6 list Reply-To at free-mail is low | 0.97% / 0.64% | 68.47% / 11.50% | 43.86% | 4.46% | adopt |
| **P1 + P3 + P6** | **0.49% (0.19-0.89) / 0.33% (0.06-0.70)** | **68.45% (61.81-74.09) / 11.50%** | 43.86% | 4.46% | **adopt** |
| P4 tracker link text not compared | 1.01% / 0.61% | 68.25% / 11.22% | 43.60% | 4.10% | reject (loses catch) |
| P1 + P3 + P4 + P6 | 0.47% / 0.31% | 68.24% / 11.22% | 43.60% | 4.10% | reject |

1. **P1, `mail.links.text_href_mismatch` and the other link checks (`analyzers._link_findings`).** Before analyzing a link, if the destination host belongs to a URL-rewriting gateway (`safelinks.protection.outlook.com` and the regional `eurNN`/`namNN` forms, `urldefense*`, `*.proofpoint.com`, `*.mimecast.com`, `linkprotect`, `secure-web`, `protection.outlook`), take the address wrapped in a query parameter as the destination (first value starting `http://` or `https://`); if none can be read, do not compare the visible text (the destination is unknown, so no mismatch can be claimed). Dev: ASF `dev@spark` 7.2% to 4.1%, modern flagged 1.03% to 0.73%, malicious 0.64% to 0.33%; no change on any old corpus. Residual: the 78 ordinary-host entries are untouched and are the likely source of most of `dev@spark`'s remaining 3.7% (not verified message by message). The host pattern is `REWRITER` in `modern_proposals.py` (it also matches generic regional gateway prefixes such as `eur01.` and `nam04.`, which a careful implementation should anchor to the known gateway domains).
2. **P3, `mail.links.ip_host`.** Severity `info` when the host is an IP address that is not globally routable (`ipaddress.ip_address(host).is_global` is false: private, loopback, link-local, documentation). Public and malformed numeric hosts stay medium. Dev: `user@spark` 7.4% to 3.7%, modern flagged 1.03% to 0.86%; old phishing 68.47% to 68.45% (one message).
3. **P6, `mail.sender.reply_to_mismatch`.** When `list_domains(msg)` is non-empty (list mail) and every Reply-To domain is a free-mail provider (gmail, googlemail, outlook, hotmail, live, yahoo, icloud, protonmail, proton.me, qq, 163, 126, mykolab), severity `low` instead of `medium`. Dev: `user@spark` 7.4% to 5.9%, modern flagged 1.03% to 0.97%. This is the change aimed at the held-out `user@flink` cause, which is a hypothesis: it was not measured there.
4. **Not adopted: P4** (not comparing bare-address text on click-tracking destinations). It gives back catch (phishing malicious 11.50% to 11.22%, spam 43.86% to 43.60%) for 0.02 points fewer modern false alarms; round 1 reached the same conclusion for a similar rule.
5. **Authentication, to be decided, not measured.** (a) Document that `trusted_authserv_ids` should name the receiving gateway (here `spamproc1-he-*.apache.org`), since the topmost stamp can be a result-less relay stamp. (b) Optionally read `Received-SPF` and the DKIM-Signature presence when no Authentication-Results exists (GNU), so that `auth.missing` stops turning 44% of a no-header archive into `insufficient_evidence`. Neither changes false alarms; both change what the verdict says.

Synthetic modern cohort: the 120 messages (receipts, password resets, shipping, ESP newsletters, security alerts, invites, bank statements, code notifications) are all clean under every variant; their only findings are low (`return_path_mismatch`, `dkim_not_aligned`, and `credential_request` on the DMARC-passing security alert). That is a regression check on shapes I wrote after reading the dev causes, not evidence about real mail.

### Held-out claim

`reports/LOCKED_EVAL.json` on the cluster was claimed once (job 11346774, rules unmodified, features of the held-out lists computed in that job) and is copied to [`modern-locked-eval.json`](../data/mail/modern-locked-eval.json). The held-out measurement was run for the current rules only; no variant was run on it. Anything further on those five lists is no longer a held-out measurement.

### Caveats

- Mailing-list mail, technical senders, a partly automated corpus, 25 groups on held out; the intervals are wide and the held-out and dev rates differ by a factor of 2.5 because of two or three lists. Two of five held-out lists carry most of the held-out false alarms.
- `dev@spark` alone is 124 of the 145 dev `text_href_mismatch` messages: one list, probably a few vendor-style HTML threads. P1's gain is therefore measured mostly on one list.
- Labels are by origin. Near-duplicate removal shrinks repeated automated mail, so notification templates are under-weighted.
- `max 250 per list-month` makes the busy lists (kafka, flink, emacs-devel) sampled rather than complete.
- ASF terms: the privacy policy says list mail is public and may be collected by third parties; it does not address bulk reuse. `mail-archives.apache.org` forbids bots, so the Pony Mail API (no `robots.txt`) was used at about one request per 3 seconds, 120 requests. GNU's `robots.txt` allows the archive with `Crawl-delay: 10`; requests were 11 seconds apart (105 requests). Please confirm the owner is comfortable with the ASF route.

### Reproduce

Code sync to `/scratch/$USER/kestrix/mailmodern-code` (home was over quota), data under `/scratch/$USER/kestrix/mailmodern`:

```bash
ssh explorer-xfer 'cd /scratch/$USER/kestrix/mailmodern-code && PYTHONPATH=src uv run --no-project --python 3.12 python -m kestrixmailbench.modern acquire --root /scratch/$USER/kestrix/mailmodern'
sbatch research/hpc/mail/modern_build.sbatch; sbatch research/hpc/mail/modern_features.sbatch; sbatch research/hpc/mail/modern_report.sbatch; sbatch research/hpc/mail/modern_diag.sbatch
sbatch research/hpc/mail/modern_variants.sbatch; sbatch research/hpc/mail/modern_variants_report.sbatch   # dev only
sbatch research/hpc/mail/modern_heldout.sbatch                                              # once; claims LOCKED_EVAL.json
```
