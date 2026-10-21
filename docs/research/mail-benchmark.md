# Email accuracy benchmark

This page records how well `kestrix.mail` detects phishing and spam on public corpora, why it misses or over-flags, and what signal weights a simple explainable model learns from the same data. It is research tooling: the package is [`src/kestrixmailbench/`](../../src/kestrixmailbench/) (not in the published wheel), the jobs are `hpc/mail_*`, and the aggregate outputs are in [`docs/data/mail/`](../data/mail/README.md).

**Status (2026-10-21).** Everything below is **development-split** numbers. The locked test split has not been opened. No learned weights are wired into `kestrix.mail`; `docs/modules/mail.md` still says Kestrix has not measured detection or false-alarm rates, and that stays true until the locked test has run and the owner decides.

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

1. **Acquire** (`hpc/mail_acquire.sh`, transfer node). Downloads are recorded with URL, size, SHA-256 and time in `manifests/mailbench-manifest.json`; a file that no longer matches its manifest entry is rejected. [`docs/data/mail/mailbench-manifest.json`](../data/mail/mailbench-manifest.json) is the committed copy.
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
8. **Locked test.** `hpc/mail_locked.sbatch` claims `reports/LOCKED_EVAL.json` with an exclusive create, evaluates every baseline and the chosen weights once, and refuses a second run. Test features are written to separate files that no dev stage opens. Not run.

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

On the cluster ([`docs/hpc.md`](../hpc.md)), from `~/kestrix` after syncing the repository and `bash hpc/setup_env.sh mail`:

```bash
ssh explorer-xfer 'mkdir -p /scratch/$USER/kestrix/mailbench/logs && cd ~/kestrix && nohup bash -l hpc/mail_acquire.sh > /scratch/$USER/kestrix/mailbench/logs/acquire.log 2>&1 &'
ssh explorer 'cd ~/kestrix && bash hpc/mail_chain.sh smoke'   # a few hundred messages first
ssh explorer 'cd ~/kestrix && bash hpc/mail_chain.sh full'    # build -> features -> dev-metrics -> learn
```

Run order after the dev review (once, on the owner's go-ahead):

```bash
ssh explorer 'cd ~/kestrix && sbatch hpc/mail_locked.sbatch --name mail-v1 \
  --weights /scratch/$USER/kestrix/mailbench/reports/mail-weights-content.json \
  --weights /scratch/$USER/kestrix/mailbench/reports/mail-weights-content_noera.json'
```

`/scratch` is purged on the first Tuesday of each month (next: 2026-11-03). The manifest lets every download be repeated; the learned weights and aggregate reports are committed under `docs/data/mail/`.
