# JSON output field guide

Every command below prints one JSON object with `--json`. All analysis reports carry
`generated_by: "Kestrix by Ruthvik Bandari"`. Severities are `high`, `medium`, `low`, `info`, and findings
are sorted most severe first. Errors go to stderr, not into the JSON.

## `kestrix mail analyze FILE --json`

| Field | Meaning |
| --- | --- |
| `schema_version` | `1` |
| `notice` | Privacy and heuristic notice. |
| `sha256` | SHA-256 of the raw message bytes. |
| `subject` | Subject, cut to 200 characters. |
| `from_address` | Address in `From`, or `null`. |
| `verdict` | `malicious`, `suspicious`, `clean` or `insufficient_evidence`. |
| `heuristic_score` | 0 to 100; high 35, medium 15, low 5 per finding, capped. Not a probability. |
| `findings[]` | `id`, `analyzer` (`auth`, `sender`, `lookalike`, `links`, `attachments`, `intent`), `severity`, `title`, `explanation`, `evidence`. |
| `counts` | `parts`, `links`, `attachments`, `text_truncated`, `links_truncated`. |

Exit 0 analysed, 2 rejected (over 25 MiB, not an email message, too deeply nested).

## `kestrix forensics file PATH --json`

| Field | Meaning |
| --- | --- |
| `filename`, `size` | Base name and size in bytes (over 50 MiB is refused). |
| `hashes` | `md5`, `sha1`, `sha256`, `sha512`. |
| `file_type` | `id`, `label`, `executable`, `extension`, `expected_extensions`, `extension_mismatch`. |
| `entropy` | `overall` (0 to 8 bits per byte), `block_size`, `block_count`, `points[]`, `high_entropy_threshold` (7.2), `high_entropy_regions[]`, `high_entropy_region_count`, `high_entropy_bytes`. |
| `byte_histogram` | 256 counts. Usually not worth showing. |
| `printable_ratio` | Share of printable bytes, 0 to 1. |
| `exif`, `exif_status` | Photo metadata (`tags`, `gps_present`, `gps`) and why it is or is not present. |
| `findings[]` | `id`, `severity`, `title`, `explanation`. |

## `kestrix forensics url URL --json`

| Field | Meaning |
| --- | --- |
| `url`, `scheme`, `host` | As given; `scheme` is `null` when none was written. |
| `unicode_host` | How the host displays to a person (decoded punycode). |
| `registrable_domain` | Offline estimate of who owns the host. |
| `score`, `level` | Heuristic 0 to 100; `none`, `low`, `medium`, `high`. |
| `score_note` | Reminder that the score is not a probability and the URL was never visited. |
| `findings[]` | `id`, `severity`, `title`, `explanation`. |

## `kestrix webcheck scan URL --json`

| Field | Meaning |
| --- | --- |
| `notice` | Authorization notice. |
| `requested_url`, `final_url` | Before and after redirects. |
| `status_code`, `headers_checked` | `null` / `false` when the TLS handshake failed. |
| `redirect_chain[]` | `url`, `address`, `status_code`, `elapsed_ms`. |
| `tls` | `host`, `status`, `detail`, `protocol`, `issuer`, `not_after`, `days_remaining`. |
| `grade`, `score` | A to F and 0 to 100. |
| `findings[]` | `id`, `severity`, `title`, `explanation`, `recommendation`, `evidence`, `baseline_severity`, `context`; whole-site scans add `pages` (at most 20 paths) and `pages_total`. |
| `timings` | `total_ms`, `http_ms`, `tls_ms`. |
| `profile` | `kind`, `detected`, `declared`, `reasons` (plain sentences), `decided_by` (the page that set the kind), `evidence`; `null` when headers were not checked. |
| `scope` | `site` (the default: up to 50 pages) or `page` (`--page-only`). The fields above about the URL, status and TLS describe the start page. |
| `pages[]` | Whole-site scans: `path`, `found_via` (`start`, `link`, `sitemap`, `probe`), `outcome` (`checked`, `not_html`, `http_error`, `redirects_off_site`, `blocked`, `failed`, `duplicate`), `status_code`, `kind`, `finding_ids`, `detail`. |
| `requests_sent`, `limits_reached` | GETs sent; `page_cap`, `deadline` or `request_budget` when the scan stopped early. |
| `links_skipped`, `sitemap_entries` | Links not fetched (other sites, files) and addresses read from `/sitemap.xml`. |

Exit 0 completed (even with grade F), 2 URL or target refused, 3 unreachable.

## `kestrix bitcoin scan ADDRESS... --json`

| Field | Meaning |
| --- | --- |
| `results[]` | `input`, `address_type`, `network` (`mainnet`, `test`, `regtest` or `null`), `risk`, `key_exposure`, `explanation`, `recommendation`, `chain_activity`. |
| `summary` | `total` and `by_risk` counts. |

`kestrix bitcoin migration TYPE --json`: `address_type`, `urgency`, `summary`, `steps[]`, `cautions[]`.
Exit 0 success, 2 rejected input, 3 upstream unavailable.

## `kestrix detect run ... --json` and `kestrix detect demo CASE --json`

| Field | Meaning |
| --- | --- |
| `outcome`, `reason` | See `detect.md`; `reason` is plain language or `null`. |
| `rule`, `mapping`, `datasets` | Titles and SHA-256 hashes of the inputs. |
| `coverage[]` | Per rule field: `sigma_field`, `index_field`, `mapped`, `present`, `total`. |
| `original` | Replay per split (`development`, `validation`): `query`, `error`, `counts` (`tp`, `fp`, `fn`, `tn`, `unknown_matched`, or `null` on error), `scenarios_expected`, `scenarios_detected`, `matched_event_ids`. |
| `hypotheses[]` | `family`, `reason_codes`, `fields`, `evidence_event_ids`, `alternative_index_fields`. |
| `telemetry_recommendations[]` | `insufficient_evidence` only: `field`, `guidance`. |
| `candidates[]` | `candidate` (envelope with `proposal_id`, `patch_kind`, `patch`), `development`; the selected one also `validation`, `policy_failures`, `passed`. |
| `rejected_candidates[]` | `proposal_id`, `reason`. |
| `selected`, `provisional`, `diff`, `artifact` | `repaired` only. `artifact` has `kind`, `content` (full patched file), `sha256`. |
| `manifest` | Versions, engine image and timings. |
| `evidence` | Only with `--evidence-dir`: `sha256`, `path`. |

Keys appear only once the run reaches the step that fills them; detect exits 10 or 11 still print JSON.
