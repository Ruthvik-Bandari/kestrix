/** Response shapes mirrored from the FastAPI source (src/kestrix/**). */

export type Severity = "info" | "low" | "medium" | "high";

// Platform -------------------------------------------------------------------

export interface Health {
  status: string;
  version: string;
  modules: string[];
}

export interface Settings {
  anthropic_key_configured: boolean;
}

// Detection repair -------------------------------------------------------------

export type Outcome =
  | "repaired"
  | "unchanged"
  | "abstained"
  | "unsupported"
  | "insufficient_evidence"
  | "engine_unavailable";

export interface EngineStatus {
  reachable: boolean;
  version: string | null;
  pinned_version: string;
  pinned: boolean;
  image: string;
}

export interface CaseManifest {
  case_id: string;
  provenance?: string;
  title: string;
  root_id?: string;
  split?: string;
  fault?: { kind: string; detail?: string; field?: string };
  expected?: { outcome: Outcome; family?: string; patch_kind?: string };
}

export interface ParsedRule {
  title: string;
  id: string | null;
  sha256: string;
  fields: string[];
  condition: string;
  /** Each selection is a list of alternative field maps (OR); each map is an AND of predicates. */
  selections: Record<string, { field: string; modifier: string; values: string[]; match_all: boolean }[][]>;
}

export interface Counts {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  unknown_matched: number;
}

export interface ReplayResult {
  rule_sha256: string;
  mapping_sha256: string;
  dataset_sha256: string;
  query: string | null;
  error: string | null;
  counts: Counts;
  scenarios_expected: string[];
  scenarios_detected: string[];
  matched_event_ids: string[];
}

export interface FieldCoverage {
  sigma_field: string;
  index_field: string;
  mapped: boolean;
  present: number;
  total: number;
}

export type Family = "mapping" | "missing_telemetry" | "noise" | "logic";

export interface Hypothesis {
  family: Family;
  reason_codes: string[];
  fields: string[];
  evidence_event_ids: string[];
  alternative_index_fields: string[];
}

export interface PredicateSpec {
  field: string;
  modifier: "equals" | "contains" | "startswith" | "endswith";
  values: string[];
  /** Every value must match (Sigma `|all`) instead of any one. */
  match_all?: boolean;
}

export type Patch =
  | { kind: "mapping"; sigma_field: string; from_field: string; to_field: string }
  | { kind: "add_exclusion"; predicates: PredicateSpec[] }
  | { kind: "set_predicate"; selection: string; field: string; predicate: PredicateSpec }
  | { kind: "set_condition"; condition: string };

export interface Candidate {
  schema_version: number;
  proposal_id: string;
  original_sha256: string;
  patch_kind: "rule" | "mapping";
  patch: Patch[];
  reason_codes: string[];
  evidence_event_ids: string[];
  assumptions: string[];
  model_revision: string;
  prompt_sha256: string | null;
}

export interface CandidateEntry {
  candidate: Candidate;
  development: ReplayResult;
  validation?: ReplayResult;
  policy_failures?: string[];
  passed?: boolean;
}

export interface DetectReport {
  schema_version: number;
  outcome: Outcome;
  reason: string | null;
  rule?: { title: string; id: string | null; sha256: string };
  mapping?: { name: string; sha256: string };
  datasets?: { development: string; validation: string | null };
  coverage?: FieldCoverage[];
  original?: { development: ReplayResult; validation?: ReplayResult };
  hypotheses?: Hypothesis[];
  candidates?: CandidateEntry[];
  healthy_reference?: { validation: ReplayResult };
  telemetry_recommendations?: { field: string; guidance: string }[];
  selected?: string;
  provisional?: boolean;
  diff?: string;
  artifact?: { kind: "rule" | "mapping"; content: string; sha256: string };
  manifest: Record<string, unknown>;
  case?: CaseManifest;
}

export interface RunBody {
  rule: string;
  mapping: string;
  development: string;
  validation?: string | null;
  healthy_rule?: string | null;
  healthy_mapping?: string | null;
}

// Web check ------------------------------------------------------------------

export interface WebFinding {
  id: string;
  severity: Severity;
  title: string;
  explanation: string;
  recommendation: string;
  evidence: string | null;
  /** Set when the site profile changed the severity: the checklist severity and why. */
  baseline_severity?: Severity | null;
  context?: string | null;
}

export type SiteKind = "static" | "static_api" | "dynamic";

export interface SiteProfile {
  kind: SiteKind;
  detected: SiteKind;
  declared: SiteKind | null;
  reasons: string[];
  evidence: {
    html: boolean;
    forms: number;
    post_forms: number;
    password_fields: number;
    input_fields: number;
    cookies: number;
    scripts_inline: number;
    scripts_external: number;
    third_party_script_hosts: string[];
    iframes: number;
    api_markers: number;
  };
}

export type TlsStatus =
  | "ok"
  | "not_https"
  | "expired"
  | "not_yet_valid"
  | "hostname_mismatch"
  | "untrusted"
  | "outdated_protocol"
  | "handshake_failed";

export interface WebReport {
  notice: string;
  requested_url: string;
  final_url: string;
  status_code: number | null;
  headers_checked: boolean;
  redirect_chain: { url: string; address: string; status_code: number; elapsed_ms: number }[];
  tls: {
    host: string;
    status: TlsStatus;
    detail: string | null;
    protocol: string | null;
    issuer: string | null;
    not_after: string | null;
    days_remaining: number | null;
  };
  grade: "A" | "B" | "C" | "D" | "F";
  score: number;
  findings: WebFinding[];
  timings: { total_ms: number; http_ms: number; tls_ms: number };
  profile?: SiteProfile | null;
}

// Forensics ------------------------------------------------------------------

export interface ForensicFinding {
  id: string;
  severity: Severity;
  title: string;
  explanation: string;
}

export type ExifStatus = "ok" | "no_exif" | "not_image" | "pillow_not_installed" | "unreadable" | "too_many_pixels";

export interface FileReport {
  filename: string;
  size: number;
  hashes: { md5: string; sha1: string; sha256: string; sha512: string };
  file_type: {
    id: string;
    label: string;
    executable: boolean;
    extension: string | null;
    expected_extensions: string[];
    extension_mismatch: boolean;
  };
  entropy: {
    overall: number;
    block_size: number;
    block_count: number;
    points_span_blocks: number;
    points: { offset: number; entropy: number }[];
    high_entropy_threshold: number;
    high_entropy_regions: { start: number; end: number; mean_entropy: number }[];
    high_entropy_region_count: number;
    high_entropy_bytes: number;
  };
  byte_histogram: number[];
  printable_ratio: number;
  exif: {
    tags: Record<string, string>;
    tags_truncated: boolean;
    gps_present: boolean;
    gps: { latitude: number; longitude: number } | null;
  } | null;
  exif_status: ExifStatus;
  findings: ForensicFinding[];
}

export interface UrlReport {
  url: string;
  scheme: string | null;
  host: string;
  unicode_host: string;
  registrable_domain: string | null;
  score: number;
  level: "none" | "low" | "medium" | "high";
  score_note: string;
  findings: ForensicFinding[];
}

// Bitcoin --------------------------------------------------------------------

export type AddressType = "P2PK" | "P2PKH" | "P2SH" | "P2WPKH" | "P2WSH" | "P2TR";
export type Risk = "critical" | "high" | "low" | "unknown";
export type PublicTestnet = "testnet4" | "signet";

export interface AddressAssessment {
  input: string;
  address_type: AddressType;
  network: "mainnet" | "test" | "regtest" | null;
  risk: Risk;
  key_exposure: "exposed" | "not_exposed" | "unknown";
  explanation: string;
  recommendation: string;
  chain_activity: {
    source: "mempool.space";
    chain: "mainnet" | "testnet4" | "signet";
    funded_outputs: number;
    spent_outputs: number;
    balance_sats: number;
  } | null;
}

export interface ScanResult {
  results: AddressAssessment[];
  summary: { total: number; by_risk: Record<Risk, number> };
}

export interface MigrationPlan {
  address_type: AddressType;
  urgency: "now" | "if_spent";
  summary: string;
  steps: string[];
  cautions: string[];
}

export interface GuardianResult {
  intent: "scan_addresses" | "explain_risk" | "migration_help" | "set_policy_request" | "unknown";
  addresses: string[];
  ignored_addresses: string[];
  address_type: AddressType | null;
  model_summary: string;
  next_step: string;
  model: string;
}
