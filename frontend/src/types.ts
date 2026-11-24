/**
 * Types transcribed by hand from `docs/API_CONTRACT.md` (API Contract v2.0.0, frozen).
 *
 * Rules applied throughout this file:
 *  - No `any`. Payloads the contract leaves open (`{...}`) are typed as
 *    `JsonValue` / `JsonObject` so they stay inspectable without lying about shape.
 *  - Fields the contract marks optional (`?`) are optional; nullable fields are
 *    `| null` so the UI is forced to handle "not assessed yet".
 *  - Every shape below is traceable to a contract line. Anything inferred is
 *    flagged with an INFERRED comment naming the contract field it came from.
 */

/* ------------------------------------------------------------------ *
 * JSON primitives
 * ------------------------------------------------------------------ */

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

/* ------------------------------------------------------------------ *
 * Conventions (contract §Conventions)
 * ------------------------------------------------------------------ */

/** `{items, next_cursor, has_more, limit}` — all list endpoints. */
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  has_more: boolean;
  limit: number;
}

export interface PageParams {
  /** 1..200, default 25. */
  limit?: number;
  /** Opaque cursor string. */
  cursor?: string | null;
}

export type UserRole = 'admin' | 'user';

/** Frozen scan status vocabulary. */
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

/** Frozen control state vocabulary. */
export type ControlStatus = 'compliant' | 'non_compliant' | 'not_applicable' | 'unknown' | 'error';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

/** Layers that can resolve a control value (contract §5 `/policies/effective`). */
export type PolicyLayer = 'baseline' | 'override' | 'device';

/* ------------------------------------------------------------------ *
 * §1 Meta
 * ------------------------------------------------------------------ */

/** `GET /health` */
export interface HealthResponse {
  status: string;
  service: string;
  environment: string;
  version: string;
  baseline_version: string;
  scoring_model_version: string;
  /** Additive in the implemented API; not read by the UI. */
  database?: JsonObject;
}

/** `{standard, control, url}` — contract §3 `standard_refs`; `url` may be absent. */
export interface StandardReference {
  standard: string;
  control: string;
  url: string | null;
}

/** `GET /api/v1/meta` → `baseline` */
export interface MetaBaseline {
  baseline_id: string;
  version: string;
  title: string;
  published_at: string;
  references: StandardReference[];
  description?: string;
  reference_policy?: string;
}

/** `GET /api/v1/meta` */
export interface MetaResponse {
  app_version: string;
  scoring_model_version: string;
  baseline: MetaBaseline;
  control_count: number;
  control_weight_total: number;
  app_name?: string;
  environment?: string;
}

/* ------------------------------------------------------------------ *
 * §2 Authentication
 * ------------------------------------------------------------------ */

/** `UserOut` */
export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

/** `GET /auth/policy` → `password` */
export interface PasswordRules {
  min_length: number;
  max_length: number;
  require_letter: boolean;
  require_digit: boolean;
  require_symbol: boolean;
}

/** `GET /auth/policy` */
export interface AuthPolicy {
  password: PasswordRules;
  access_token_minutes: number;
  refresh_token_days: number;
  max_failed_logins: number;
  lockout_minutes: number;
  /** Human-readable restatement of the rules; shown verbatim when present. */
  password_hint?: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  full_name?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

/** `POST /auth/login` and `POST /auth/refresh` (identical shape). */
export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
  /** Seconds. */
  expires_in: number;
}

/** Refresh tokens are accepted **only** in the JSON body (contract §2). */
export interface RefreshRequest {
  refresh_token: string;
}

export interface LogoutRequest {
  refresh_token?: string;
}

export interface MessageResponse {
  message: string;
}

/* ------------------------------------------------------------------ *
 * §3 Scans
 * ------------------------------------------------------------------ */

export interface Remediation {
  what_is_wrong: string;
  why_it_matters: string;
  what_should_be_done: string;
  /** Present on `ControlResult.remediation`; absent on `Finding.recommendation`. */
  verify?: string;
  /** Command that verifies the fix, when the backend supplies one. */
  verify_command?: string | null;
}

/**
 * `Finding.recommendation`.
 * Declared as a type alias (not an interface) so it stays assignable to the
 * `JsonValue` index signatures used by the AI payloads below.
 */
export type FindingRecommendation = {
  what_is_wrong: string;
  why_it_matters: string;
  what_should_be_done: string;
  priority: string;
  remediation_type: string;
  verify_command?: string | null;
  remediation_instruction?: string | null;
};

export type ControlResultStatus = ControlStatus;

export interface ControlResult {
  control_id: string;
  title: string;
  category: string;
  weight: number;
  severity: Severity | string;
  status: ControlStatus;
  applicability: string;
  actual_state: JsonValue;
  expected_state: JsonValue;
  evidence: JsonValue;
  standard_refs: StandardReference[];
  rationale: string;
  remediation: Remediation;
  exempted: boolean;
  exemption_reason?: string | null;
}

export interface Finding {
  id: string;
  control_id: string | null;
  title: string;
  category: string;
  severity: Severity | string;
  status: ControlStatus | string;
  description: string | null;
  current_value: JsonValue;
  expected_value: JsonValue;
  evidence: JsonValue;
  /** Nullable: a finding may be recorded without a generated recommendation. */
  recommendation: FindingRecommendation | null;
  standard_refs?: StandardReference[];
}

/**
 * `ScanSummary` — counts and scores are nullable: they stay null until the scan
 * completes, so the UI can distinguish "no findings" from "not assessed yet".
 */
export interface ScanSummary {
  id: string;
  device_id: string | null;
  hostname: string | null;
  status: ScanStatus;
  stage: string;
  /** 0..100 */
  progress: number;
  source: string;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  security_score: number | null;
  compliance_score: number | null;
  assessment_coverage: number | null;
  risk_score: number | null;
  risk_level: string | null;
  evidence_quality: string | null;
  critical_count: number | null;
  high_count: number | null;
  medium_count: number | null;
  low_count: number | null;
  informational_count: number | null;
  total_findings: number | null;
  controls_assessed: number | null;
  controls_total: number | null;
  scanner_version: string | null;
  scoring_model_version: string | null;
  baseline_version: string | null;
  error_message: string | null;
}

/** `POST /scans/start` body. */
export interface ScanStartRequest {
  device_id?: string;
  source: string;
  collectors?: string[];
  inventory?: boolean;
}

/** `POST /scans/start` → `202` (never blocks on collection). */
export interface ScanStartResponse {
  scan_id: string;
  status: ScanStatus;
  stage: string;
  progress: number;
}

/** `GET /scans/{id}/status` */
export interface ScanStatusResponse {
  scan_id: string;
  status: ScanStatus;
  stage: string;
  progress: number;
  heartbeat_at: string | null;
  error_message: string | null;
  duration_ms: number | null;
}

/**
 * `POST /scans/{id}/cancel` → `202 {"scan_id","status":"cancelling"}`.
 * CONTRACT NOTE: "cancelling" is not part of the frozen status vocabulary
 * (`queued|running|completed|failed|cancelled`); it is modelled separately here
 * and treated as non-terminal until the scan reports `cancelled`.
 */
export type ScanCancellingStatus = 'cancelling';

export interface ScanCancelResponse {
  scan_id: string;
  status: ScanCancellingStatus;
}

/** `GET /scans` filters. */
export interface ScanListFilters extends PageParams {
  status?: ScanStatus;
  device_id?: string;
  source?: string;
  /** hostname contains */
  q?: string;
}

export interface AssessmentCounts {
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  informational_count: number;
  total_findings: number;
  controls_assessed: number;
  controls_total: number;
}

/** Category rollup inside `results.categories`. */
export interface CategoryScore {
  /** Contract shows `[{...}]`; the implemented API emits `label`. */
  category?: string;
  label?: string;
  score: number | null;
  count: number;
  status: string;
  non_compliant?: number;
  unknown?: number;
  weight?: number;
  exposure?: number;
  description?: string;
}

/**
 * `results.assessment` — contract shows `assessment:{...}` without fields.
 * Kept as an open object so the UI never invents keys.
 */
export type AssessmentMeta = JsonObject;

/** `results` block of `GET /scans/{id}/results`. */
export interface ScanAssessment extends AssessmentCounts {
  security_score: number | null;
  compliance_score: number | null;
  assessment_coverage: number | null;
  risk_score: number | null;
  risk_level: string | null;
  evidence_quality: string | null;
  controls: ControlResult[];
  categories: CategoryScore[];
  assessment: AssessmentMeta;
}

/**
 * INFERRED: contract shows `device:{...}` inside `GET /scans/{id}/results`.
 * Shape mirrors `DeviceOut` (contract §4), which describes the same entity.
 */
export interface ScanDevice {
  id?: string;
  hostname?: string;
  os_type?: string;
  os_version?: string | null;
  os_build?: string | null;
  criticality?: number;
  criticality_label?: string;
  first_seen_at?: string | null;
  last_scan_at?: string | null;
}

/** `GET /scans/{id}/results` */
export interface ScanResults {
  scan_id: string;
  status: ScanStatus;
  /** Present when collection itself reported a limitation. */
  scanner_error?: string | null;
  device: ScanDevice | null;
  results: ScanAssessment;
  findings: Finding[];
}

/** `GET /scans/{id}/document` — full stored evidence (evidence drawer only). */
export interface ScanDocument {
  scan_id: string;
  schema_version: string | null;
  normalized_data: JsonObject | null;
  baseline_version?: string | null;
  scoring_model_version?: string | null;
  evidence_bytes?: number | null;
}

/** `POST /scans/upload` → `200` (synchronous). */
export interface ScanUploadResponse {
  scan_id: string;
  status: ScanStatus;
  /** Contract shows `summary:{...}`; shape unspecified. */
  summary: JsonObject;
  findings: Finding[];
  message?: string;
  finding_count?: number;
  device_id?: string | null;
  categories?: CategoryScore[];
}

/* ------------------------------------------------------------------ *
 * §4 Devices
 * ------------------------------------------------------------------ */

export type Criticality = 1 | 2 | 3 | 4 | 5;

/** `criticality_label` values, mapping 1..5 — contract §4 (frozen). */
export const CRITICALITY_LABELS: Record<Criticality, string> = {
  1: 'low',
  2: 'standard',
  3: 'elevated',
  4: 'high',
  5: 'critical',
};

/** Latest completed assessment attached to a device. */
export interface DeviceLatest {
  security_score: number | null;
  risk_level: string | null;
  risk_score: number | null;
  evidence_quality: string | null;
  compliance_score: number | null;
  assessment_coverage: number | null;
  completed_at: string | null;
}

/** `DeviceOut` */
export interface Device {
  id: string;
  hostname: string;
  os_type: string;
  os_version: string | null;
  os_build: string | null;
  criticality: number;
  criticality_label: string;
  first_seen_at: string | null;
  last_scan_at: string | null;
  scan_count: number;
  latest?: DeviceLatest | null;
}

export interface DeviceRegisterRequest {
  hostname: string;
  os_type?: string;
  os_version?: string;
  os_build?: string;
  criticality?: number;
}

export interface DeviceUpdateRequest {
  hostname?: string;
  os_type?: string;
  os_version?: string;
  os_build?: string;
  criticality?: number;
}

/** Contract §4 documents only `limit`/`cursor` for `GET /devices`. */
export type DeviceListFilters = PageParams;

/** `GET /devices/compare` → `devices[]` */
export interface DeviceCompareRow {
  device_id: string;
  hostname: string;
  os_type: string;
  os_version: string | null;
  criticality: number;
  last_scan_at: string | null;
  security_score: number | null;
  risk_score: number | null;
  risk_level: string | null;
  evidence_quality: string | null;
}

export interface DeviceCompareResponse {
  devices: DeviceCompareRow[];
}

/* ------------------------------------------------------------------ *
 * §5 Policies (baseline + overrides + exemptions)
 * ------------------------------------------------------------------ */

export interface BaselineControl {
  control_id: string;
  title: string;
  category: string;
  weight: number;
  severity: Severity | string;
  expected_state: JsonValue;
  /** Contract types this loosely; the shipped pack emits an object of conditions. */
  applicability: JsonValue;
  rationale: string;
  remediation: Remediation;
  references: StandardReference[];
  /** Evidence document paths this control reads (contract: `evidence_keys`). */
  evidence_paths: string[];
  collector?: string;
  evaluation?: JsonObject;
}

/** `GET /baseline` */
export interface BaselinePack {
  baseline_id: string;
  version: string;
  title: string;
  description: string;
  published_at: string;
  references: StandardReference[];
  /** Contract shows `thresholds:{...}` / `categories:{...}` without fields. */
  thresholds: JsonObject;
  categories: JsonObject;
  controls: BaselineControl[];
  schema_version?: string;
  reference_policy?: string;
  severity_impact?: Record<string, number>;
  control_count?: number;
  control_weight_total?: number;
}

/** A policy override row, keyed by `control_id`. */
export interface Policy {
  id: string;
  control_id: string;
  name: string;
  description: string | null;
  category?: string | null;
  severity?: Severity | string | null;
  weight?: number | null;
  expected_value?: JsonValue;
  recommendation_template?: string | null;
  is_enabled: boolean;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface PolicyCreateRequest {
  control_id: string;
  name: string;
  description?: string;
  category?: string;
  severity?: string;
  weight?: number;
  expected_value?: JsonValue;
  recommendation_template?: string;
  is_enabled?: boolean;
}

export interface PolicyUpdateRequest {
  name?: string;
  description?: string;
  category?: string;
  severity?: string;
  weight?: number;
  expected_value?: JsonValue;
  recommendation_template?: string;
}

export interface PolicyListParams extends PageParams {
  /** Contract: default `true` for admins, `false` otherwise. */
  include_disabled?: boolean;
}

/**
 * `GET /policies/effective` row.
 *
 * The contract only promises "the baseline values and which layer overrode
 * them". The API sends the effective value per field (`weight`, `severity`)
 * alongside the baseline value (`baseline_weight`, `baseline_severity`) and a
 * `sources` map naming the winning layer for each field — that is what the
 * Policies page renders side by side with the override.
 */
export interface EffectiveControl {
  control_id: string;
  title: string;
  category: string;
 /** Effective (resolved) values. */
  weight: number;
  severity: string;
  enabled: boolean;
  /** Shipped-baseline values, before overrides. */
  baseline_weight: number;
  baseline_severity: string;
  expected_state: JsonValue;
  collector: string;
  rationale: string;
  remediation: Remediation;
  references: StandardReference[];
  /** Field name → layer that supplied it (`baseline`, `override`, `device`). */
  sources: Record<string, string>;
  exempted: boolean;
  exemption_reason: string | null;
}

export interface EffectivePoliciesResponse {
  baseline_id: string;
  baseline_version: string;
  total_weight: number;
  controls: EffectiveControl[];
}

/** Per-device control exemption (`GET /devices/{id}/exemptions`). */
export interface Exemption {
  control_id: string;
  reason: string;
  expires_at: string | null;
  id?: string;
  device_id?: string;
  created_by?: string | null;
  created_at?: string | null;
}

export interface ExemptionCreateRequest {
  control_id: string;
  reason: string;
  expires_at?: string;
}

/* ------------------------------------------------------------------ *
 * §6 Admin
 * ------------------------------------------------------------------ */

/** `GET /admin/users` row = `UserOut` + lockout/login telemetry. */
export interface AdminUser extends User {
  failed_login_count: number;
  locked_until: string | null;
  last_login_at: string | null;
}

export interface AuditLogEntry {
  id: string;
  created_at: string | null;
  actor_id: string | null;
  actor_email: string | null;
  action: string;
  entity_type: string | null;
  entity_id: string | null;
  outcome: string;
  ip_address: string | null;
  request_id: string | null;
  details: JsonObject | null;
  entry_hash: string;
  prev_hash: string;
  /** Monotonic position in the hash chain. */
  seq?: number;
}

/** `GET /admin/audit-logs` filters. */
export interface AuditLogFilters extends PageParams {
  action?: string;
  actor_id?: string;
  outcome?: string;
  /** ISO-8601 timestamp. */
  from?: string;
  /** ISO-8601 timestamp. */
  to?: string;
}

/** `GET /admin/audit-logs/verify` */
export interface AuditChainVerifyResult {
  chain_valid: boolean;
  checked: number;
  first_broken_id: string | null;
  first_broken_seq?: number | null;
  head_hash?: string | null;
}

/** `GET /admin/stats` */
export interface AdminStats {
  users: number;
  devices: number;
  scans: number;
  findings: number;
  audit_entries: number;
  database_bytes: number;
  evidence_bytes: number;
  reports?: number;
}

export type AuditOutcome = 'success' | 'failure' | 'denied' | string;

/**
 * AMBIGUOUS IN CONTRACT: the responses of `PATCH /admin/users/{id}/role`,
 * `PATCH /admin/users/{id}/status` and `POST /admin/users/{id}/unlock` are not
 * specified. Only an acknowledgement message is assumed.
 */
export interface AdminMutationAck {
  message?: string;
  [key: string]: JsonValue | undefined;
}

/* ------------------------------------------------------------------ *
 * §7 Platform security policy
 * ------------------------------------------------------------------ */

export interface LockoutPolicy {
  max_failed_logins: number;
  lockout_minutes: number;
  window_minutes: number;
}

export interface TokenSecurityPolicy {
  algorithm: string;
  access_token_minutes: number;
  refresh_token_days: number;
  refresh_rotation: boolean;
  reuse_detection: boolean;
}

export interface RateLimitRule {
  name: string;
  limit: number;
  window_seconds: number;
  scope: string;
}

export interface UploadSecurityPolicy {
  max_bytes: number;
  allowed_extensions: string[];
  quarantine_ttl_minutes: number;
}

export interface HeaderSecurityPolicy {
  content_security_policy: string;
  x_frame_options: string;
  referrer_policy: string;
  hsts: boolean;
}

export interface RetentionPolicy {
  scan_days: number;
  audit_days: number;
  report_days: number;
}

export interface SecretsPolicy {
  jwt_secret_configured: boolean;
  jwt_secret_strength: string;
  ai_key_configured: boolean;
}

export interface AiRuntimePolicy {
  enabled: boolean;
  timeout_seconds: number;
  max_retries: number;
  cache_ttl_minutes: number;
  redact_pii: boolean;
}

export interface StartupCheck {
  name: string;
  ok: boolean;
  severity: string;
  message: string;
}

/** `GET /admin/security-policy` */
export interface SecurityPolicy {
  password: PasswordRules;
  lockout: LockoutPolicy;
  tokens: TokenSecurityPolicy;
  rate_limits: RateLimitRule[];
  uploads: UploadSecurityPolicy;
  headers: HeaderSecurityPolicy;
  retention: RetentionPolicy;
  secrets: SecretsPolicy;
  ai: AiRuntimePolicy;
  startup_checks: StartupCheck[];
}

/* ------------------------------------------------------------------ *
 * §8 AI (advisory only)
 * ------------------------------------------------------------------ */

export interface AiStatus {
  provider: string;
  model: string;
  configured: boolean;
  connected: boolean;
  checked_at: string | null;
  cached: boolean;
  enabled?: boolean;
  error?: string | null;
}

/** `POST /ai/report/{scan_id}` */
export interface AiReport {
  report_id: string;
  summary: string;
  model_used: string;
  cached: boolean;
  scan_id?: string;
  advisory?: boolean;
}

/** `POST /ai/findings/{finding_id}/explain` */
export interface AiExplanation {
  finding_id: string;
  title: string;
  explanation: string;
  model_used: string;
  cached: boolean;
  advisory?: boolean;
}

/** `POST /ai/findings/{finding_id}/recommend` */
export interface AiFindingRecommendation {
  finding_id: string;
  title: string;
  priority: string;
  recommendation: FindingRecommendation;
  model_used: string;
  cached: boolean;
  advisory?: boolean;
}

/**
 * `GET /ai/scans/{scan_id}/recommendations` element. The endpoint returns flat
 * remediation fields rather than a nested object.
 */
export interface AiScanRecommendationItem {
  finding_id: string;
  control_id: string | null;
  title: string;
  severity: string;
  category: string;
  priority: string;
  what_is_wrong: string;
  why_it_matters: string;
  what_should_be_done: string;
  verify?: string | null;
}

export interface AiScanRecommendations {
  scan_id: string;
  recommendations: AiScanRecommendationItem[];
}

/** `GET /ai/risk-priorities/{scan_id}` element (deterministic ranking). */
export interface PrioritizedFinding {
  finding_id: string;
  control_id: string | null;
  title: string;
  severity: string;
  category: string;
  priority: string;
  score: number;
  weight?: number | null;
  risk_contribution?: number | null;
}

export interface AiRiskPriorities {
  scan_id: string;
  /** The single highest-priority finding, or null when there are none. */
  fix_first: PrioritizedFinding | null;
  prioritized_findings: PrioritizedFinding[];
}

export interface ChatSession {
  id: string;
  title: string;
  scan_id?: string | null;
  created_at?: string | null;
}

export interface ChatMessage {
  id: string;
  role: string;
  content: string;
}

/** `POST /ai/chat` body. */
export interface ChatRequest {
  content: string;
  session_id?: string | null;
  /** Optional scan context; the backend validates ownership and binds sessions to one scan. */
  scan_id?: string | null;
}

/** `POST /ai/chat` response. */
export interface ChatResponse {
  session_id: string;
  question: string;
  answer: string;
  model_used: string;
}

/* ------------------------------------------------------------------ *
 * Errors (contract §Conventions)
 * ------------------------------------------------------------------ */

/** FastAPI 422 item. */
export interface ValidationErrorItem {
  loc: Array<string | number>;
  msg: string;
  type: string;
}

/** `{"detail": "<human readable message>"}` */
export interface ApiErrorBody {
  detail?: string | ValidationErrorItem[];
}
