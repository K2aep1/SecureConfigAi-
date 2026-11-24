# SecureConfigAI — API Contract v2.0.0

**Status: FROZEN.** This file is the single source of truth for the HTTP interface
between `backend/` and `frontend/`. Backend implements it; frontend consumes it.
Any change must be made here first.

Base URL: `http://127.0.0.1:8001` (dev). All routes below are relative to `/api/v1`
unless stated otherwise. JSON in, JSON out, UTF-8.

## Conventions

- **Auth**: `Authorization: Bearer <access_token>` on every route except
  `GET /health`, `GET /auth/policy`, `POST /auth/register`, `POST /auth/login`,
  `POST /auth/refresh`.
- **Errors**: `{"detail": "<human readable message>"}` with the HTTP status.
  Validation errors keep FastAPI's 422 shape.
- **Rate limits**: `429` with `Retry-After: <seconds>` and
  `detail: "Too many requests. Try again in N seconds."`.
- **Security headers** are present on every response (see `SECURITY_MODEL.md`).
- **Request tracing**: every response carries `X-Request-ID` (echoes the request
  header of the same name when supplied, otherwise generated).
- **Pagination envelope** (all list endpoints):
  ```json
  {"items": [...], "next_cursor": "opaque-or-null", "has_more": true, "limit": 25}
  ```
  Query params: `limit` (1..200, default 25) and `cursor` (opaque string).
- **Timestamps**: ISO-8601 UTC with `Z`-equivalent offset (`2026-10-06T13:22:31.123456+00:00`).

## 1. Meta

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/health` | none | `{"status":"healthy","service":"SecureConfigAI","environment":"development","version":"2.0.0","baseline_version":"1.0.0","scoring_model_version":"2.0.0"}` |
| GET | `/api/v1/meta` | none | `{"app_version","scoring_model_version","baseline":{"baseline_id","version","title","published_at","references":[...]},"control_count","control_weight_total"}` |

## 2. Authentication

| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| GET | `/auth/policy` | none | – | Password + session rules for the UI: `{"password":{"min_length":12,"max_length":72,"require_letter":true,"require_digit":true,"require_symbol":false},"access_token_minutes":30,"refresh_token_days":7,"max_failed_logins":5,"lockout_minutes":15}` |
| POST | `/auth/register` | none | `{"email","password","full_name"?}` | `201 UserOut` |
| POST | `/auth/login` | none | `{"email","password"}` | `200 {"access_token","refresh_token","token_type":"bearer","expires_in":1800}` |
| POST | `/auth/refresh` | none | `{"refresh_token"}` | `200` same as login (rotates the refresh token) |
| POST | `/auth/logout` | bearer | `{"refresh_token"?}` | `200 {"message"}` — revokes the presented refresh token family |
| GET | `/auth/me` | bearer | – | `UserOut` |

`UserOut = {"id","email","full_name","role","is_active","created_at"}`

Behaviour:
- `register` always creates `role="user"`; the request field `role` is ignored.
- `login` returns `423` while the account is locked, `403` when the account is
  disabled, `401` for bad credentials (same message for unknown user and bad
  password). Failed attempts count toward the lockout policy.
- `refresh` detects refresh-token reuse: a previously rotated token returns `401`
  and revokes the whole family.
- Refresh tokens are accepted **only** in the JSON body (never a query string).

## 3. Scans

`ScanSummary = {id, device_id, hostname, status, stage, progress, source, started_at, completed_at,
duration_ms, security_score, compliance_score, assessment_coverage, risk_score, risk_level,
evidence_quality, critical_count, high_count, medium_count, low_count, informational_count,
total_findings, controls_assessed, controls_total, scanner_version, scoring_model_version,
baseline_version, error_message}`

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/scans/start` | bearer | Body `{"device_id"?, "source":"local_agent", "collectors"?:[...], "inventory":bool?}`. Returns **`202`** `{"scan_id","status":"queued","stage":"Queued","progress":0}`. Never blocks on collection. |
| GET | `/scans` | bearer | Paged `ScanSummary` list. Filters: `status`, `device_id`, `source`, `q` (hostname contains). Default order `started_at desc`. |
| GET | `/scans/{id}` | bearer | `ScanSummary` for one scan. |
| GET | `/scans/{id}/status` | bearer | `{"scan_id","status","stage","progress","heartbeat_at","error_message","duration_ms"}` — poll this while a scan runs (recommended cadence 1 s, stop on terminal status). |
| POST | `/scans/{id}/cancel` | bearer | `202 {"scan_id","status":"cancelling"}`; terminal status becomes `cancelled`. |
| GET | `/scans/{id}/results` | bearer | Assessment payload (no raw document): `{scan_id,status,device:{...},results:{security_score,compliance_score,assessment_coverage,risk_score,risk_level,evidence_quality,evidence_quality_explained,collector_health:{status,counts,collectors,degraded},scoring_model_current,stored_scoring_model_version,current_scoring_model_version,counts...,controls:[ControlResult],categories:[...],assessment:{...}},findings:[Finding]}` |
| GET | `/scans/{id}/document` | bearer | `{"scan_id","schema_version","normalized_data":{...}}` — full stored evidence, for the deep-dive view. |
| GET | `/scans/{id}/report/html` | bearer | `text/html` with `ETag`; honours `If-None-Match` → `304`. |
| GET | `/scans/{id}/report/pdf` | bearer | `application/pdf` with `ETag`; honours `If-None-Match` → `304`. |
| POST | `/scans/upload` | bearer | multipart `file` (.json/.zip) → `200 {scan_id,status,summary:{...},findings:[...]}` (synchronous; analysis is sub-second). |
| DELETE | `/scans/{id}` | bearer | `204`, deletes the scan and its artefacts. |

`ControlResult = {control_id, title, category, weight, severity, status, applicability,
actual_state, expected_state, evidence, standard_refs:[{standard,control,url}], rationale,
remediation:{what_is_wrong,why_it_matters,what_should_be_done,verify}, exempted:bool, exemption_reason?}`

`Finding = {id, control_id, title, category, severity, status, description,
current_value, expected_value, evidence, recommendation:{what_is_wrong,why_it_matters,
what_should_be_done,priority,remediation_type}}`

Status vocabulary (frozen): `queued`, `running`, `completed`, `failed`, `cancelled`.
Control states (frozen): `compliant`, `non_compliant`, `not_applicable`, `unknown`, `error`.

## 4. Devices

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/devices` | bearer | Paged. `DeviceOut = {id,hostname,os_type,os_version,os_build,criticality,criticality_label,first_seen_at,last_scan_at,scan_count,latest:{security_score,risk_level,risk_score,evidence_quality,compliance_score,assessment_coverage,completed_at}?}` |
| POST | `/devices/register` | bearer | `{"hostname","os_type"?,"os_version"?,"os_build"?,"criticality"?}` → `201 DeviceOut` (upsert by hostname). |
| GET | `/devices/{id}` | bearer | `DeviceOut` |
| PUT | `/devices/{id}` | bearer | Partial update incl. `criticality` (1..5). |
| DELETE | `/devices/{id}` | bearer | `204`; detaches scan history. |
| GET | `/devices/compare` | bearer | `{"devices":[{device_id,hostname,os_type,os_version,criticality,last_scan_at,security_score,risk_score,risk_level,evidence_quality}]}` |

`criticality_label` ∈ `{"low","standard","elevated","high","critical"}` mapping 1..5.

## 5. Policies (global baseline + overrides)

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/baseline` | bearer | The shipped baseline pack: `{baseline_id,version,title,description,published_at,references:[...],thresholds:{...},categories:{...},controls:[BaselineControl]}` |
| GET | `/policies` | bearer | Overrides. `?include_disabled=true` returns disabled ones too (default `true` for admins, `false` otherwise). Paged. |
| POST | `/policies` | admin | `{"control_id"|"rule_key","name","description"?,"category"?,"severity"?,"weight"?,"expected_value"?,"recommendation_template"?,"is_enabled"?}` → `201` |
| GET | `/policies/{id}` | bearer | One override. |
| PUT | `/policies/{id}` | admin | Partial update (never silently re-enables). |
| PATCH | `/policies/{id}/toggle` | admin | Flips `is_enabled`, returns the row **with the new state**. |
| DELETE | `/policies/{id}` | admin | `204`. |
| GET | `/policies/effective` | admin | The resolved control set: for each control, the baseline values and which layer overrode them (`baseline`, `override`, `device`). |
| GET | `/devices/{id}/exemptions` | bearer | Per-device control exemptions. |
| POST | `/devices/{id}/exemptions` | admin | `{"control_id","reason","expires_at"?}` → `201`; the control becomes `not_applicable` with the reason recorded. |
| DELETE | `/devices/{id}/exemptions/{control_id}` | admin | `204`. |

`BaselineControl = {control_id,title,category,weight,severity,expected_state,applicability,
rationale,remediation:{...},references:[{standard,control,url}],evidence_keys:[...]}`

## 6. Admin

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/admin/users` | admin | Paged `UserOut` + `{failed_login_count, locked_until, last_login_at}`. |
| PATCH | `/admin/users/{id}/role` | admin | `?role=admin|user` (or JSON body). Self-demotion blocked with `400`. |
| PATCH | `/admin/users/{id}/status` | admin | `?is_active=true|false`. Self-disable blocked with `400`. |
| POST | `/admin/users/{id}/unlock` | admin | Clears lockout + failed attempts. |
| GET | `/admin/audit-logs` | admin | Paged. Filters `action`, `actor_id`, `outcome`, `from`, `to`. Rows include `{id,created_at,actor_id,actor_email,action,entity_type,entity_id,outcome,ip_address,request_id,details,entry_hash,prev_hash}`. |
| GET | `/admin/audit-logs/verify` | admin | `{"chain_valid":bool,"checked":N,"first_broken_id":null|id}`. |
| GET | `/admin/security-policy` | admin | The effective platform security policy (section 7). |
| GET | `/admin/stats` | admin | `{users,devices,scans,findings,audit_entries,reports,db_bytes,evidence_bytes}` |
| POST | `/admin/maintenance/retention` | admin | Apply (or preview) the retention windows. `?dry_run=true` **is the default**; `false` deletes and writes `admin.retention_purge` to the audit chain. Returns per-class counts and byte totals. Only terminal scans are eligible. |

## 7. Platform security policy (effective values, read-only)

`GET /admin/security-policy` returns:

```json
{
  "password": {"min_length":12,"max_length":72,"require_letter":true,"require_digit":true,"require_symbol":false},
  "lockout": {"max_failed_logins":5,"lockout_minutes":15,"window_minutes":15},
  "tokens": {"algorithm":"HS256","access_token_minutes":30,"refresh_token_days":7,"refresh_rotation":true,"reuse_detection":true},
  "rate_limits": [{"name":"auth.login","limit":10,"window_seconds":300,"scope":"ip+email"}, "..."],
  "uploads": {"max_bytes":67108864,"allowed_extensions":[".json",".zip"],"quarantine_ttl_minutes":60},
  "headers": {"content_security_policy":"...","x_frame_options":"DENY","referrer_policy":"no-referrer","hsts":false},
  "retention": {"scan_days":365,"audit_days":730,"report_days":180},
  "secrets": {"jwt_secret_configured":true,"jwt_secret_strength":"strong","ai_key_configured":false},
  "ai": {"enabled":true,"timeout_seconds":30,"max_retries":2,"cache_ttl_minutes":60,"redact_pii":true},
  "startup_checks": [{"name":"jwt_secret","ok":true,"severity":"critical","message":"..."}]
}
```

## 8. AI (advisory only)

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/ai/status` | bearer | Cached provider status: `{provider,model,configured,connected,checked_at,cached:bool}`. Never calls the provider inline more than once per 60 s. |
| POST | `/ai/report/{scan_id}` | bearer | `{report_id,summary,model_used,cached}` |
| POST | `/ai/findings/{finding_id}/explain` | bearer | `{finding_id,title,explanation,model_used,cached}` |
| POST | `/ai/findings/{finding_id}/recommend` | bearer | `{finding_id,title,priority,recommendation:{...},model_used,cached}` |
| GET | `/ai/scans/{scan_id}/recommendations` | bearer | `{scan_id,recommendations:[...]}` |
| GET | `/ai/risk-priorities/{scan_id}` | bearer | `{scan_id,fix_first,prioritized_findings:[...]}` |
| GET | `/ai/chat/sessions` | bearer | Paged `ChatSessionOut`. |
| POST | `/ai/chat` | bearer | `{"content","session_id"?}` → `{session_id,question,answer,model_used}` |
| GET | `/ai/chat/{session_id}` | bearer | `[ChatMessageOut]` |
| DELETE | `/ai/chat/{session_id}` | bearer | `204` |

## 9. Frontend requirements

- Consume this contract only; no hard-coded API paths outside `src/api/`.
- Poll `/scans/{id}/status` while a scan is `queued`/`running` (1 s, then 3 s backoff).
- Never request `/scans/{id}/document` unless the user opens the evidence drawer.
- Show `evidence_quality`, `assessment_coverage` and control counts next to every score.
- Distinguish `unknown` and `error` controls visually from `non_compliant` ones.
- Paginate every table; no unbounded lists.
- Surface the baseline version and scoring model version in the UI footer.
