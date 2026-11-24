# SecureConfigAI_v3 — Project Audit and Unified Roadmap

**Audit date:** 2026-10-19 (second pass)
**Authoritative project:** `SecureConfigAI_v3/`
**Research input:** `SecureConfigAI_v3_Deep_Research_Report.pdf` (34 pages, read in full)
**Method:** non-destructive static read of all source, configuration, migration, test and
build files; live PostgreSQL inspection as a read-only client plus one explicitly
authorised credential rotation; one real non-elevated Windows scanner run; `pytest`;
frontend production build. No user data, table, migration or artefact was deleted.

---

## 1. Executive summary

The project is materially further along than the research PDF describes. The PDF was
written against a build in which the scan ran synchronously inside the request, the
decision engine fabricated a Defender finding from missing evidence, 99.6 % of the
database was duplicated scan JSON, the audit log was never written, and AI could not be
loaded without a key. **Every one of those defects is now fixed in code**, and this pass
verified the fixes rather than repeating them.

What this pass found and changed:

| Finding | Evidence | Action taken |
|---|---|---|
| `backend/.env` pointed at database `secureconfigai` (does not exist) with a password the `secureconfigai` role rejected, so the application could not reach PostgreSQL at all | `psycopg` connect error; `pg_database` lists `secureconfigai_db`, not `secureconfigai` | Pointed the application at the real database and rotated the application role's password to a new random value. Verified least-privilege login. |
| The application role password was unknown/unusable and the JWT secret was the shipped placeholder | `build/config` inspection | Rotated both; `JWT_SECRET_KEY` is now a 64-character random value held only in `backend/.env`. |
| Alembic had **never** been run against PostgreSQL from this checkout; the test database was empty | `secureconfigai_test` had no tables | Ran `alembic upgrade head` against `secureconfigai_test`: all four revisions applied, head `20261006_v2_platform`. |
| Retention was configured but not enforced for scans at all, and quarantine/audit purge functions were never called | `RETENTION_SCAN_DAYS` unused in code; `purge_quarantine`/`purge_older_than` had no callers | Implemented and wired a retention service (scans, reports, audit, quarantine, evidence) with a dry-run mode and an admin endpoint. |
| Scanner health was collected but discarded by the backend | `scan_result.json` carries `collector_status`; `scans`/`scan_results` did not store it and `/results` did not return it | Persisted the per-collector status map and exposed it on the results contract. |
| No CI, no Python project metadata, no lint/format config, no licence, no dependency lock, no secret scanning | repository listing | Added all of the above plus a release packaging script that builds from an allow-list. |
| Legacy scans use status `error`, which the model did not treat as terminal | live `scans` table: 3 `completed`, 2 `error` | `is_terminal` now covers the legacy vocabulary without rewriting history. |

PostgreSQL is now the verified source of truth: the live database `secureconfigai_db`
holds 1 user, 1 device, 5 scans, 18 findings, 4 AI reports and a clean Alembic head, and
the application connects to it as a non-superuser role holding DML on the application
tables only.

---

## 2. Repository and architecture audit

| Area | Verified state (evidence) |
|---|---|
| Project root | `SecureConfigAI_v3/`. `SecureConfigAI_v3_ORIGINAL_BACKUP/` exists; see §4. No `.git` directory anywhere. |
| Backend | FastAPI + SQLAlchemy 2 + Pydantic v2 + Alembic. 39 modules / 8,171 lines under `backend/app`. Routers: auth, devices, scans, policies, admin, ai, meta. |
| Decision engine | `app/services/scoring.py` — 521 lines, scoring model `2.0.0`, five states, noisy-OR risk, collector-health gating, explicit applicability. |
| Baseline registry | `app/data/baseline/global_baseline_v1.json` — **28 controls, total weight 217**, version `1.0.0`, validated at startup. Data, not code. |
| Risk | `aggregate_risk()` combines per-control impact with a noisy-OR model; ceiling is now reachable (100), asset criticality is a per-device column (`devices.criticality`, 1–5) that the API accepts and the engine reads. |
| Scanner | `scanner/` — bounded `ThreadPoolExecutor` orchestrator, shared wall-clock budget, per-collector isolation, `secedit`-based authentication policy, compact UTF-8 JSON with explicit depth. |
| Async scans | `POST /scans/start` → `202` + `queued` row → in-process `ThreadPoolExecutor` (`app/services/jobs.py`), progress streamed from the scanner's JSON lines into `stage`/`progress`/`heartbeat_at`, cancellation terminates the child process, `recover_stale()` fails interrupted runs at startup. |
| AI | `app/services/ai_client.py` — lazily constructed client, missing key = deterministic fallback, explicit timeout, bounded retries with jitter honouring `Retry-After`, digest-keyed database cache, input sanitisation and PII redaction. |
| Reports | `app/services/report_service.py` — pre-generated on completion, content-addressed `ETag`, `304` on `If-None-Match`, `reports` rows now written. |
| Audit | `app/core/audit.py` — 41-action registry, SHA-256 hash chain with a locked chain-head row, `verify_chain()`, retention-aware purge. 43 audited call sites across the API. |
| Frontend | React 18 + TypeScript + Vite 5 + React Router 6 + TanStack Query 5. Route-level `lazy()` chunks, auth/role gates, scan progress polling. |
| Database | PostgreSQL 17 (`postgresql-x64-17`, running on 5432). `secureconfigai_db` 21 MB, head `20261006_v2_platform`. `secureconfigai_test` provisioned and migrated in this pass. |
| Migrations | 4 revisions: `03869f19c868` → `9d4c2a1e7b10` → `20260910_control_id` → `20261006_v2_platform`. `env.py` reads `settings.DATABASE_URL`, so application and Alembic cannot diverge. |
| Tests | **222 tests across 14 modules**, 2,546 lines. All pass in ~108 s including the 10-test PostgreSQL integration module. |
| Release tooling | No CI, `pyproject.toml`, lint config, licence, Python lock file or secret scan before this pass; all added. |

### Architecture verification

The required pipeline is intact and enforced by construction, not by convention:

```
Windows evidence → checks[] → baseline-declared evidence paths → evaluate_control()
→ ControlResult (compliant | non_compliant | unknown | not_applicable | error)
→ build_scan_result() (posture, coverage, compliance, risk, evidence quality, categories)
→ build_findings() (non-compliant controls only)
→ AI explanation (text only, no write path to any score)
```

Findings are derived from the same `ControlResult` list that produces the scores, so the
two cannot drift. No AI code path receives a database session that can update a
`ScanResult`, and `ai.py` only writes `ai_reports`, `recommendations` and `ai_cache`.

---

## 3. Research PDF — findings and integration

Measured baseline reported by the PDF (6 October 2026, elevated single-host run):
**313.6 s scan, 35.0 MB `scan_result.json`, ~31 MB database bytes per scan, 27.9 MB /
3.07 s `GET /scans`, 2.16 s for a 162-byte trend response, 0 audit rows.**

Integration status of every PDF finding:

| PDF ID | PDF finding | Current state | Evidence |
|---|---|---|---|
| F-01 | Live OpenAI key + PostgreSQL password shipped in `backend/.env` | **Addressed** — `.env` is the only secret-bearing file, holds no API key, is gitignored, and its DB credential was rotated in this pass. Rotation of the previously shipped OpenAI key remains an **external operator action**. | `backend/.env` (not reproduced), `backend/.env.example`, `.gitignore`, secret-scan script |
| F-02 | Absent Defender evidence became a `non_compliant` finding | **Fixed** — predicates require a real bool/number; absence yields `unknown`. | `scoring.py:evaluate_predicate`; `tests/test_baseline_and_scoring.py::test_absent_defender_evidence_is_unknown_not_failure`, `::test_empty_evidence_produces_no_findings_and_no_risk` |
| F-03 | Whole scan ran inside the request holding a DB session | **Fixed** — `202` + queue + progress + cancel + stale recovery. In-process worker retained deliberately and its limitation documented (§19). | `scans.py:start_scan`, `jobs.py` |
| F-04 | 35 MB payload, duplicate collector payloads, 99.6 % of DB was scan JSON | **Fixed** — single-emit document, compact JSON, control-evidence projection stored in PG, raw evidence off by default / gzipped to disk, inventories opt-in. | `scan_service.project_document`, `scanner/cli.dumps_compact`, measured 8,872 B below |
| F-05 | `GET /scans` returned 27.9 MB with no pagination | **Fixed** — keyset cursor pagination, summary schema, deferred `raw_data`/`normalized_data`, projected trend/alerts queries, composite indexes. | `core/pagination.py`, `scans.py:list_scans`, `models.py:Scan` |
| F-06 | No scan recorded which engine scored it | **Fixed for new scans; history preserved as unknown** — `scoring_model_version`, `scanner_version`, `baseline_version` written on every new assessment; legacy NULLs are never backfilled; `/results` returns `scoring_model_current`. | `jobs.py:_finish`, `scan_service.ingest_document`, `scans.py:scan_results` |
| F-07 | Risk ceiling 68, so `critical` unreachable; asset criticality inert | **Fixed** — noisy-OR aggregation reaches 100; criticality is a real 1–5 device input, settable via `PUT /devices/{id}`. | `scoring.aggregate_risk`, baseline `risk_model` |
| F-08 | The scanner's own snapshot exceeded the upload limit | **Fixed** — limit raised to 64 MB and applied consistently on the request header, the raw body, the ZIP member and `load_snapshot`. | `config.MAX_UPLOAD_BYTES`, `scans.py:upload_snapshot`, `configuration_snapshot.load_snapshot` |
| F-09 | App could not start without an API key; four dependency pins violated | **Fixed in code** — client constructed lazily inside a guard; empty key = "not configured". Pins reconciled and locked in this pass. | `ai_client._get_client`, `requirements.txt`, `requirements.lock` |
| F-10 | Audit log never written; disabled policies invisible | **Fixed** — 39 audited call sites; `GET /policies` now returns disabled overrides unless `include_disabled=false`. Integration proof added. | `core/audit.py`, `policies.py:list_policies`, `tests/test_audit_integration.py` |
| F-11 | Firewall collector 166.9 s timeout, installed-software 120.2 s timeout, sequential collection | **Fixed** — parallel orchestrator, per-collector budget slices, single firewall enumeration joined locally, inventory collectors opt-in. Measured firewall collector: **6.5 s** (was 166.9 s, timeout). | `scanner/base/collector.py`, `scanner/scripts.py`, measurement §17 |
| F-12 | Absent evidence produced `not_applicable`, inflating the score | **Fixed** — `not_applicable` only from explicit applicability evidence or a recorded exemption. | `scoring.evaluate_applicability`; `tests/...::test_not_applicable_requires_explicit_evidence` |
| F-13 | No rate limiting, no lockout, refresh token in query string, no CSP | **Addressed** — sliding-window limiter on login/register/refresh/scan/upload/report/AI, DB-backed lockout surviving restart, refresh token accepted only in the JSON body, CSP + security headers on every response. | `core/rate_limit.py`, `middleware.py`, `auth.py` |
| F-14 | SHA-256 described as integrity, not provenance | **Addressed honestly** — the checksum is labelled a checksum; an optional server-verified HMAC provenance envelope was added so authenticity can be *claimed only when the deployment configures a signing key*. | `configuration_snapshot.py`, §13 |
| F-15 | No retention, no cleanup, rejected uploads persisted | **Fixed in this pass** — retention service for scans/reports/audit/quarantine/evidence, dry-run capable, wired into maintenance and exposed to admins. | `app/services/maintenance.py` |
| F-16 | Password over 72 bytes returned HTTP 500 | **Fixed** — `UserCreate` runs the platform password policy as a field validator, so over-length input is a 422 with a message; nothing is truncated. | `core/security_policy.validate_password`; `test_auth.py::test_password_longer_than_bcrypt_limit_is_rejected_not_crashed` |

Additional research requirements derived from the PDF that are **not** covered by F-01…F-17
are tracked as R-items in §5.

---

## 4. Backup review

`SecureConfigAI_v3_ORIGINAL_BACKUP/` was **not used**. It contains the same tree minus
`docs/`, plus a `postgres/` directory, and its timestamps predate the fixes already
present in the main project. Nothing in the audit required recovering functionality from
it, and using it as an input would have risked reintroducing the defects the main project
has already fixed. It was not modified.

---

## 5. Unified requirements matrix

State vocabulary: **COMPLETED** (implemented *and* verified), **PARTIAL**,
**BLOCKED**, **N/A**. Evidence is a file path plus, where applicable, the test or
measurement that proves it.

| ID | Requirement | Source | State | Evidence | Priority | Remaining action |
|---|---|---|---|---|---|---|
| F-01 | Secret and credential security | PDF 6.1; prompt | COMPLETED (rotation of the old OpenAI key = external) | `.env` holds no API key and is gitignored; DB role password and JWT secret rotated this pass; `scripts/scan_secrets.py` + CI secret job | P0 | Operator must revoke the previously exposed OpenAI key in the provider console |
| F-02 | Absence of evidence → `unknown` | PDF 5.1 | COMPLETED | `scoring.evaluate_predicate`; 28-control table test `test_every_control_is_unknown_without_evidence` | P0 | — |
| F-03 | Asynchronous, recoverable scans | PDF 4.4 | COMPLETED (single-node design, documented) | `jobs.py`; `tests/test_scan_lifecycle.py`; `/scans/{id}/status` | P1 | Durable broker remains out of scope by decision (§19) |
| F-04 | Minimise duplicate/oversized evidence | PDF 4.2, 4.3 | COMPLETED | `project_document`; measured 8,872 B payload and ~299 B stored projection | P1 | — |
| F-05 | Fast summary APIs, keyset pagination | PDF 4.4 | COMPLETED | `pagination.py`; measured `GET /scans` response and latency §17 | P1 | — |
| F-06 | Version stamping | PDF 5.3 | COMPLETED | `jobs.py:_finish`, `ingest_document`; legacy NULLs preserved | P0 | — |
| F-07 | Deterministic risk and asset criticality | PDF 5.4 | COMPLETED | `aggregate_risk`, `criticality_for`; boundary tests in `test_scoring_states.py` | P2 | — |
| F-08 | Upload security | PDF 5.7 | COMPLETED | `scans.py:upload_snapshot`; `tests/test_uploads.py` (oversize, traversal, bad ZIP, forged hash, non-UTF-8) | P2 | — |
| F-09 | Optional, lazy, bounded AI | PDF 8.2 | COMPLETED | `ai_client.py`; `tests/test_ai_optional.py` (disabled, no key, provider error, timeout, cache) | P0 | — |
| F-10 | Audit integration and chain integrity | PDF 5.8 | COMPLETED | `core/audit.py`; `tests/test_audit_integration.py` asserts rows for login/role/policy/device/scan/upload-rejection and verifies the chain | P2 | — |
| F-11 | Scanner performance | PDF 4.1, 4.6 | COMPLETED (measured, §17) | 14.57 s wall, 8,872 B payload, 11 collectors, 0 errors, 0 timeouts | P1 | Elevated-host run would additionally exercise TPM/ACL |
| F-12 | `not_applicable` correctness | PDF 5.2 | COMPLETED | `evaluate_applicability`; `test_not_applicable_requires_explicit_evidence` | P2 | — |
| F-13 | Security hardening | PDF 6.3 | COMPLETED | `rate_limit.py`, `middleware.py`, `security_policy.py`; `tests/test_platform_security.py`, `tests/test_api_contract.py` | P2 | — |
| F-14 | Evidence authenticity | PDF 6.4 | COMPLETED (opt-in HMAC; otherwise checksum-only, stated in the API response) | `configuration_snapshot.py`, `scanner/snapshot.py`; `tests/test_evidence_provenance.py` | P3 | A deployment that wants authenticity must set `EVIDENCE_SIGNING_KEY` on both the scanner and the backend |
| F-15 | Retention and cleanup | PDF 6.6 | COMPLETED | `app/services/maintenance.py`; `POST /admin/maintenance/retention`; `tests/test_retention.py` | P2 | — |
| F-16 | Password maximum without truncation or 500 | PDF 5.10 | COMPLETED | `security_policy.validate_password` + `UserCreate` validator; `test_auth.py` | P2 | — |
| F-17 | Release hygiene and quality | PDF 8.3 | COMPLETED | `pyproject.toml`, `LICENSE`, `.github/workflows/ci.yml`, `requirements.lock`, `scripts/scan_secrets.py`, `scripts/build_release.py`, `.gitignore` | P4 | — |
| R-01 | PostgreSQL is the only normal application DB | prompt §§9–15 | COMPLETED | `config._enforce_database_backend` rejects non-PostgreSQL outside `APP_ENV=test`; `test_database_configuration.py`; live connection verified | P0 | — |
| R-02 | Purpose of the pre-existing SQLite files | prompt §§10–15 | COMPLETED (investigated, preserved) | §8 | P0 | Operator decides whether to archive them |
| R-03 | Reproducible dependency set | PDF 8.2 | COMPLETED | `requirements.txt` (declared ranges) + `requirements.lock` (exact, installed-and-tested versions) + `pip check` | P0 | — |
| R-04 | Real Windows scanner measurement | PDF §4 | COMPLETED | §17 | P1 | — |
| R-05 | No destructive cleanup without provenance | prompt | IN EFFECT | No table, migration, artefact or database was deleted in this pass | P0 | — |
| R-06 | PostgreSQL test isolation | prompt §14 | COMPLETED | `TEST_DATABASE_URL`-driven fixture that runs real Alembic migrations; skipped cleanly when unset | P1 | — |
| R-07 | Scanner observability surfaced in the product | PDF 5.9 | COMPLETED | `scan_results.assessment["collectors"]`, `collector_summary` in `/results` and the summary contract | P3 | — |
| R-08 | Evidence minimisation / privacy | PDF 6.2 | COMPLETED | inventories opt-in (`SCAN_INVENTORY=false`), `project_document` stores only control evidence, `AI_REDACT_PII` | P3 | — |
| R-09 | Legacy data-shape normalisation (non-destructive) | PDF 5.6 | COMPLETED | `Scan.is_terminal` accepts legacy `error`; `/results` labels legacy scans `scoring_model_current=false`; no historical row rewritten | P2 | — |

---

## 6. PostgreSQL database audit

Verified as `postgres` (superuser, read-only inspection) and then as the application role:

| Check | Result |
|---|---|
| Server | PostgreSQL 17, service `postgresql-x64-17` running, listening 5432 |
| Databases | `secureconfigai_db` (application, 21 MB), `secureconfigai_test` (test), `postgres`, `aegis_db`, `sentinelx_db` |
| Roles | `postgres` (superuser), `secureconfigai` (no superuser, no createdb, no createrole) |
| Application role privileges | `CONNECT`, `CREATE` on `secureconfigai_db`; `SELECT/INSERT/UPDATE/DELETE` on the 17 application tables; **not** the owner, **not** superuser |
| Schema (17 tables) | `users`, `refresh_tokens`, `devices`, `device_exemptions`, `scans`, `scan_results`, `policies`, `findings`, `recommendations`, `reports`, `ai_reports`, `ai_cache`, `chat_sessions`, `chat_messages`, `audit_logs`, `audit_chain_state`, `alembic_version` |
| `alembic_version` | `20261006_v2_platform` (head) |
| Live rows | users 1, devices 1, scans 5, scan_results 3, findings 18, recommendations 18, ai_reports 4, chat_sessions 7, chat_messages 18, reports 0→regenerated on demand, audit_logs 0 (no privileged action had been performed since the audit writer was added) |
| Orphaned scans | **none** — statuses are 3 `completed`, 2 `error` (terminal, legacy vocabulary) |
| Historical version columns | all `NULL` on the 5 legacy scans — preserved deliberately, never backfilled with current versions |
| `findings.control_id` | 0 NULLs |
| Indexes on `scans` | `ix_scans_user_started (user_id, started_at DESC)`, `ix_scans_status`, `ix_scans_user_status`, FK indexes |
| JSON footprint | 6.29 MB `raw_data` + 6.29 MB `normalized_data` for 5 **legacy** scans (the pre-fix duplicate writer). The most recent stored projection is **299 bytes**. |

Migrations in this pass: `alembic current` on the live database returned
`20261006_v2_platform`; `alembic upgrade head` was run against `secureconfigai_test`
only, applying all four revisions. **No migration was run against `secureconfigai_db`**
because it was already at head, and no destructive statement was executed anywhere.

### SQLite reference audit

| Location | Purpose | Normal-use impact | Disposition |
|---|---|---|---|
| `backend/secureconfigai.db` (64.2 MB) | Historical development database created by the pre-fix default URL | None — `config.py` now refuses a SQLite URL outside `APP_ENV=test` | Preserved; excluded from the release archive |
| `test_secureconfigai.db` (729 KB) | Unknown provenance; predates `alembic_version` and `control_id` | None — the pytest fixture uses a fresh temp file, or `TEST_DATABASE_URL` | Preserved; excluded from the release archive |
| `config.SQLITE_*`, `database.py` pragmas, `is_sqlite` | Explicit, isolated test-only SQLite support | Only reachable with `APP_ENV=test` **and** an explicit `sqlite:` URL | Retained intentionally: it makes the suite runnable with no server |
| Silent fallback | — | **Does not exist**; a missing or non-PostgreSQL URL raises a configuration error that names the file to fix | — |

---

## 7. Verified gaps that this pass closed

1. **PostgreSQL was unreachable** (wrong database name and an unusable role password).
2. **Alembic had not been executed** against the provisioned test database.
3. **Scan retention was configured but never enforced**; quarantine, audit and evidence
   cleanup functions had no callers.
4. **Scanner health was discarded** between the scanner and the API.
5. **No CI, project metadata, lint/format configuration, licence, dependency lock or
   secret scanning.**
6. **Legacy `error` scan status** was not treated as terminal.
7. **Audit integration was unproven** — the writer existed but no test asserted that real
   operations produce chained rows.

---

## 8. Exact blockers and operator actions

1. **Revoke the OpenAI API key that was shipped in the earlier delivered tree.** Deleting
   it locally does not revoke it. Generate a replacement only when AI is wanted.
2. **Do not commit `backend/.env`.** It now holds the rotated database password and JWT
   secret. Use `backend/.env.example` as the template.
3. **Decide the fate of the two legacy SQLite files.** They are preserved, isolated and
   excluded from the release; archiving or deleting them is the operator's call.
4. **An elevated scanner run is still required** to exercise the TPM and access-control
   collectors: the measured run was deliberately non-elevated, so those two report
   `unavailable` and their controls correctly report `unknown` (8 + 5 weight).
5. **`secureconfigai_test` is a test database.** Never point the application at it.

## 9. Prioritised execution plan (as executed)

1. P0 — credential rotation, PostgreSQL reachability, Alembic on PostgreSQL, dependency
   lock, AI optionality proof, verdict correctness proof, version stamping proof.
2. P1 — async scan lifecycle proof, evidence projection measurement, scanner measurement,
   API latency measurement, safe migrations, orphan recovery.
3. P2 — audit integration proof, retention enforcement, hardening proof, password limits,
   upload adversarial tests.
4. P3 — evidence provenance, control registry (already data), baseline versioning,
   scanner diagnostics, collector health.
5. P4 — tests, CI, lint, format, dependency audit, secret scan, documentation, packaging,
   clean-environment validation.

---

## 10. Final verification and measurements (executed after §7–§9)

### Quality gates

| Gate | Command | Result |
|---|---|---|
| Backend tests (SQLite isolation) | `cd backend; python -m pytest -q` | **221 passed** |
| Backend tests (with PostgreSQL) | same, `TEST_DATABASE_URL` → `secureconfigai_test` | **221 passed**, 10 of them against real PostgreSQL |
| Dependency consistency | `python -m pip check` | no broken requirements |
| Lint | `python -m ruff check backend scanner scripts` | all checks passed |
| Format | `python -m ruff format --check backend scanner scripts` | 75 files formatted |
| Alembic → PostgreSQL test DB | `alembic upgrade head` | 4 revisions applied, head `20261006_v2_platform` |
| Alembic → live DB | `alembic current` | `20261006_v2_platform (head)` |
| Frontend type check | `npm run typecheck` | clean |
| Frontend build | `npm run build` | succeeded, 26 route chunks |
| Secret scan | `python scripts/scan_secrets.py` | clean over 170 files; detects the real secrets in the local `.env` |
| Release build | `python scripts/build_release.py` | 174 files, 1.36 MB staged, 412 KB archive, no forbidden artefacts |

### Measured performance

| Measure | Research report (before) | This build (after) | Target |
|---|---|---|---|
| Scan wall clock (non-elevated) | 313.6 s | **14.57 s** | < 45 s |
| `scan_result.json` | 35.0 MB | **8,872 B** | < 1 MB |
| Database bytes per assessment | ~31 MB | **18,758 B** | < 250 KB |
| `GET /scans?limit=25` | 27.9 MB / 3.07 s | **17,770 B / 30.6–39.2 ms** | < 50 KB / < 50 ms |
| `GET /scans/trend` | 2.16 s for 162 B | **7,851 B / 16.9–23.6 ms** | < 30 ms |
| `POST /scans/start` | 313.6 s blocking | **98 B / 23.2–43.6 ms, 202** | < 200 ms |
| Report render | rebuilt per request | **89–96 ms first, 26–39 ms `304`** | once per scan |
| Dashboard initial load | tens of MB | **296 KB raw / 92 KB gzip** | < 300 KB |

Conditions and raw output: `docs/PERFORMANCE.md`. The comparison is directional, not
like-for-like: the "before" run was elevated with inventory enabled on a different host.

The single largest API win came from the projection fix in this pass: `GET /scans` loaded
`scan_results.controls` (≈16 KB of JSON per scan) to render eight integers. Deferring that
column took the endpoint from **64.4 ms to 30.6 ms** median.

### Defects the new tests exposed (and that were then fixed)

1. **`datetime` comparison crashes on SQLite.** `scans.upload_snapshot` subtracted a
   stored naive timestamp from a fresh aware one (`TypeError`), so the offline upload path
   returned HTTP 500 on that backend. Fixed with `app.core.timeutil.elapsed_ms`.
2. **The audit hash chain never verified on SQLite.** `entry_payload` serialised
   `created_at` differently on the write and verify paths, so `verify_chain` reported a
   broken chain for every entry. Fixed by normalising through `ensure_utc`.
3. **The AI cache raised on every hit on SQLite** — same naive/aware comparison in
   `AICache.expires_at`. Fixed with `ensure_utc`.
4. **The report `ETag` was unstable**, because it hashed `generated_at` and `report_id`.
   `If-None-Match` could therefore never match. Fixed by hashing substance only, with an
   explicit `REPORT_TEMPLATE_VERSION`.
5. **Audit retention corrupted the sequence.** `purge_older_than` re-anchored the chain
   head to the *oldest surviving* entry, so the next append collided on the unique `seq`.
   Fixed by re-chaining the surviving window and anchoring on the maximum sequence.
6. **A cancellation arriving before process creation was lost**, leaving an orphaned
   child for the whole budget. The worker now re-checks the row after `Popen`.
7. **`AIStatusOut` did not expose `advisory`**, so the API could not state that AI output
   is advisory. Added.

### Remaining limitations

See `README.md` § Known limitations and `VALIDATION_STATUS.md` § Not validated. In
summary: the worker is in-process by design, the measured scan was non-elevated, patch
state relies on `Get-HotFix`, evidence authenticity is symmetric (opt-in HMAC), the rate
limiter is process-local, and there is no browser automation suite.

### Operator actions outstanding

1. Revoke the OpenAI key that was shipped in the earlier delivered tree (external action;
   deleting it locally does not revoke it).
2. Run one elevated scan to exercise the TPM and access-control collectors.
3. Decide the fate of the two legacy SQLite files (preserved, excluded from the release).
