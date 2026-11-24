# SecureConfigAI Architecture

## Evidence pipeline

`Windows native sources → collectors → raw evidence → normalization → deterministic controls → findings → risk → scoring → API → UI/report/AI`

The deterministic control and scoring layers are the source of truth. AI is advisory and receives only stored scan evidence and findings.

## Scanner

Collectors use Microsoft/Windows mechanisms including PowerShell, CIM/WMI, Registry, NetSecurity, NetTCPIP, Defender, BitLocker and TPM. Each collector is isolated. A failed collector does not invalidate unrelated evidence.

Each check records a status and evidence metadata. The scanner records execution privilege and timing. Full scans are intentionally not constrained by a single short global timeout; PowerShell commands have bounded execution time and collector failures are isolated.

## Privilege model

The FastAPI service remains a normal local process. The scanner can request Windows UAC elevation. If elevation is declined, it continues in limited mode and records the real privilege state.

## Decision model

Controls have stable IDs and explicit states:

- `compliant`
- `non_compliant`
- `not_applicable`
- `unknown`
- `error`

Missing or failed evidence is never silently treated as compliant.

## Scoring

### Security Posture

For applicable, assessed controls:

`Σ(weight × compliant_state) / Σ(assessed_applicable_weight) × 100`

`compliant_state = 1`, `non_compliant = 0`.

### Assessment Coverage

`assessed_applicable_weight / total_applicable_weight × 100`

Coverage is intentionally separate from posture so a perfect score with incomplete evidence is visible as incomplete.

### Compliance

Compliance is calculated per applicable assessed control, without treating finding counts as controls.

### Risk

Risk is separate from posture and only `non_compliant` controls contribute. Each failing
control has a normalised impact `severity_impact × category_exposure × asset_criticality /
125`, and impacts are combined with a noisy-OR model:
`risk = 100 × (1 − Π(1 − L·impact_i))` with `L = 0.5`. The result is bounded to 0–100,
monotonic in the number of failures, reachable in every band (so the `critical` threshold
is not dead code), and driven by a real per-device 1–5 asset criticality. This is a project
methodology and is not represented as an official NIST formula;
`SCORING_METHODOLOGY.md` carries the derivation and worked examples.

## Assessment execution

A scan is never run inside the request that starts it:

```
POST /scans/start → 202 Accepted + queued row
                  → ScanJobManager (bounded ThreadPoolExecutor)
                  → scanner subprocess, JSON progress on stdout
                  → stage / progress / heartbeat mirrored into the scan row
                  → ingest_document() → controls, findings, scores, audit row
```

* The queued row is durable even though the worker is in-process: a restart reconciles it
  (`recover_stale` fails anything whose heartbeat is older than `SCAN_STALE_AFTER_SECONDS`),
  so an interrupted scan can never present as running.
* `POST /scans/{id}/cancel` terminates the child process and wins over a late worker
  failure; a cancellation that arrives before the process exists is re-checked after
  `Popen`.
* The scanner is bounded twice: per-collector slices and one shared wall-clock budget
  (`SCAN_BUDGET_SECONDS`). Collectors that could not start are recorded `skipped`.
* Per-collector status, duration and error are persisted on the scan result and returned by
  `GET /scans/{id}/results` as `collector_health`, so a degraded run cannot present as a
  clean one.

## Audit trail

`app/core/audit.py` writes a hash-chained row for every privileged action (41 action types,
43 call sites): authentication success and failure, lockout, role and status changes, policy
CRUD and toggles, device lifecycle, scan start/complete/fail/cancel/upload/delete, upload
rejection, AI generation and retention passes. Each row carries actor, action, entity,
outcome, request id, source address and timestamp, and commits to the previous row's hash.
`GET /admin/audit-logs/verify` recomputes the chain. Audit rows are immutable: the actor
foreign key refuses deletion of a user who has history, because nulling that column would
rewrite a row the chain has already hashed.

## Retention

`app/services/maintenance.py` is the only component that deletes anything. Windows are
configuration (`RETENTION_SCAN_DAYS`, `RETENTION_AUDIT_DAYS`, `RETENTION_REPORT_DAYS`,
`UPLOAD_QUARANTINE_TTL_MINUTES`). Only terminal scans are eligible, the default is a dry
run, an enforcement pass is audited, and an audit purge re-anchors the chain so the
surviving window still verifies.

## Frontend

The frontend renders backend metrics. It does not implement a second scoring model. The UI is organized into separate pages for overview, scans, devices, controls, policies, reports, AI, and administration.

The visual system is monochrome-first: white, charcoal, black and neutral gray, with restrained semantic colors only for status.

## Database

PostgreSQL is the application database. `app/core/config.py` refuses a missing or
non-PostgreSQL `DATABASE_URL` outside `APP_ENV=test`, so there is no silent SQLite fallback
and no accidentally created `.db` file. Alembic is the schema authority (the application
never calls `create_all()`), and `alembic/env.py` reads the same `settings.DATABASE_URL`, so
the application and the migration tool cannot diverge.

Large evidence columns (`scans.raw_data`, `scans.normalized_data`) are `deferred`, so list
queries never load them; the list endpoint additionally loads only the twelve
`scan_results` columns a summary needs. Tests use an isolated temporary SQLite database by
default, or a dedicated PostgreSQL test database when `TEST_DATABASE_URL` is set; neither
can reach the development database.
