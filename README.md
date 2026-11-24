# SecureConfigAI

Windows endpoint security-configuration assessment with a **deterministic** control engine
and an **advisory-only** AI explanation layer.

**V4 is a security-hardening release.** Headline changes versus V3: atomic refresh-token
rotation (race-proof reuse detection), lockout-counter decay, an optionally *keyed*
(HMAC) audit chain with structural verification, a bounded AI provider budget, a
credential-rotation CLI (`scripts/rotate_secrets.py`), an admin session-revocation
endpoint, and a dependency lock free of unexplained packages. See `CHANGELOG.md` for
the complete annotated list. The shipped archive is built with the allow-list release
tool — no secrets, databases or evidence files are ever included.

```
Windows endpoint → evidence collection → evidence contract → deterministic controls
→ verdicts → posture / coverage / compliance → risk → findings → AI explanation
→ reports / dashboard / API
```

The deterministic engine is authoritative. No AI code path can change a control verdict, a
severity, a score or a finding; the AI receives findings and returns text.

- **Backend** — FastAPI, SQLAlchemy 2, Pydantic v2, Alembic, **PostgreSQL** (required)
- **Frontend** — React 18, TypeScript, Vite 5, React Router 6, TanStack Query 5
- **Scanner** — Python orchestration over PowerShell collectors, bounded wall-clock budget
- **AI** — OpenAI/DeepSeek compatible, lazily constructed, optional, timeout-bounded

---

## Quick start

### 1. Database (PostgreSQL — the source of truth)

```sql
-- run once, as a PostgreSQL administrator (e.g. in pgAdmin 4's query tool)
CREATE ROLE secureconfigai LOGIN PASSWORD '<a strong password>';
CREATE DATABASE secureconfigai_db OWNER secureconfigai;
GRANT CONNECT ON DATABASE secureconfigai_db TO secureconfigai;

CREATE DATABASE secureconfigai_test OWNER secureconfigai;   -- for the test suite
```

`pgAdmin 4` is an administration client for the PostgreSQL server. The application talks
to PostgreSQL directly through SQLAlchemy; it never talks to pgAdmin.

### 2. Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock   # exact, tested set
Copy-Item .env.example .env
# edit .env: DATABASE_URL (real password) and JWT_SECRET_KEY (random, >= 32 chars)
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

`http://127.0.0.1:8001/health` · `http://127.0.0.1:8001/docs`

### 3. Frontend

```powershell
cd frontend
npm ci
npm run dev        # http://localhost:5173
npm run build      # production bundle in dist/
```

### 4. A real assessment

```powershell
.\RUN_SCANNER.bat                                   # elevated scan into scanner/manual_scan_output
# or, inside the product: POST /api/v1/scans/start  -> 202 Accepted, then poll /scans/{id}/status
```

---

## What is enforced, and where

| Property | Where it is enforced |
|---|---|
| PostgreSQL is the only normal database; no SQLite fallback | `backend/app/core/config.py` — a missing or non-PostgreSQL URL raises a configuration error naming the file to fix. SQLite is accepted only when `APP_ENV=test` **and** an explicit URL is given. |
| Application and Alembic cannot diverge | both read `settings.DATABASE_URL` (`backend/alembic/env.py`) |
| Only evidence produces a verdict | `backend/app/services/scoring.py` — `compliant`/`non_compliant` require a real boolean or number; anything else is `unknown` |
| `not_applicable` requires evidence | `evaluate_applicability()` or a recorded exemption — never silence |
| Collector failure is visible, not a verdict | collector health gates every control and the per-collector status map is stored and returned |
| AI cannot change results | `backend/app/services/ai_client.py` returns text only; no AI code path writes a control, score or finding |
| Audit trail is tamper-evident | `backend/app/core/audit.py` — hash-chained rows for 41 actions, `GET /admin/audit-logs/verify` |
| Retention is real | `backend/app/services/maintenance.py` — dry-run by default, `POST /admin/maintenance/retention` |
| Evidence authenticity is claimed only when proven | SHA-256 is a checksum; authenticity needs a configured signing key (see below) |

### Evidence integrity vs. authenticity

* **Integrity (always).** Every snapshot carries a SHA-256 over its own content. That
  detects corruption; it does **not** prove who produced the file, because anyone holding
  the file can recompute it. The API reports `integrity_verified` and never calls it a
  signature.
* **Authenticity (opt-in).** Set the same 32+ character `EVIDENCE_SIGNING_KEY` on the
  scanner and on the backend. The scanner then adds an HMAC-SHA-256 envelope over
  `evidence_digest | scan_id | timestamp | scanner_version | nonce`, and the backend
  recomputes the digest from the received bytes and verifies the MAC. The upload response
  reports `authenticity_verified`. A shared key is not non-repudiation, and without a
  server-issued nonce it does not prevent replay — that limitation is stated rather than
  papered over.

---

## The decision engine

* **28 controls**, total weight **217**, baseline version `1.0.0`
  (`backend/app/data/baseline/global_baseline_v1.json`).
* Five states: `compliant`, `non_compliant`, `unknown`, `not_applicable`, `error`.
* **Posture** = weighted compliant weight / assessed applicable weight.
* **Coverage** = assessed applicable weight / total applicable weight (independent of
  posture — a low score with low coverage is not the same as a low score with full
  coverage).
* **Compliance** = compliant assessed controls / assessed controls (unweighted).
* **Risk** = `100 · (1 − Π(1 − L·impact_i))` over failing controls, where
  `impact = severity_impact × category_exposure × asset_criticality / 125`. Bounded 0–100,
  reachable in every band, and asset criticality is a real 1–5 per-device input.
* Findings are derived from the same control list that produces the scores, so the two
  cannot drift.

`SCORING_METHODOLOGY.md` documents the derivation; `SECURITY_MODEL.md` documents the
service's own security posture. The baseline pack cites CIS Controls v8.1, the CIS Windows
11 Enterprise Benchmark, the Microsoft Security Baseline for Windows 11 and NIST SP 800-53
Rev. 5 **by name and URL**. No specific benchmark revision number is claimed, because the
exact revision this control set was derived from is not recorded — an honest limitation
rather than a fabricated citation.

---

## Project layout

```
backend/        FastAPI application, models, Alembic migrations, tests, tools
frontend/       React + TypeScript client
scanner/        Windows collector package (CLI, collectors, normaliser, snapshot)
docs/           API contract and scanner output specification
scripts/        secret scan, release builder, API benchmark
.github/        CI (backend, frontend, secrets, release hygiene)
```

---

## Tests and quality gates

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest -q                     # SQLite isolation, fast
$env:TEST_DATABASE_URL = "postgresql+psycopg://secureconfigai:<pw>@localhost:5432/secureconfigai_test"
.\.venv\Scripts\python.exe -m pytest -q                     # + PostgreSQL integration
```

```powershell
python -m ruff check backend scanner scripts         # lint
python -m ruff format --check backend scanner scripts
python scripts/scan_secrets.py                       # credential scan
python scripts/build_release.py                      # clean, allow-listed release archive
python scripts/benchmark_api.py --scans 30           # latency/payload measurement
```

**221 tests pass** (SQLite isolation) and the same suite passes with the PostgreSQL
integration test enabled. The suite never touches a development database: the fixture
points at a temporary SQLite file, and the PostgreSQL test refuses any database whose name
does not contain `test`.

### Measured behaviour (this machine, PostgreSQL 17, in-process client)

| Measure | Result | Target |
|---|---|---|
| Scan wall clock (non-elevated, inventory off) | **14.6 s** | < 45 s |
| `scan_result.json` | **8.9 KB** | < 1 MB |
| Database bytes per assessment | **18.8 KB** | < 250 KB |
| `GET /scans?limit=25` | **17.8 KB**, 31–39 ms median | < 50 KB, < 50 ms |
| `GET /scans/trend` | **7.9 KB**, 17–24 ms | < 30 ms |
| `POST /scans/start` | **98 B**, 23–44 ms (`202`) | < 200 ms |
| Dashboard initial load (built assets) | **296 KB raw / 92 KB gzip** | < 300 KB |

Before these changes the research report measured 313.6 s / 35 MB / ~31 MB per scan /
27.9 MB and 3.07 s for the history endpoint. `docs/PERFORMANCE.md` records the conditions
and the raw numbers.

---

## Known limitations (stated, not hidden)

1. **The scan worker is in-process** (`ThreadPoolExecutor`). Job state is durable in
   PostgreSQL — queued rows survive a restart and interrupted runs are failed at startup —
   but throughput is bounded by one service process. Moving to a broker is a local change:
   `ScanJobManager` exposes exactly `submit` / `cancel` / `recover_stale`.
2. **The measured scan was non-elevated**, so the TPM and access-control collectors
   reported `unavailable` and their controls correctly report `unknown`. An elevated run is
   needed to exercise them.
3. **Path state comes from `Get-HotFix`**, which misses updates delivered outside the
   Windows Update catalogue. The collector records its source so this is visible; the
   Windows Update Agent API would be the next step.
4. **Evidence authenticity is symmetric** (shared HMAC key). Non-repudiation would need an
   asymmetric signature plus RFC 3161 timestamps.
5. **The rate limiter is process-local.** Correct for a single-node deployment; a
   multi-instance deployment must move it to a shared store.
6. **Account lockout is durable** (database-backed) but the login limiter is not.
7. Two legacy SQLite files (`backend/secureconfigai.db`, `test_secureconfigai.db`) are
   preserved as historical data. They are gitignored and excluded from the release archive;
   they are never used by the application.

## Release hygiene

`.env`, databases, virtual environments, `node_modules`, `dist`, caches and generated
scanner output are excluded **by construction**: `scripts/build_release.py` copies an
allow-list into a staging directory, refuses forbidden artefacts, scans the staged tree for
credentials, and writes `MANIFEST.sha256`. `.gitignore` is a second line of defence, not
the only one.

## Licence

MIT — see `LICENSE`. Confirm the licence with the project author and the awarding
institution before public distribution.
