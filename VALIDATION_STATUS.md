# Validation Status

Everything below was executed in this workspace. Where something could not be executed,
it says so and says why. No pass in this file is inferred from code inspection alone.

**Validated on:** Windows 11 (build 26200), CPython 3.14.6, PostgreSQL 17 (local service),
Node 24.16 / npm 11.13, 2026-10-19.

## Passed — backend

| Check | Command | Result |
|---|---|---|
| Full test suite (isolated SQLite) | `cd backend && python -m pytest -q` | **221 passed** |
| Full test suite incl. PostgreSQL integration | same, with `TEST_DATABASE_URL` set to `secureconfigai_test` | **221 passed** (10 of them exercise a real PostgreSQL database) |
| Dependency consistency | `python -m pip check` | `No broken requirements found.` |
| Lint | `python -m ruff check backend scanner scripts` | `All checks passed!` |
| Formatting | `python -m ruff format --check backend scanner scripts` | `75 files already formatted` |
| Alembic → PostgreSQL | `alembic upgrade head` against `secureconfigai_test` | all four revisions applied; head `20261006_v2_platform` |
| Alembic → live database | `alembic current` against `secureconfigai_db` | `20261006_v2_platform (head)` — already current, no migration needed |

## Passed — frontend

| Check | Command | Result |
|---|---|---|
| Install | `npm ci` | lockfile satisfied |
| Type check | `npm run typecheck` | clean |
| Production build | `npm run build` | built in ~3 s; 26 route-level chunks |
| Initial payload | measured from `dist/` | **296 KB raw / 92 KB gzip** |

## Passed — scanner (real Windows host)

`python -m scanner.cli --output <tmp> --no-inventory --no-elevate --budget-seconds 120 --parallel 4`

* Wall clock **14.57 s**; `scan_result.json` **8,872 bytes**; snapshot 9,182 bytes.
* 11 collectors selected: 9 `completed`, 2 `unavailable` (TPM and access control — the
  run was deliberately non-elevated), 0 errors, 0 timeouts, 0 skipped.
* Status reported as `completed_with_errors`, which is accurate.
* Firewall collector **6.46 s** (the research report measured 166.9 s ending in timeout).

Reproduce with `scripts/benchmark_api.py` for the API side and the command above for the
scanner. Full numbers: `docs/PERFORMANCE.md`.

## Passed — security

| Check | Result |
|---|---|
| Secret scan of the release tree | `python scripts/scan_secrets.py` → `OK: no credential patterns found in 170 file(s)` |
| Secret scan of a file that *does* hold credentials | detects both the database password and the JWT secret in the local `backend/.env` (which is gitignored and excluded from the release) — i.e. the scanner is not a no-op |
| Release build | 174 files staged from an allow-list, no `.env`, no `*.db`, no `node_modules`, no caches; archive 412 KB |
| Authentication/authorisation | covered by `test_auth.py`, `test_platform_security.py`, `test_api_contract.py` (lockout, rate limit, token-type confusion, cross-user 404, admin-only 403) |
| Audit chain | `test_audit_integration.py` proves rows for register/login/role/status/policy/device/scan/upload-rejection/AI and that tampering breaks verification |
| Upload hardening | `test_uploads.py` — wrong extension, empty, invalid JSON, non-UTF-8, oversize, ZIP traversal, ZIP without JSON, corrupt ZIP, forged hash, unsupported schema, unrecognisable document |

## Not validated — and why

1. **Credential rotation of the previously shipped OpenAI key.** This requires the
   provider console. It is an operator action; deleting the line does not revoke a key.
   *Status: BLOCKED on operator.*
2. **Elevated scanner run.** TPM and access-control collectors need administrative
   privileges. Their controls correctly report `unknown` until such a run is performed.
   *Status: PARTIAL — code path exercised, evidence incomplete by design of the run.*
3. **Browser-level end-to-end test** (Playwright/Selenium). The API is exercised end to end
   and the frontend builds and type-checks, but no browser automation suite exists.
   *Status: NOT IMPLEMENTED.*
4. **Multi-worker / multi-node deployment.** The scan worker is in-process and the rate
   limiter is process-local; neither has been tested under horizontal scale-out.
   *Status: OUT OF SCOPE by design decision.*
5. **Historical scan re-scoring.** Legacy scans keep `NULL` version columns and their
   stored metrics are from an older engine. They are labelled, not rewritten.
   *Status: DELIBERATE — rewriting history would destroy the evidence of the change.*

## Historical note

An earlier copy of this file said the test suite and the frontend build could not run
because dependencies were missing. That was true of the environment it described and is no
longer true: both now run from the pinned lockfile. It is retained here as a correction
rather than silently deleted, because a validation document that quietly changes its
claims is worse than one that records them.
