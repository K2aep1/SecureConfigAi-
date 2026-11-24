# SecureConfigAI_v3 — Troubleshooting

## 1. Make sure you are running *this* folder

The dashboard must be started from this `SecureConfigAI_v3` folder. Do not run an older
SecureConfigAI checkout or a stale Vite process.

## 2. The service refuses to start and names `DATABASE_URL`

That is the intended behaviour, not a bug.

The application requires PostgreSQL for normal use and **will not** fall back to SQLite. If
`backend/.env` is missing, or `DATABASE_URL` is empty, or it points at a non-PostgreSQL URL,
startup fails with a configuration error rather than silently creating a local database.

```env
DATABASE_URL=postgresql+psycopg://secureconfigai:<password>@localhost:5432/secureconfigai_db
JWT_SECRET_KEY=<48+ random characters from: python -c "import secrets;print(secrets.token_urlsafe(48))">
```

Check the target before starting:

```powershell
cd backend
.\.venv\Scripts\python.exe -m alembic current     # should print a revision, not an error
```

If PostgreSQL is not running, start the service (`postgresql-x64-17` on this machine) and
verify with `Get-Service postgresql*`.

## 3. `relation "users" does not exist` (or any other missing table)

Alembic is the only schema authority; the application never calls `create_all()` at
startup. Apply the migrations:

```powershell
cd backend
.\.venv\Scripts\python.exe -m alembic upgrade head
```

## 4. The old `.db` files

`backend/secureconfigai.db` and `test_secureconfigai.db` are historical artefacts from a
previous configuration. They are not used by the application, are gitignored, and are
excluded from the release archive. Do not delete them until you have decided whether their
scan history is worth keeping — inspect them read-only first.

## 5. AI is optional — and says so

No API key is required. Without one, `GET /api/v1/ai/status` reports
`configured: false` and every AI endpoint returns a deterministic local explanation with
`model_used: "local-rule-engine"`. Scanning, controls, scores, findings and reports are
unaffected.

To enable a provider:

```env
AI_ENABLED=true
AI_PROVIDER=openai
OPENAI_API_KEY=<key>
OPENAI_MODEL=gpt-4o-mini
AI_TIMEOUT_SECONDS=30
```

Then `GET /api/v1/ai/status` should show `configured: true` and, if the key and network
work, `connected: true`. Never commit the key.

## 6. Start the backend

Run `START_BACKEND.bat`, then check:

- <http://127.0.0.1:8001/health> — includes the database dialect and reachability
- <http://127.0.0.1:8001/docs> — interactive API documentation (disabled in production)

## 7. Test the scanner directly

Run `RUN_SCANNER.bat`. It writes `scanner\manual_scan_output\scan_result.json`.

A non-elevated run reports `completed_with_errors` with the TPM and access-control
collectors `unavailable`; that is accurate, not a bug. Their controls report `unknown`
until an elevated run collects the evidence. The console prints per-collector status and
durations.

## 8. A scan stays "queued" or "running"

- `queued` means the worker pool is busy. `SCAN_JOB_WORKERS` (default 2) is the concurrency
  limit.
- A run interrupted by a crash is reconciled at startup: anything still `running` with a
  heartbeat older than `SCAN_STALE_AFTER_SECONDS` is marked `failed` with a reason.
- `POST /api/v1/scans/{id}/cancel` terminates the child process and wins over a late worker
  failure.

## 9. Everything is 429

Rate limits are on by default (`RATE_LIMIT_*` in `backend/.env`). The response carries
`Retry-After`. Account lockout is separate and database-backed: `MAX_FAILED_LOGINS`
attempts lock the account for `LOCKOUT_MINUTES`, and an administrator can clear it with
`POST /api/v1/admin/users/{id}/unlock`.

## 10. An upload is rejected

The API returns a specific reason: wrong extension, empty file, invalid JSON, non-UTF-8
body, oversize body, unsafe ZIP path, no JSON in the ZIP, corrupt ZIP, an integrity hash
that no longer matches, an unsupported schema version, or a provenance MAC that fails.
Each rejection is written to the audit trail as `scan.upload.rejected`.

## 11. The browser shows an old dashboard

Stop every stale `npm run dev`, start `START_FRONTEND.bat` from this folder, and hard
refresh with <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>R</kbd>. The shipped `dist/` is a build
of the current source; if it disagrees with the source, rebuild with `npm run build`.

## 12. Something is wrong with the tests

```powershell
cd backend
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pytest -q
```

The suite uses an isolated temporary SQLite database by default. Set `TEST_DATABASE_URL` to
a **separate** PostgreSQL database to also run the integration test; it refuses any database
whose name does not contain `test`.

## 13. Retention deleted something

It should not have deleted anything active. Only terminal scans
(`completed`/`failed`/`cancelled`/`error`) older than `RETENTION_SCAN_DAYS` are eligible, and
`POST /api/v1/admin/maintenance/retention` defaults to `dry_run=true`. Preview first; the
enforcement pass is recorded in the audit chain as `admin.retention_purge`.
