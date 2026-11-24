# SecureConfigAI Security Model

## Trust boundaries

1. **Browser/UI** — untrusted input and display logic. It renders backend metrics and never
   computes an authoritative score.
2. **FastAPI** — authenticates, authorises, validates and persists.
3. **Scanner** — performs controlled, read-only Windows security collection and is treated
   as an untrusted evidence source by the backend.
4. **Decision engine** — evaluates evidence deterministically; it is the authority.
5. **AI provider** — advisory only, and outside the trust boundary entirely: its output is
   text that can never change a control, a score or a finding.

## PowerShell

The application invokes a fixed set of scanner commands. Arbitrary PowerShell is never
constructed from user input: collector scripts are static, paths and the output directory
are passed as separate arguments, and the backend never accepts a command from a request.

## Privilege

The web application is not intended to run elevated. The scanner can request Windows UAC
elevation; if elevation is declined or unavailable it continues with the privileges it has
and records the real state per collector. Collectors that could not read their source
report `unavailable`, and their controls report `unknown` — never a fabricated verdict.

The service account that runs the API is separate from the database role: the application
connects with a non-superuser PostgreSQL role holding DML on its own schema.

## Secrets

Secrets are environment configuration only, live in `backend/.env`, and are never read from
or written to the API, the frontend bundle, logs, error responses or diagnostic output.

* `JWT_SECRET_KEY` — a startup check fails the process in production while it is a
  placeholder or shorter than 32 characters.
* `DATABASE_URL` — carries the application role's password; the repository has a
  placeholder-only `.env.example`.
* `OPENAI_API_KEY` / `DEEPSEEK_API_KEY` — optional; an empty value means "not configured"
  and the deterministic path is used.
* `EVIDENCE_SIGNING_KEY` — optional shared secret for evidence provenance (below).

`scripts/scan_secrets.py` scans the release tree in CI and is a hard gate in
`scripts/build_release.py`. The scanner is verified against a file that *does* contain real
credentials, so it is not a no-op. If a real key was previously present in a project copy it
must be **revoked at the provider**; deleting the file does not revoke it.

## Evidence integrity vs. authenticity

These are two different guarantees and the code never conflates them.

**Integrity (always available).** Every configuration snapshot carries a SHA-256 over its
own content, computed canonically (sorted keys, no whitespace, UTF-8) with the
`integrity`/`provenance` blocks excluded. It detects corruption in transit and at rest. It
does **not** prove origin, because anyone holding the file can recompute it. The API reports
`integrity_verified` and never labels this a signature.

**Authenticity (opt-in).** When a 32+ character `EVIDENCE_SIGNING_KEY` is configured on both
the scanner and the backend, the scanner adds an HMAC-SHA-256 envelope over

```
evidence_digest | scan_id | timestamp | scanner_version | nonce
```

where `evidence_digest` is the snapshot's canonical SHA-256. The backend **recomputes the
digest from the received bytes** — a client-supplied digest is never used as the reference
value — and verifies the MAC with `hmac.compare_digest`. The upload response reports
`authenticity_verified`, and a mismatch is rejected as tampering, not accepted with a
warning.

Residual limitation, stated rather than hidden: a shared key gives origin assurance between
the two parties that hold it. It is not non-repudiation, and without a server-issued nonce
and a trusted timestamp it does not prevent replay. The next step would be an asymmetric
signature plus RFC 3161 timestamps.

## Evidence minimisation

The backend stores a **projection** of the evidence: only the fields the baseline declares
plus collector health. Raw snapshots are not stored in the database by default
(`STORE_RAW_EVIDENCE=false`); when they are needed they are gzipped to disk under
`backend/uploads/evidence` and referenced by path. Inventory collectors (network topology,
installed software, listening ports) are **opt-in** (`SCAN_INVENTORY=false`) because no
control reads them and they map an endpoint's attack surface into the database.

## Service hardening

| Control | Implementation |
|---|---|
| Password policy | single source of truth (`PlatformSecurityPolicy`), enforced as a request-schema validator so an over-length password is a 422, never truncated and never a 500 |
| Account lockout | database-backed `failed_login_count` / `locked_until`, survives restart, visible to administrators, cleared by an audited admin action |
| Rate limiting | sliding window per address and/or account on login, registration, refresh, scan start, upload, report and AI |
| Tokens | JWT with pinned algorithm, issuer, audience, `exp`/`iat`/`sub` required; access and refresh tokens are not interchangeable; refresh tokens rotate with fingerprint storage and reuse detection that revokes the family |
| Refresh transport | JSON body only — never a query string |
| Headers | CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP on every response; HSTS opt-in |
| Errors | one generic 500 body with a request id; internals go to the server log only |
| Authorisation | ownership checks return 404 (not 403) for another user's resource; admin routes require the admin role |
| Audit | hash-chained, immutable rows for every privileged action |
| Retention | configurable windows, dry-run by default, enforcement audited |
| Production guards | startup refuses a placeholder JWT secret; interactive docs are disabled |

## Database

PostgreSQL is the source of truth. A missing or non-PostgreSQL `DATABASE_URL` is a
configuration error outside the test environment — there is no SQLite fallback. The
application role is not a superuser and is not the schema owner. Migrations are the only
schema authority.
