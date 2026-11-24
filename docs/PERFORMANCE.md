# Performance measurements

Every number here was produced on the project machine and can be reproduced with the
commands shown. Nothing in this file is estimated.

## Test conditions

| Item | Value |
|---|---|
| Host | Windows 11 (build 26200), local PostgreSQL 17 service |
| Python | CPython 3.14.6 in `backend/.venv` |
| Database | `secureconfigai_test` (PostgreSQL 17, local socket, no TLS) |
| Dataset | 30 assessments created through `POST /scans/upload`, 28 controls each, 10 compliant / 20 failing, asset criticality 4 |
| Client | `fastapi.testclient.TestClient` — **in-process**, so network and TLS are excluded |
| Samples | 10–15 per endpoint; median and p95 reported |
| Date | 2026-10-19 |

In-process timing is not comparable to a browser measurement. It isolates the cost of the
application plus the database, which is what the optimisation work targets.

## Reproduce

```powershell
cd <project root>
$env:TEST_DATABASE_URL = "postgresql+psycopg://secureconfigai:<pw>@localhost:5432/secureconfigai_test"
python scripts/benchmark_api.py --scans 30 --samples 15
```

The script applies the migrations, seeds the history, measures, then deletes exactly the
rows it created.

## Results (after the optimisation work)

| Endpoint | Response bytes | Median | p95 | Target |
|---|---|---|---|---|
| `GET /scans?limit=25` | 17,770 | 30.6 – 39.2 ms | 36.0 – 55.2 ms | < 50 KB / < 50 ms |
| `GET /scans/trend?limit=30` | 7,851 | 16.9 – 23.6 ms | 18.1 – 25.9 ms | < 30 ms |
| `GET /scans/alerts` | 1,411 | 12.6 – 20.2 ms | 13.7 – 23.9 ms | — |
| `GET /scans/{id}` | 702 | 16.3 – 20.3 ms | 19.4 – 38.0 ms | — |
| `GET /scans/{id}/results` | 61,776 | 20.3 – 31.7 ms | 22.0 – 37.4 ms | — |
| `POST /scans/start` | 98 | 23.2 – 43.6 ms | 26.1 – 49.9 ms | < 200 ms |
| `GET /scans/{id}/report/html` (first render) | — | 89 – 96 ms | — | generated once |
| `GET /scans/{id}/report/html` (`If-None-Match`) | 0 (`304`) | 26.5 – 38.8 ms | — | no rebuild |

Ranges are the spread across two full runs on the same machine; the spread is machine
noise (antivirus, OneDrive-synced working directory), not a change in the code path.

**Database footprint**

| Measure | Bytes |
|---|---|
| `scans.normalized_data` (control-evidence projection), 30 scans | 23,704 |
| `scan_results.controls` (authoritative per-control record), 30 scans | 493,300 |
| `scan_results.assessment` + `categories`, 30 scans | 38,340 |
| `scans.raw_data` (metadata only; raw evidence is not stored), 30 scans | 6,930 |
| **Total for 30 assessments** | **562,754** |
| **Per assessment** | **≈ 18.8 KB** |

The dominant term is `scan_results.controls` — the authoritative per-control record, not
duplicated evidence. Moving it to a compressed column would shrink the figure further but
would make the individual control results harder to query, so it is a deliberate trade.

## Scanner (real Windows run)

Non-elevated, inventory disabled, 120-second budget, parallelism 4:

```
scan complete in 14.2s
  schema_version : 1.2
  scan_result.json: 8872 bytes
  configuration_snapshot.json: 9182 bytes
  collectors     : 11 (completed=9 unavailable=2 errors=0 timeouts=0 skipped=0)
  status         : completed_with_errors
    device               completed    1989.3 ms
    firewall             completed    6464.7 ms
    system_hardening     completed    9180.5 ms
    tpm                  unavailable  1286.8 ms  Administrator privilege is required
    authentication       completed    1149.5 ms
    updates              completed   12059.7 ms
    account_security      completed    972.5 ms
    services              completed    2904.0 ms
    access_control       unavailable   978.7 ms  Attempted to perform an unauthorized operation
    registry              completed    1257.0 ms
    network_security      completed    2453.6 ms
```

Wall clock including interpreter startup and JSON writing: **14.57 s**.

`completed_with_errors` is the honest status: two privileged collectors could not read
their sources, so their controls report `unknown` (TPM 8 weight, Access Control 5 weight)
rather than being silently scored.

## Before / after

The research report's measurements are the "before" column. They were taken on a
different machine, with the elevated scanner and with inventory enabled, so the comparison
is directional rather than like-for-like — stated explicitly because it matters.

| Measure | Before (research report) | After (measured here) | Target |
|---|---|---|---|
| Scan wall clock | 313.6 s | 14.6 s | < 45 s |
| `scan_result.json` | 35.0 MB | 8.9 KB | < 1 MB |
| Database bytes per scan | ~31 MB | 18.8 KB | < 250 KB |
| `GET /scans` | 27.9 MB / 3.07 s | 17.8 KB / 31–39 ms | < 50 KB / < 50 ms |
| `GET /scans/risk-trend` | 2.16 s for 162 B | 7.9 KB / 17–24 ms | < 30 ms |
| Scan request | 313.6 s blocking | 98 B / 23–44 ms, `202` | < 200 ms |
| Report generation | rebuilt every request | first 89–96 ms, then `304` | once per scan |
| Dashboard first load | tens of MB | 296 KB raw / 92 KB gzip | < 300 KB |

## What made the difference

1. **Firewall collector** — one enumeration of each filter class joined locally on rule
   identity, instead of a second full rule enumeration plus seven dependent filter cmdlets
   per rule: **166.9 s (timeout) → 6.5 s**.
2. **Deterministic parallelism with a shared deadline** — collectors run in a bounded pool
   under one wall-clock budget instead of thirteen sequential 120-second allowances.
3. **Evidence projection** — only the evidence the baseline declares is stored; the
   collector payload is emitted once, compact, instead of four times.
4. **Deferred columns plus explicit projections** — `Scan.raw_data` and
   `Scan.normalized_data` are `deferred`, and the list query now loads only the twelve
   `ScanResult` columns a summary needs. Loading `scan_results.controls` (16 KB of JSON per
   scan) for 25 rows was the single largest cost in `GET /scans`: removing it took the
   endpoint from **64 ms to 31 ms** median.
5. **Keyset pagination** with a composite index on `(user_id, started_at DESC)`.
6. **Reports generated once** on completion and served with a content-addressed `ETag`.

## Residual gaps

* The measured scan was non-elevated. An elevated run is required to exercise TPM and
  access-control collection; those controls currently report `unknown` on this host.
* `GET /scans` median is inside the 50 ms target, but its p95 exceeded 50 ms on one of two
  runs (55 ms). It is a self-reported miss, not a rounded pass.
* `GET /scans/{id}/results` is 61 KB because it carries all 28 control results plus the
  findings. That is the dashboard payload; the list endpoint deliberately does not.
